/*
 * MetricMQ ESP32 Arduino Client Library — Implementation
 *
 * Binary protocol wire format (16-byte header):
 *   [0]     protocol version = 0x01
 *   [1]     command byte (BinaryCommand enum)
 *   [2-3]   topic length, big-endian uint16
 *   [4-7]   payload length, big-endian uint32
 *   [8-15]  sequence number, big-endian uint64
 *   [16..16+topic_len-1]    topic bytes (UTF-8, no null terminator)
 *   [16+topic_len..]        payload bytes
 *
 * For SIGNED_PUBLISH (0x10), between topic and payload:
 *   [64 bytes] Ed25519 signature over raw (topic + payload) bytes, no separator
 *   [4 bytes]  key_id, big-endian uint32
 */

#include "MetricMQ.h"

// libsodium is bundled in arduino-esp32 SDK v2.0.0+
#include <sodium.h>

// ── Endian helpers ────────────────────────────────────────────────────────

void MetricMQClient::_writeU16BE(uint8_t* b, uint16_t v) {
    b[0] = (v >> 8) & 0xFF;
    b[1] =  v       & 0xFF;
}
void MetricMQClient::_writeU32BE(uint8_t* b, uint32_t v) {
    b[0] = (v >> 24) & 0xFF; b[1] = (v >> 16) & 0xFF;
    b[2] = (v >>  8) & 0xFF; b[3] =  v        & 0xFF;
}
void MetricMQClient::_writeU64BE(uint8_t* b, uint64_t v) {
    for (int i = 7; i >= 0; --i) { b[i] = v & 0xFF; v >>= 8; }
}
uint16_t MetricMQClient::_readU16BE(const uint8_t* b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
uint32_t MetricMQClient::_readU32BE(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}
uint64_t MetricMQClient::_readU64BE(const uint8_t* b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) { v = (v << 8) | b[i]; }
    return v;
}

// ── Constructor / Destructor ─────────────────────────────────────────────

MetricMQClient::MetricMQClient() {
    sodium_init();   // idempotent — safe to call multiple times
}

MetricMQClient::~MetricMQClient() {
    disconnect();
}

// ── Public API ────────────────────────────────────────────────────────────

void MetricMQClient::setSigningKey(const char* device_id, const uint8_t sk[64]) {
    // Use a hash of device_id string as key_id for determinism
    uint32_t id = 5381;
    for (const char* p = device_id; *p; ++p)
        id = ((id << 5) + id) ^ (uint8_t)*p;
    setSigningKey(sk, id == 0 ? 1 : id);
}

void MetricMQClient::setSigningKey(const uint8_t sk[64], uint32_t key_id) {
    memcpy(_sk, sk, 64);
    _key_id  = key_id;
    _signing = true;
}

void MetricMQClient::setExactlyOnce(bool enabled) {
    _exactly_once = enabled;
}

void MetricMQClient::generateKeypair(uint8_t pk_out[32], uint8_t sk_out[64]) {
    sodium_init();
    crypto_sign_keypair(pk_out, sk_out);
}

bool MetricMQClient::connect(const char* host, uint16_t port,
                              const char* client_id) {
    _host      = String(host);
    _port      = port;
    _client_id = client_id ? String(client_id) : String("");
    _connected = false;

    if (!_tcp.connect(host, port)) {
        Serial.printf("[MetricMQ] TCP connect to %s:%u FAILED\n", host, port);
        return false;
    }
    _tcp.setNoDelay(true);

    // Send a SUBSCRIBE frame with client_id as a special "hello" so the broker
    // can track exactly-once offsets by client_id.
    // For brokers that support the CONNECT command this would be cleaner,
    // but the current MetricMQ broker identifies clients by client_id in
    // the first SUBSCRIBE frame.
    _connected  = true;
    _last_ping  = millis();

    // Re-subscribe to any topics already registered (after reconnect)
    for (auto& s : _subs) {
        _sendSubscribeFrame(s.topic.c_str());
    }

    return true;
}

void MetricMQClient::disconnect() {
    if (_tcp.connected()) _tcp.stop();
    _connected = false;
}

bool MetricMQClient::isConnected() {
    if (!_tcp.connected()) {
        _connected = false;
    }
    return _connected;
}

void MetricMQClient::loop() {
    if (!isConnected()) return;

    // Send keep-alive PING every 60 seconds
    if (millis() - _last_ping > KEEPALIVE_MS) {
        _sendPing();
        _last_ping = millis();
    }

    // Poll for incoming frames
    _pollIncoming();
}

bool MetricMQClient::publish(const char* topic, const char* payload) {
    return publish(topic, (const uint8_t*)payload, strlen(payload));
}

bool MetricMQClient::publish(const char* topic,
                              const uint8_t* payload, size_t len) {
    if (!isConnected()) return false;
    return _sendBinaryFrame(BinaryCommand::PUBLISH, topic, payload, len, false);
}

bool MetricMQClient::publishSigned(const char* topic, const char* payload) {
    return publishSigned(topic, (const uint8_t*)payload, strlen(payload));
}

bool MetricMQClient::publishSigned(const char* topic,
                                    const uint8_t* payload, size_t len) {
    if (!isConnected()) return false;
    if (!_signing) {
        Serial.println("[MetricMQ] publishSigned: no signing key set — use setSigningKey() before connect()");
        return false;
    }
    return _sendBinaryFrame(BinaryCommand::SIGNED_PUBLISH, topic, payload, len, true);
}

bool MetricMQClient::subscribe(const char* topic, MetricMQCallback callback) {
    if (!topic || !callback) return false;

    // Store the subscription locally for replay after reconnect
    for (auto& s : _subs) {
        if (s.topic == topic) {
            s.callback = callback;  // update existing
            if (isConnected()) _sendSubscribeFrame(topic);
            return true;
        }
    }
    _subs.push_back({std::string(topic), callback});

    if (isConnected()) return _sendSubscribeFrame(topic);
    return true;  // will be sent on next connect()
}

// ── Frame Building ────────────────────────────────────────────────────────

bool MetricMQClient::_sendBinaryFrame(BinaryCommand cmd,
                                       const char* topic,
                                       const uint8_t* payload, size_t payload_len,
                                       bool sign) {
    size_t topic_len = strlen(topic);
    if (topic_len > 256) {
        Serial.println("[MetricMQ] Topic too long (max 256 bytes)");
        return false;
    }

    // Signature is 64 bytes + 4 bytes key_id = 68 bytes overhead for signed frames
    size_t sig_overhead = sign ? 68 : 0;

    // Check total frame size: 16-byte header + topic + sig_overhead + payload
    if (16 + topic_len + sig_overhead + payload_len > 1500) {
        Serial.println("[MetricMQ] Frame too large (max 1500 bytes)");
        return false;
    }

    // Build the message to sign: topic_bytes + payload_bytes (no separator)
    uint8_t sig[64] = {};
    if (sign) {
        // Concatenate topic + payload for signing
        size_t msg_len = topic_len + payload_len;
        uint8_t* msg_buf = (uint8_t*)malloc(msg_len);
        if (!msg_buf) {
            Serial.println("[MetricMQ] malloc failed for signing buffer");
            return false;
        }
        memcpy(msg_buf, topic, topic_len);
        memcpy(msg_buf + topic_len, payload, payload_len);

        // Ed25519 detached signature
        crypto_sign_detached(sig, nullptr, msg_buf, msg_len, _sk);
        free(msg_buf);
    }

    // Build 16-byte header
    // Payload length in header = actual payload only (NOT including sig overhead)
    // The broker knows to read sig+key_id after topic for SIGNED_PUBLISH
    uint8_t header[16] = {};
    header[0] = 0x01;                           // protocol version
    header[1] = (uint8_t)cmd;                   // command
    _writeU16BE(&header[2], (uint16_t)topic_len);
    _writeU32BE(&header[4], (uint32_t)payload_len);
    _writeU64BE(&header[8], 0ULL);              // sequence — assigned by broker

    // Send header
    if (_tcp.write(header, 16) != 16) goto send_fail;

    // Send topic
    if (_tcp.write((const uint8_t*)topic, topic_len) != topic_len) goto send_fail;

    // For signed frames: send signature then key_id before payload
    if (sign) {
        if (_tcp.write(sig, 64) != 64) goto send_fail;
        uint8_t kid[4];
        _writeU32BE(kid, _key_id);
        if (_tcp.write(kid, 4) != 4) goto send_fail;
    }

    // Send payload
    if (payload_len > 0) {
        if (_tcp.write(payload, payload_len) != payload_len) goto send_fail;
    }

    return true;

send_fail:
    Serial.println("[MetricMQ] TCP write failed — connection lost");
    _connected = false;
    _tcp.stop();
    return false;
}

bool MetricMQClient::_sendSubscribeFrame(const char* topic) {
    size_t topic_len = strlen(topic);

    // For subscribe, we embed client_id in the payload so the broker
    // can track exactly-once ACK offsets per client
    std::string cid = _client_id.c_str();
    const uint8_t* payload = (const uint8_t*)cid.c_str();
    size_t payload_len = _exactly_once ? cid.size() : 0;

    uint8_t header[16] = {};
    header[0] = 0x01;
    header[1] = (uint8_t)BinaryCommand::SUBSCRIBE;
    _writeU16BE(&header[2], (uint16_t)topic_len);
    _writeU32BE(&header[4], (uint32_t)payload_len);
    _writeU64BE(&header[8], 0ULL);

    if (_tcp.write(header, 16) != 16) return false;
    if (_tcp.write((const uint8_t*)topic, topic_len) != topic_len) return false;
    if (payload_len > 0) {
        if (_tcp.write(payload, payload_len) != payload_len) return false;
    }
    return true;
}

bool MetricMQClient::_sendPing() {
    uint8_t frame[16] = {};
    frame[0] = 0x01;
    frame[1] = (uint8_t)BinaryCommand::PING;
    return _tcp.write(frame, 16) == 16;
}

// ── Incoming Frame Polling ────────────────────────────────────────────────

void MetricMQClient::_pollIncoming() {
    // Receive buffer — 2048 bytes max incoming frame
    static uint8_t buf[2048];
    static size_t  buf_len = 0;

    // Read available bytes into buffer
    while (_tcp.available() && buf_len < sizeof(buf)) {
        buf[buf_len++] = (uint8_t)_tcp.read();
    }

    // Need at least a 16-byte header to parse
    while (buf_len >= 16) {
        // Check protocol version
        if (buf[0] != 0x01) {
            // Out of sync — clear buffer
            buf_len = 0;
            return;
        }

        BinaryCommand cmd = (BinaryCommand)buf[1];
        uint16_t topic_len   = _readU16BE(&buf[2]);
        uint32_t payload_len = _readU32BE(&buf[4]);
        uint64_t seq         = _readU64BE(&buf[8]);

        // Sanity check lengths
        if (topic_len > 256 || payload_len > 2000) {
            Serial.printf("[MetricMQ] Incoming frame too large (t=%u p=%u) — dropping\n",
                          topic_len, payload_len);
            buf_len = 0;
            return;
        }

        size_t total = 16 + topic_len + payload_len;
        if (buf_len < total) break;  // incomplete frame, wait for more data

        // Handle PONG (keep-alive response)
        if (cmd == BinaryCommand::PONG) {
            // Consume frame
            memmove(buf, buf + total, buf_len - total);
            buf_len -= total;
            continue;
        }

        // Handle incoming PUBLISH (broker delivering a message to this subscriber)
        if (cmd == BinaryCommand::PUBLISH || cmd == BinaryCommand::SIGNED_PUBLISH) {
            // Extract topic string (null-terminate it)
            char topic_str[257] = {};
            memcpy(topic_str, buf + 16, topic_len);
            topic_str[topic_len] = '\0';

            // Extract payload
            const uint8_t* payload_ptr = buf + 16 + topic_len;

            // For signed frames, skip the 64-byte sig + 4-byte key_id prefix
            size_t actual_payload_len = payload_len;
            if (cmd == BinaryCommand::SIGNED_PUBLISH && payload_len >= 68) {
                payload_ptr       += 68;
                actual_payload_len -= 68;
            }

            // Send ACK if exactly-once is enabled
            if (_exactly_once && seq > 0) {
                uint8_t ack[16] = {};
                ack[0] = 0x01;
                ack[1] = (uint8_t)BinaryCommand::ACK;
                _writeU64BE(&ack[8], seq);
                _tcp.write(ack, 16);
                _last_seq = seq;
            }

            // Dispatch to matching subscribers
            _dispatch(topic_str, payload_ptr, actual_payload_len, seq);
        }

        // Consume processed frame
        memmove(buf, buf + total, buf_len - total);
        buf_len -= total;
    }
}

void MetricMQClient::_dispatch(const char* topic,
                                const uint8_t* payload, size_t len,
                                uint64_t seq) {
    for (auto& s : _subs) {
        const char* pat = s.topic.c_str();
        size_t pt = strlen(pat);
        size_t tt = strlen(topic);

        bool match = false;

        // Exact match
        if (strcmp(pat, topic) == 0) {
            match = true;
        }
        // Global wildcard "#"
        else if (strcmp(pat, "#") == 0) {
            match = true;
        }
        // Prefix wildcard "sensors/#"
        else if (pt > 2 && pat[pt-2] == '/' && pat[pt-1] == '#') {
            // Check if topic starts with the prefix before "/#"
            size_t prefix_len = pt - 2;
            if (tt >= prefix_len && memcmp(pat, topic, prefix_len) == 0) {
                match = true;
            }
        }
        // Single-level wildcard "sensors/+"
        else if (pt > 0 && pat[pt-1] == '+') {
            // Match one segment — topic must not have a '/' after the + position
            size_t prefix_len = pt - 1;  // length before the +
            if (tt >= prefix_len && memcmp(pat, topic, prefix_len) == 0) {
                // No additional slash in the remaining segment
                bool extra_slash = false;
                for (size_t i = prefix_len; i < tt; ++i) {
                    if (topic[i] == '/') { extra_slash = true; break; }
                }
                if (!extra_slash) match = true;
            }
        }

        if (match) {
            s.callback(topic, payload, len, seq);
        }
    }
}