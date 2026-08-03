#pragma once
/*
 * MetricMQ ESP32 Arduino Client Library
 * Lightweight pub/sub client for the MetricMQ broker.
 *
 * Copy MetricMQ.h and MetricMQ.cpp into your project's lib/MetricMQ/ folder.
 * Requires: arduino-esp32 v2.0.0+ (libsodium bundled in SDK)
 *
 * API:
 *   MetricMQClient client;
 *   client.connect("192.168.1.100", 6379);            // connect (no client_id)
 *   client.connect("192.168.1.100", 6379, "my-id");   // connect with exactly-once replay
 *   client.publish("topic", "payload");
 *   client.subscribe("topic", callback);
 *   client.loop();          // call every loop() iteration
 *   client.isConnected();   // poll this — no auto-reconnect
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <functional>
#include <vector>
#include <string>

// Maximum number of public keys the client can hold for verifying
// incoming signed messages. Verified against incoming signed frames.
static constexpr uint8_t MAX_VERIFY_KEYS = 4;

// Keep-alive PING interval in milliseconds (60 seconds)
static constexpr uint32_t KEEPALIVE_MS = 60000UL;

// Binary protocol commands
enum class BinaryCommand : uint8_t {
    PUBLISH        = 0x02,
    SUBSCRIBE      = 0x03,
    ACK            = 0x06,
    PING           = 0x07,
    PONG           = 0x08,
    SIGNED_PUBLISH = 0x10,
};

// Callback type for received messages
// topic   — null-terminated topic string
// payload — raw payload bytes (not null-terminated)
// len     — payload length in bytes
// seq     — broker-assigned sequence number (0 if not in binary mode)
using MetricMQCallback = std::function<void(
    const char* topic,
    const uint8_t* payload,
    size_t len,
    uint64_t seq
)>;

struct Subscription {
    std::string      topic;
    MetricMQCallback callback;
};

class MetricMQClient {
public:
    MetricMQClient();
    ~MetricMQClient();

    // Connect to broker. Pass client_id for exactly-once delivery replay.
    // setSigningKey() must be called before connect() if using signed publishes.
    bool connect(const char* host, uint16_t port,
                 const char* client_id = nullptr);

    // Disconnect cleanly
    void disconnect();

    // Returns true if TCP connection is alive.
    // Auto-reconnect is NOT built-in — poll this and call connect() manually.
    bool isConnected();

    // Must be called every loop() iteration.
    // Drives the 60-second keep-alive PING and fires incoming message callbacks.
    void loop();

    // Publish an unsigned message.
    // topic + payload must fit within ~1484 bytes combined.
    bool publish(const char* topic, const char* payload);
    bool publish(const char* topic, const uint8_t* payload, size_t len);

    // Publish a signed message (requires setSigningKey() before connect()).
    // Frame overhead: +64 bytes signature +4 bytes key_id vs unsigned.
    // topic + payload must fit within ~1416 bytes combined.
    bool publishSigned(const char* topic, const char* payload);
    bool publishSigned(const char* topic, const uint8_t* payload, size_t len);

    // Subscribe to a topic. Callback fires on every received message.
    // Wildcard: "sensors/#" catches everything under sensors/.
    // Call this after connect(). Re-call after every reconnect.
    bool subscribe(const char* topic, MetricMQCallback callback);

    // Set Ed25519 signing key before connect().
    // key_id must match what is registered in the broker keystore.
    // sk: 64-byte Ed25519 secret key (from metricmq-keygen output).
    void setSigningKey(const char* device_id, const uint8_t sk[64]);
    void setSigningKey(const uint8_t sk[64], uint32_t key_id);

    // Disable exactly-once delivery tracking (saves ~2KB RAM on tight budgets).
    void setExactlyOnce(bool enabled);

    // Generate a keypair from the ESP32's chip ID (deterministic per device).
    // Call once; store sk in NVS for production use.
    static void generateKeypair(uint8_t pk_out[32], uint8_t sk_out[64]);

private:
    WiFiClient   _tcp;
    String       _host;
    uint16_t     _port          = 6379;
    String       _client_id;
    bool         _connected     = false;
    bool         _exactly_once  = true;
    bool         _signing       = false;
    uint32_t     _key_id        = 0;
    uint8_t      _sk[64]        = {};
    uint64_t     _last_seq      = 0;
    uint32_t     _last_ping     = 0;

    std::vector<Subscription> _subs;

    // Internal frame send helpers
    bool _sendBinaryFrame(BinaryCommand cmd,
                          const char* topic,
                          const uint8_t* payload, size_t payload_len,
                          bool sign);

    bool _sendPing();
    bool _sendSubscribeFrame(const char* topic);
    bool _sendConnectFrame();

    // Receive and dispatch one frame (non-blocking)
    void _pollIncoming();

    // Write uint16/uint32/uint64 big-endian
    static void _writeU16BE(uint8_t* buf, uint16_t v);
    static void _writeU32BE(uint8_t* buf, uint32_t v);
    static void _writeU64BE(uint8_t* buf, uint64_t v);
    static uint16_t _readU16BE(const uint8_t* buf);
    static uint32_t _readU32BE(const uint8_t* buf);
    static uint64_t _readU64BE(const uint8_t* buf);

    void _dispatch(const char* topic,
                   const uint8_t* payload, size_t len,
                   uint64_t seq);
};