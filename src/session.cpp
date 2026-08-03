#if defined(_WIN32) || defined(WIN32)
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define close_socket closesocket
#define sleep_ms(ms) Sleep(ms)
#define SOCKLEN_T int
// On Windows, SO_RCVTIMEO takes a DWORD timeout in milliseconds.
static inline void set_recv_timeout(int fd, int seconds) {
    DWORD ms = static_cast<DWORD>(seconds) * 1000u;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
}
static inline bool is_recv_timeout_error() {
    int e = WSAGetLastError();
    return e == WSAETIMEDOUT || e == WSAEWOULDBLOCK;
}
#else
#include <unistd.h>
#include <arpa/inet.h>
#define close_socket close
#define sleep_ms(ms) usleep(ms * 1000)
#define SOCKLEN_T socklen_t
// On POSIX, SO_RCVTIMEO takes a struct timeval.
static inline void set_recv_timeout(int fd, int seconds) {
    struct timeval tv{seconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}
static inline bool is_recv_timeout_error() {
    return errno == EAGAIN || errno == EWOULDBLOCK;
}
#endif

#include "session.hpp"
#include "broker.hpp"
#include "resp_parser.hpp"
#include "binary_protocol.hpp"
#include "metricmq/logger.hpp"
#include "metricmq/crypto.hpp"
#include <iostream>
#include <string>
#include <memory>
#include <cstring>
#include <algorithm>
#include <chrono>

namespace metricmq {

Session::Session(int sock_fd, Broker* broker)
    : sock_fd_(sock_fd), broker_(broker), protocol_type_(ProtocolType::UNKNOWN),
      sequence_(0), last_activity_(std::chrono::steady_clock::now()) {
    LOG_DEBUG("Session created: fd={}", sock_fd);
    std::cout << "New client connected: " << sock_fd << "\n";
}

ProtocolType Session::detectProtocol(const std::string& buffer) {
    if (buffer.empty()) return ProtocolType::UNKNOWN;
    
    uint8_t first_byte = static_cast<uint8_t>(buffer[0]);
    
    // RESP starts with: +, -, :, $, *
    if (first_byte == '+' || first_byte == '-' || first_byte == ':' ||
        first_byte == '$' || first_byte == '*') {
        LOG_DEBUG("Protocol detected: RESP (fd={})", sock_fd_);
        return ProtocolType::RESP;
    }
    
    // Binary protocol: version byte (currently 0x01)
    if (first_byte == BINARY_PROTOCOL_VERSION) {
        LOG_DEBUG("Protocol detected: BINARY (fd={})", sock_fd_);
        return ProtocolType::BINARY;
    }
    
    LOG_WARN("Unknown protocol detected: first_byte=0x{:02x} (fd={})", first_byte, sock_fd_);
    return ProtocolType::UNKNOWN;
}

// Maximum size of the per-session receive buffer (16 MB).
// A client claiming a payload larger than this is either buggy or malicious.
// The connection is dropped rather than allocating unbounded memory.
static constexpr size_t MAX_RECV_BUFFER = 16 * 1024 * 1024;

void Session::run() {
    // Set a receive timeout so recv() wakes up periodically even when the
    // client is silent. This lets us detect idle connections without a
    // dedicated watchdog thread.
    set_recv_timeout(sock_fd_, RECV_TIMEOUT_S);

    char buffer[4096];
    try {
        while (true) {
            int n = recv(sock_fd_, buffer, sizeof(buffer), 0);
            if (n < 0) {
                if (is_recv_timeout_error()) {
                    // recv() timed out — check how long we've been idle
                    auto idle_s = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - last_activity_).count();
                    if (idle_s >= SESSION_IDLE_TIMEOUT_S) {
                        LOG_WARN("Session fd={} idle for {}s — closing zombie connection",
                                 sock_fd_, idle_s);
                        break;
                    }
                    continue;  // not idle long enough yet — keep waiting
                }
                LOG_WARN("Recv error on fd={}: {}", sock_fd_, errno);
                break;
            }
            if (n == 0) {
                break;  // connection closed gracefully
            }

            last_activity_ = std::chrono::steady_clock::now();

            // Guard against unbounded buffer growth (OOM / slow-loris style attack).
            // If a client has been trickling data without completing valid frames,
            // drop the connection once the staging buffer exceeds the limit.
            if (recv_buffer_.size() + static_cast<size_t>(n) > MAX_RECV_BUFFER) {
                LOG_WARN("recv_buffer_ exceeded {} bytes on fd={} — dropping connection",
                         MAX_RECV_BUFFER, sock_fd_);
                sendBinary(BinaryFrame::error("Message too large — connection closed"));
                break;
            }

            // Append to receive buffer
            recv_buffer_.append(buffer, n);

            // Auto-detect protocol on first message
            if (protocol_type_ == ProtocolType::UNKNOWN) {
                protocol_type_ = detectProtocol(recv_buffer_);
                if (protocol_type_ == ProtocolType::UNKNOWN) {
                    LOG_WARN("Unable to detect protocol on fd={}", sock_fd_);
                    continue;
                }
                LOG_INFO("Protocol detected: {} (fd={})",
                         protocol_type_ == ProtocolType::RESP ? "RESP" : "Binary", sock_fd_);
            }

            // Parse messages based on protocol
            if (protocol_type_ == ProtocolType::RESP) {
                while (!recv_buffer_.empty()) {
                    auto result = RespParser::parse(recv_buffer_);
                    if (!result) break;

                    auto [value, bytes_consumed] = *result;
                    recv_buffer_.erase(0, bytes_consumed);
                    handleCommand(value);
                }
            } else if (protocol_type_ == ProtocolType::BINARY) {
                while (!recv_buffer_.empty()) {
                    auto result = BinaryProtocol::parse(recv_buffer_);
                    if (!result) break;

                    auto [frame, bytes_consumed] = *result;
                    recv_buffer_.erase(0, bytes_consumed);
                    handleBinaryFrame(frame);
                }
            }
        }
    } catch (const std::exception& e) {
        // Parsers or handlers threw — log it and let the session exit cleanly.
        // Without this catch the entire broker process would be terminated via
        // std::terminate() because this runs in a detached thread.
        LOG_ERROR("Session fd={} threw exception: {} — closing connection", sock_fd_, e.what());
    } catch (...) {
        LOG_ERROR("Session fd={} threw unknown exception — closing connection", sock_fd_);
    }

    LOG_INFO("Client disconnected: fd={}{}", sock_fd_,
             client_id_.empty() ? "" : " client_id=" + client_id_);
    if (!client_id_.empty()) {
        broker_->unregisterClient(client_id_);
    }

    broker_->removeSession(this);
    close_socket(sock_fd_);
}

void Session::handleBinaryFrame(const BinaryFrame& frame) {
    switch (frame.command) {
        case BinaryCommand::CMD_SUBSCRIBE: {
            // Topic format: "client_id\0topic" (client_id is optional, backward compatible)
            std::string topic = frame.topic;
            size_t sep = topic.find('\0');
            
            if (sep != std::string::npos) {
                // Legacy format: "client_id\0topic" embedded in the topic field
                client_id_ = topic.substr(0, sep);
                topic = topic.substr(sep + 1);

                broker_->registerClient(client_id_, this);
                broker_->replayMessagesForClient(this, topic, client_id_);
                broker_->subscribe(this, topic);
            } else if (!frame.payload.empty()) {
                // New format (MetricMQ library): client_id is in the payload field,
                // actual topic is in the topic field.
                client_id_ = frame.payload;

                broker_->registerClient(client_id_, this);
                broker_->replayMessagesForClient(this, topic, client_id_);
                broker_->subscribe(this, topic);
            } else {
                // No client_id present — plain subscribe, no replay.
                broker_->subscribe(this, topic);
            }
            
            // Send ACK
            sendBinary(BinaryFrame::ack(frame.sequence));
            std::cout << "Binary SUBSCRIBE: " << topic;
            if (!client_id_.empty()) {
                std::cout << " (client: " << client_id_ << ")";
            }
            std::cout << "\n";
            break;
        }

        case BinaryCommand::CMD_UNSUBSCRIBE: {
            broker_->unsubscribe(this, frame.topic);
            sendBinary(BinaryFrame::ack(frame.sequence));
            break;
        }

        case BinaryCommand::CMD_PUBLISH: {
            // Check if topic requires signature (secure/ prefix)
            if (frame.topic.starts_with("secure/")) {
                sendBinary(BinaryFrame::error("Topic '" + frame.topic + "' requires signed publish (CMD_SIGNED_PUBLISH)"));
                std::cout << "REJECTED unsigned publish to secure topic: " << frame.topic << "\n";
                LOG_WARN("Rejected unsigned publish to secure topic '{}' from fd={}", frame.topic, sock_fd_);
                break;
            }

            // Create MESSAGE frame for subscribers
            BinaryFrame msg = BinaryFrame::message(frame.topic, frame.payload, ++sequence_);
            std::string serialized = BinaryProtocol::serialize(msg);
            broker_->publish(frame.topic, serialized);
            
            // Send ACK to publisher
            sendBinary(BinaryFrame::ack(frame.sequence));
            std::cout << "Binary PUBLISH: " << frame.topic << " (" << frame.payload.size() << " bytes)\n";
            break;
        }

        case BinaryCommand::CMD_PING: {
            sendBinary(BinaryFrame::pong());
            break;
        }

        case BinaryCommand::CMD_ACK: {
            // Handle acknowledgment from client
            if (!client_id_.empty()) {
                broker_->handleAck(client_id_, frame.sequence);
            }
            break;
        }

        case BinaryCommand::CMD_SIGNED_PUBLISH: {
            // Verify signature before publishing
            auto& keystore = crypto::get_global_keystore();
            
            // Build message to verify: topic + payload
            std::string message_to_verify = frame.topic + frame.payload;
            
            // Verify using stored public key
            bool valid = keystore.verify_with_key(
                frame.key_id,
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(message_to_verify.data()),
                    message_to_verify.size()
                ),
                frame.signature
            );
            
            if (!valid) {
                sendBinary(BinaryFrame::error("Invalid signature or unknown key"));
                std::cout << "REJECTED signed publish: invalid signature (key_id=" 
                          << frame.key_id << ")\n";
                LOG_WARN("Rejected signed publish: invalid signature key_id={} topic='{}' fd={}",
                         frame.key_id, frame.topic, sock_fd_);
                break;
            }
            
            // Check topic-scope authorization
            auto key_info = keystore.get_key_info(frame.key_id);
            if (key_info && !key_info->allowed_topics.empty()) {
                // allowed_topics can be a pattern like "sensors/*" or exact like "secure/data"
                const std::string& allowed = key_info->allowed_topics;
                bool topic_ok = false;
                
                if (allowed == "*" || allowed == "#") {
                    topic_ok = true;  // Wildcard: all topics
                } else if (allowed.size() >= 2 && allowed.back() == '*') {
                    // Prefix match: "sensors/*" matches "sensors/temp", "sensors/hum", etc.
                    std::string prefix = allowed.substr(0, allowed.size() - 1);
                    topic_ok = frame.topic.starts_with(prefix);
                } else {
                    topic_ok = (frame.topic == allowed);  // Exact match
                }
                
                if (!topic_ok) {
                    sendBinary(BinaryFrame::error("Key not authorized for topic '" + frame.topic + "'"));
                    std::cout << "REJECTED signed publish: key_id=" << frame.key_id
                              << " not authorized for topic '" << frame.topic << "'"
                              << " (allowed: '" << allowed << "')\n";
                    LOG_WARN("Rejected signed publish: key_id={} not authorized for topic '{}' (allowed: '{}')",
                             frame.key_id, frame.topic, allowed);
                    break;
                }
            }
            
            // Signature valid + topic authorized - create SIGNED_MESSAGE for subscribers
            BinaryFrame msg = BinaryFrame::signed_message(
                frame.topic, frame.payload, frame.signature, frame.key_id, ++sequence_
            );
            std::string serialized = BinaryProtocol::serialize(msg);
            broker_->publish(frame.topic, serialized);
            
            // Send ACK to publisher
            sendBinary(BinaryFrame::ack(frame.sequence));
            std::cout << "VERIFIED signed publish: " << frame.topic 
                      << " (key_id=" << frame.key_id << ")\n";
            LOG_INFO("Verified signed publish: topic='{}' key_id={} fd={}", 
                     frame.topic, frame.key_id, sock_fd_);
            break;
        }

        case BinaryCommand::CMD_SIGNED_MESSAGE:
            // This is broker->client only, ignore if received
            break;

        default:
            sendBinary(BinaryFrame::error("Unknown command"));
            break;
    }
}

void Session::sendBinary(const BinaryFrame& frame) {
    std::string data = BinaryProtocol::serialize(frame);
    send(data);
}

void Session::handleCommand(const RespValue& command) {
    if (!command.isArray()) {
        sendResp(RespValue::error("ERR Protocol error: expected array"));
        return;
    }

    const auto& arr = command.asArray();
    if (arr.empty()) {
        sendResp(RespValue::error("ERR empty command"));
        return;
    }

    std::string cmd = arr[0].asString();
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);

    if (cmd == "SUBSCRIBE") {
        // SUBSCRIBE topic1 [topic2 ...]
        for (size_t i = 1; i < arr.size(); ++i) {
            std::string topic = arr[i].asString();
            broker_->subscribe(this, topic);
            
            // Send subscription confirmation
            RespArray resp;
            resp.push_back(RespValue::bulkString("subscribe"));
            resp.push_back(RespValue::bulkString(topic));
            resp.push_back(RespValue::integer(static_cast<int64_t>(i)));
            sendResp(RespValue::array(resp));
        }
    }
    else if (cmd == "UNSUBSCRIBE") {
        // UNSUBSCRIBE topic1 [topic2 ...]
        for (size_t i = 1; i < arr.size(); ++i) {
            std::string topic = arr[i].asString();
            broker_->unsubscribe(this, topic);
            
            RespArray resp;
            resp.push_back(RespValue::bulkString("unsubscribe"));
            resp.push_back(RespValue::bulkString(topic));
            resp.push_back(RespValue::integer(0));
            sendResp(RespValue::array(resp));
        }
    }
    else if (cmd == "PUBLISH") {
        // PUBLISH topic message
        if (arr.size() != 3) {
            sendResp(RespValue::error("ERR wrong number of arguments for PUBLISH"));
            return;
        }
        
        std::string topic = arr[1].asString();
        std::string payload = arr[2].asString();
        
        // Store and route raw payload; deliverMessage() handles per-protocol wrapping
        broker_->publish(topic, payload);
        
        // Reply with number of subscribers (simplified: always return 1)
        sendResp(RespValue::integer(1));
    }
    else if (cmd == "PING") {
        // PING [message]
        if (arr.size() > 1) {
            sendResp(RespValue::bulkString(arr[1].asString()));
        } else {
            sendResp(RespValue::simpleString("PONG"));
        }
    }
    else if (cmd == "ACK") {
        // ACK sequence_id
        if (arr.size() != 2) {
            sendResp(RespValue::error("ERR wrong number of arguments for ACK"));
            return;
        }
        
        uint64_t seq = static_cast<uint64_t>(arr[1].asInteger());
        if (!client_id_.empty()) {
            broker_->handleAck(client_id_, seq);
        }
        sendResp(RespValue::simpleString("OK"));
    }
    else {
        sendResp(RespValue::error("ERR unknown command '" + cmd + "'"));
    }
}

void Session::sendResp(const RespValue& value) {
    std::string data = RespParser::serialize(value);
    send(data);
}

void Session::send(const std::string& data) {
    if (sock_fd_ == -1) return;
    // Mutex ensures that replay and live-delivery threads cannot interleave
    // bytes from different frames on the same socket.
    std::lock_guard<std::mutex> lock(send_mutex_);
    // Loop until all bytes are sent. ::send() on a loaded kernel buffer may
    // return fewer bytes than requested; silently dropping the remainder would
    // produce truncated frames on the receiver.
    const char* ptr = data.c_str();
    size_t remaining = data.size();
    while (remaining > 0) {
        int sent = ::send(sock_fd_, ptr, static_cast<int>(remaining), 0);
        if (sent < 0) {
            LOG_WARN("send() failed on fd={}: errno={}", sock_fd_, errno);
            break;
        }
        ptr       += sent;
        remaining -= static_cast<size_t>(sent);
    }
}

} // namespace metricmq
