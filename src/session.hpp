/**
 * @file session.hpp
 * @brief Per-connection session: protocol detection and message dispatch.
 *
 * Each accepted TCP connection creates one Session running on its own detached
 * thread. Responsibilities:
 * - Buffer received bytes into recv_buffer_ (capped at 16 MB).
 * - Detect RESP vs binary protocol from the first byte.
 * - Parse complete frames and dispatch to the broker.
 * - Send responses back to the client.
 *
 * @par Protocol detection (first byte)
 * | Byte | Protocol |
 * |------|----------|
 * | +  -  :  $  * | RESP (Redis-compatible) |
 * | 0x01 | Binary (MetricMQ native) |
 *
 * @par Crash isolation
 * run() is wrapped in try/catch so an exception from one malformed frame
 * closes only this session � not the entire broker process.
 */
#pragma once
#include <string>
#include <chrono>
#include <mutex>

namespace metricmq {

class Broker;
class RespValue;
struct BinaryFrame;

/// Protocol detected from the first byte of a connection.
enum class ProtocolType {
    UNKNOWN, ///< First byte not yet received.
    RESP,    ///< Redis Serialization Protocol (text).
    BINARY   ///< MetricMQ native binary framing.
};

/**
 * @brief Single-connection session running on a dedicated thread.
 *
 * Created by Broker::run() via make_shared<Session>(fd, broker) and
 * started with thread([session]{ session->run(); }).detach().
 */
class Session {
public:
    /**
     * @brief Construct a session for an accepted socket.
     * @param sock_fd File descriptor of the accepted TCP connection.
     * @param broker  Non-owning pointer to the shared Broker instance.
     */
    Session(int sock_fd, Broker* broker);

    /**
     * @brief Blocking receive loop. Returns when the connection closes or errors.
     *
     * Drops connection and logs a warning if recv_buffer_ would exceed 16 MB.
     */
    void run();

    /**
     * @brief Write raw bytes to the client socket.
     * @param data Bytes to send (RESP-encoded responses, raw payloads, etc.).
     */
    void send(const std::string& data);

    /**
     * @brief Send a message payload prefixed with its sequence ID.
     * @param sequence Broker-assigned monotonic sequence number.
     * @param data     Payload bytes.
     */
    void sendWithSequence(uint64_t sequence, const std::string& data);

    /** @brief Return the registered client identifier (empty for anonymous clients). */
    const std::string& getClientId() const { return client_id_; }

    /**
     * @brief Set the client identifier.
     *
     * Called when parsing the SUBSCRIBE frame: the topic field carries
     * the client_id and the actual topic separated by a null byte.
     */
    void setClientId(const std::string& client_id) { client_id_ = client_id; }

    /** @brief Return the detected protocol type for this session. */
    ProtocolType getProtocol() const { return protocol_type_; }

    friend class Broker;  ///< Allow Broker to call private send methods

private:
    void handleCommand(const RespValue& command);     ///< Dispatch RESP command to broker.
    void handleBinaryFrame(const BinaryFrame& frame); ///< Dispatch binary frame to broker.
    void sendResp(const RespValue& value);             ///< Serialize and send a RESP value.
    void sendBinary(const BinaryFrame& frame);         ///< Serialize and send a binary frame.
    ProtocolType detectProtocol(const std::string& buffer); ///< Classify by first byte.

    int          sock_fd_;        ///< Accepted client socket file descriptor.
    Broker*      broker_;         ///< Non-owning pointer to the shared Broker.
    std::string  recv_buffer_;    ///< Accumulated receive buffer (cap: 16 MB).
    ProtocolType protocol_type_;  ///< Protocol detected for this connection.
    uint64_t     sequence_;       ///< Local sequence counter.
    std::string  client_id_;      ///< Client ID for exactly-once delivery tracking.
    mutable std::mutex send_mutex_;  ///< Serialises concurrent sendBinary/send calls.

    /// Timestamp of the last byte received on this connection.
    /// Reset on every successful recv(). When now() - last_activity_ exceeds
    /// SESSION_IDLE_TIMEOUT_S the connection is closed.
    std::chrono::steady_clock::time_point last_activity_;

    /// Idle threshold: connection closed after this many seconds with no data.
    static constexpr int SESSION_IDLE_TIMEOUT_S = 300;  // 5 minutes

    /// SO_RCVTIMEO interval: short enough to poll idle state, long enough not
    /// to spin. recv() wakes up with a timeout error every RECV_TIMEOUT_S seconds.
    static constexpr int RECV_TIMEOUT_S = 30;
};

} // namespace metricmq
