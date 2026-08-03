// src/broker.hpp
#pragma once
#include <vector>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <mutex>
#include <atomic>
#include "storage/LmdbStorage.hpp"

namespace metricmq {

class Session;

/**
 * @brief Bounded, O(1)-lookup ACK set — replaces unbounded unordered_set.
 *
 * Keeps the last MAX sequence numbers acknowledged by a single client.
 * When full, the oldest entry is evicted (FIFO). Memory per client is fixed
 * at MAX * (8 + ~56) bytes ≈ 640 KB for MAX = 10 000.
 *
 * Thread safety: not thread-safe — must be accessed under the broker mutex.
 */
struct BoundedAckSet {
    static constexpr size_t MAX = 10'000; ///< Max ACKs kept per client in memory.

    void insert(uint64_t seq) {
        if (lookup_.count(seq)) return;       // already acked — no-op
        if (order_.size() >= MAX) {
            lookup_.erase(order_.front());    // evict oldest
            order_.pop_front();
        }
        order_.push_back(seq);
        lookup_.insert(seq);
        if (seq > max_seq_) max_seq_ = seq;
    }

    bool contains(uint64_t seq) const { return lookup_.count(seq) > 0; }

    /// Highest sequence number ever inserted (survives eviction of older entries).
    uint64_t max_seq() const { return max_seq_; }

    bool empty() const { return lookup_.empty(); }

private:
    std::deque<uint64_t>         order_;    ///< Insertion order — front = oldest.
    std::unordered_set<uint64_t> lookup_;   ///< O(1) membership test.
    uint64_t                     max_seq_{0};
};

class Broker {
public:
    explicit Broker(int port = 6379);
    ~Broker();
    void run();  // blocking
    void stop();  // graceful shutdown

    // Topic subscription management
    void subscribe(Session* session, const std::string& topic);
    void unsubscribe(Session* session, const std::string& topic);
    uint64_t publish(const std::string& topic, const std::string& payload);  // Returns sequence ID

    // Exactly-once semantics
    void handleAck(const std::string& client_id, uint64_t sequence);
    uint64_t getLastSequence() const;
    uint64_t getLastAck(const std::string& client_id) const;
    bool isAcked(const std::string& client_id, uint64_t sequence) const;

    // Replay messages for newly subscribed session
    void replayMessages(Session* session, const std::string& topic, uint64_t from_seq = 0);
    void replayMessagesForClient(Session* session, const std::string& topic, const std::string& client_id);

    // Client management
    void registerClient(const std::string& client_id, Session* session);
    void unregisterClient(const std::string& client_id);

    // Session management
    void removeSession(Session* session);

    friend class Session;  // Allow Session to access private members

private:
    int countTotalSubscribers() const;  // Helper for metrics
    void runCompactionIfDue();          // Periodic LMDB compaction
    
    // Protocol-aware message delivery
    void deliverMessage(Session* session, const std::string& topic, 
                       const std::string& payload, uint64_t sequence);

    int port_;
    int server_fd_;
    std::vector<std::shared_ptr<Session>> sessions_;

    // Topic -> Set of subscribers
    std::unordered_map<std::string, std::unordered_set<Session*>> topic_subscribers_;

    // Persistence layer
    std::unique_ptr<storage::LmdbStorage> persistence_;

    // Exactly-once: bounded per-client ACK tracking (replaces unbounded unordered_set)
    std::unordered_map<std::string, BoundedAckSet> client_acks_;
    // client_id -> last ACK'd sequence (optimization for sequential access)
    std::unordered_map<std::string, uint64_t> last_ack_seq_;
    // client_id -> session mapping
    std::unordered_map<std::string, Session*> client_sessions_;

    uint64_t current_sequence_;

    // Compaction: keep the last MAX_STORED_MESSAGES in LMDB; run every COMPACT_EVERY publishes
    static constexpr uint64_t MAX_STORED_MESSAGES = 100'000;
    static constexpr uint64_t COMPACT_EVERY       = 1'000;
    uint64_t publish_count_{0};

    // Hard limit on simultaneous connections
    static constexpr size_t MAX_CONNECTIONS = 1000;
    std::atomic<size_t> active_connections_{0};

    // Shutdown flag
    std::atomic<bool> shutdown_requested_;

    // Mutex for thread-safe access
    mutable std::mutex mutex_;
};

} // namespace metricmq