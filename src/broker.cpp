// Broker Core Logic

#if defined(_WIN32) || defined(WIN32)
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#define sleep_ms(ms) Sleep(ms)
#define SOCKLEN_T int
#else
#include <unistd.h>
#include <arpa/inet.h>
#define sleep_ms(ms) usleep(ms * 1000)
#define SOCKLEN_T socklen_t
#endif

#include "broker.hpp"
#include "session.hpp"
#include "binary_protocol.hpp"
#include "resp_parser.hpp"
#include "metricmq/logger.hpp"
#include "metricmq/metrics.hpp"
#include <iostream>
#include <cstring>
#include <thread>
#include <chrono>


namespace metricmq {

Broker::Broker(int port) : port_(port), server_fd_(-1), current_sequence_(0), shutdown_requested_(false) {
    LOG_INFO("Initializing MetricMQ Broker on port {}", port_);
    
    // Initialize persistence layer
    persistence_ = std::make_unique<storage::LmdbStorage>("metricmq.db");
    
    // Restore sequence counter from persistence
    if (persistence_) {
        current_sequence_ = persistence_->get_last_seq();
        LOG_INFO("Restored sequence counter from persistence: {}", current_sequence_);
    }
    
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    
    LOG_DEBUG("Broker initialization complete");
}

Broker::~Broker() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void Broker::subscribe(Session* session, const std::string& topic) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        topic_subscribers_[topic].insert(session);
        LOG_INFO("Session subscribed to topic: '{}' (total subscribers: {})", 
                 topic, topic_subscribers_[topic].size());
        
        // Update metrics
        Metrics::instance().incrementSubscriptions();
        Metrics::instance().incrementTopicSubscribers(topic);
        Metrics::instance().setActiveSubscribers(countTotalSubscribers());
        Metrics::instance().setTopicCount(topic_subscribers_.size());
    }
    
    // No replay here for binary clients — session.cpp already calls
    // replayMessagesForClient() before subscribe() so replay is complete
    // before live messages can arrive.
    // RESP clients have no stable client_id so replay is not applicable.
}

void Broker::unsubscribe(Session* session, const std::string& topic) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = topic_subscribers_.find(topic);
    if (it != topic_subscribers_.end()) {
        it->second.erase(session);
        LOG_INFO("Session unsubscribed from topic: '{}' (remaining: {})", 
                 topic, it->second.size());
        
        // Update metrics
        Metrics::instance().incrementUnsubscriptions();
        Metrics::instance().decrementTopicSubscribers(topic);
        Metrics::instance().setActiveSubscribers(countTotalSubscribers());
        
        if (it->second.empty()) {
            topic_subscribers_.erase(it);
            LOG_DEBUG("Topic '{}' removed (no subscribers)", topic);
            Metrics::instance().setTopicCount(topic_subscribers_.size());
        }
    }
}

uint64_t Broker::publish(const std::string& topic, const std::string& payload) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Get next sequence ID
    uint64_t seq = ++current_sequence_;
    
    // Persist message
    if (persistence_) {
        persistence_->save(seq, topic, payload);
    }

    // Trigger periodic compaction (runs outside the hot path every COMPACT_EVERY publishes)
    if (++publish_count_ % COMPACT_EVERY == 0) {
        runCompactionIfDue();
    }
    
    // Find subscribers for this topic
    int delivered = 0;
    auto it = topic_subscribers_.find(topic);
    if (it != topic_subscribers_.end()) {
        for (auto* session : it->second) {
            // Send in the format appropriate for this session's protocol
            deliverMessage(session, topic, payload, seq);
        }
        delivered += it->second.size();
    }
    
    // Also send to wildcard subscribers ("#")
    auto wildcard_it = topic_subscribers_.find("#");
    if (wildcard_it != topic_subscribers_.end()) {
        for (auto* session : wildcard_it->second) {
            // Send in the format appropriate for this session's protocol
            deliverMessage(session, topic, payload, seq);
        }
        delivered += wildcard_it->second.size();
    }
    
    LOG_DEBUG("Published message [seq={}] to topic '{}': {} bytes -> {} subscribers",
              seq, topic, payload.size(), delivered);
    
    // Update metrics
    Metrics::instance().incrementPublished();
    Metrics::instance().incrementTopicMessages(topic);
    Metrics::instance().incrementDelivered();  // Count each delivery
    
    auto end = std::chrono::high_resolution_clock::now();
    auto latency_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    Metrics::instance().recordPublishLatency(latency_us);
    
    return seq;
}

void Broker::replayMessages(Session* session, const std::string& topic, uint64_t from_seq) {
    if (persistence_) {
        // Cap replay to MAX_STORED_MESSAGES — matches the compaction window so we never
        // request records that have already been deleted from LMDB.
        auto messages = persistence_->load_range(from_seq, from_seq + MAX_STORED_MESSAGES);
        for (const auto& [seq, msg_topic, msg_payload] : messages) {
            if (msg_topic == topic) {
                deliverMessage(session, msg_topic, msg_payload, seq);
            }
        }
    }
}

void Broker::removeSession(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove from all topic subscriptions and update per-topic metrics.
    // unsubscribe() only fires on an explicit UNSUBSCRIBE frame; abrupt
    // disconnects come straight here, so we must decrement the gauge ourselves.
    for (auto& [topic, subscribers] : topic_subscribers_) {
        if (subscribers.erase(session)) {
            Metrics::instance().decrementTopicSubscribers(topic);
        }
    }

    // Remove empty topics
    for (auto it = topic_subscribers_.begin(); it != topic_subscribers_.end();) {
        if (it->second.empty()) {
            it = topic_subscribers_.erase(it);
        } else {
            ++it;
        }
    }
    
    // Remove from sessions list
    sessions_.erase(
        std::remove_if(sessions_.begin(), sessions_.end(),
            [session](const auto& s) { return s.get() == session; }),
        sessions_.end()
    );
    active_connections_--;
    
    // Update metrics
    Metrics::instance().incrementDisconnections();
    Metrics::instance().setActiveConnections(sessions_.size());
    Metrics::instance().setActiveSubscribers(countTotalSubscribers());
    Metrics::instance().setTopicCount(topic_subscribers_.size());
}

int Broker::countTotalSubscribers() const {
    // Must be called with mutex locked
    int count = 0;
    for (const auto& [topic, subscribers] : topic_subscribers_) {
        count += subscribers.size();
    }
    return count;
}

void Broker::runCompactionIfDue() {
    // Must be called under the broker mutex (already held by publish())
    if (!persistence_ || current_sequence_ <= MAX_STORED_MESSAGES) return;
    uint64_t threshold = current_sequence_ - MAX_STORED_MESSAGES;
    LOG_INFO("Running LMDB compaction: purging seq <= {}", threshold);
    persistence_->compact(threshold);
    persistence_->purge_old_acks(threshold);
}

void Broker::run() {
    LOG_INFO("Starting broker run loop");
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOG_CRITICAL("Failed to create server socket");
        return;
    }
    LOG_DEBUG("Server socket created: fd={}", server_fd);
    
    int opt = 1;
#ifdef _WIN32
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_CRITICAL("bind() failed on port {}: errno={}", port_, errno);
        close(server_fd);
        return;
    }
    if (listen(server_fd, 10) < 0) {
        LOG_CRITICAL("listen() failed: errno={}", errno);
        close(server_fd);
        return;
    }
    
    server_fd_ = server_fd;  // Store for shutdown
    
    LOG_INFO("Broker listening on 0.0.0.0:{}", port_);
    std::cout << "Broker listening on port " << port_ << "\n";

    while (!shutdown_requested_) {
        // Set timeout on accept to allow checking shutdown flag
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;   // 1 second timeout
        timeout.tv_usec = 0;
        
        int activity = select(server_fd + 1, &readfds, nullptr, nullptr, &timeout);
        
        if (activity < 0) {
            if (!shutdown_requested_) {
                std::cerr << "Select error\n";
            }
            break;
        }
        
        if (activity == 0) {
            // Timeout, check shutdown flag and continue
            continue;
        }
        
        if (FD_ISSET(server_fd, &readfds)) {
            int client = accept(server_fd, nullptr, nullptr);
            if (client < 0) {
                if (!shutdown_requested_) {
                    LOG_WARN("Accept failed: errno={}", errno);
                    std::cerr << "Accept error\n";
                }
                continue;
            }
            
            LOG_INFO("New client connected: fd={}", client);

            // Enforce connection cap before allocating a session
            if (active_connections_.load() >= MAX_CONNECTIONS) {
                LOG_WARN("Connection limit ({}) reached — rejecting fd={}", MAX_CONNECTIONS, client);
                close(client);
                continue;
            }

            auto session = std::make_shared<Session>(client, this);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                sessions_.push_back(session);
            }
            active_connections_++;
            std::thread([session] { session->run(); }).detach();

            // Update metrics
            Metrics::instance().incrementConnections();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                Metrics::instance().setActiveConnections(sessions_.size());
            }
        }
    }
    
    LOG_INFO("Broker run loop exiting (shutdown requested)");
    std::cout << "Broker shutting down...\n";
}

void Broker::stop() {
    LOG_WARN("Graceful shutdown initiated");
    std::cout << "\n🛑 Initiating graceful shutdown...\n";
    
    shutdown_requested_ = true;
    
    // Close server socket to stop accepting new connections
    if (server_fd_ != -1) {
#ifdef _WIN32
        closesocket(server_fd_);
#else
        close(server_fd_);
#endif
        server_fd_ = -1;
    }
    
    // Give sessions time to finish current operations
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Flush persistence layer
    LOG_INFO("Flushing persistence layer to disk");
    std::cout << "💾 Flushing persistence layer...\n";
    if (persistence_) {
        // LMDB will auto-flush on destruction, but we ensure it here
        persistence_.reset();  // Destroy LMDB storage (flushes to disk)
        LOG_INFO("Persistence layer flushed successfully");
        std::cout << "✅ Persistence flushed\n";
    }
    
    LOG_INFO("Graceful shutdown complete");
    std::cout << "✅ Graceful shutdown complete\n";
}

void Broker::handleAck(const std::string& client_id, uint64_t sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Record ACK for this client
    client_acks_[client_id].insert(sequence);
    
    // Update last_ack optimization cache
    if (sequence > last_ack_seq_[client_id]) {
        last_ack_seq_[client_id] = sequence;
    }
    
    // Persist ACK state
    if (persistence_) {
        persistence_->save_ack(client_id, sequence);
    }
    
    // Update metrics
    Metrics::instance().incrementAcks();
    
    LOG_TRACE("ACK received: client='{}' seq={}", client_id, sequence);
}

uint64_t Broker::getLastSequence() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_sequence_;
}

uint64_t Broker::getLastAck(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = last_ack_seq_.find(client_id);
    if (it != last_ack_seq_.end()) {
        return it->second;
    }
    return 0;
}

bool Broker::isAcked(const std::string& client_id, uint64_t sequence) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = client_acks_.find(client_id);
    if (it != client_acks_.end()) {
        return it->second.contains(sequence);
    }
    return false;
}

void Broker::registerClient(const std::string& client_id, Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check for duplicate client ID
    if (client_sessions_.count(client_id) > 0) {
        std::cerr << "Warning: Client ID '" << client_id << "' already connected. Replacing.\n";
    }
    
    client_sessions_[client_id] = session;
    
    // Load ACK state from persistence into bounded set (caps at BoundedAckSet::MAX)
    if (persistence_) {
        auto acks = persistence_->load_acks(client_id);
        auto& bounded = client_acks_[client_id];
        for (uint64_t seq : acks) {
            bounded.insert(seq);
        }
    }
}

void Broker::deliverMessage(Session* session, const std::string& topic, 
                           const std::string& payload, uint64_t sequence) {
    // Send message in the format appropriate for this session's protocol
    ProtocolType protocol = session->getProtocol();
    
    if (protocol == ProtocolType::BINARY) {
        // For binary clients, send as a binary message frame
        BinaryFrame msg = BinaryFrame::message(topic, payload, sequence);
        session->sendBinary(msg);
    } else {
        // RESP clients expect: ["message", topic, payload]
        RespArray msg;
        msg.push_back(RespValue::bulkString("message"));
        msg.push_back(RespValue::bulkString(topic));
        msg.push_back(RespValue::bulkString(payload));
        std::string serialized = RespParser::serialize(RespValue::array(msg));
        session->send(serialized);
    }
}

void Broker::unregisterClient(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    client_sessions_.erase(client_id);
    // Keep ACK state in memory for potential reconnection
}

void Broker::replayMessagesForClient(Session* session, const std::string& topic, const std::string& client_id) {
    // Get last ACK'd sequence for this client
    uint64_t last_ack = getLastAck(client_id);

    if (persistence_) {
        // Cap at MAX_STORED_MESSAGES: requesting beyond the compaction window only
        // wastes LMDB cursor time on records that were already deleted.
        auto messages = persistence_->load_range(last_ack + 1, last_ack + MAX_STORED_MESSAGES);
        for (const auto& [seq, msg_topic, msg_payload] : messages) {
            if (msg_topic == topic && !isAcked(client_id, seq)) {
                deliverMessage(session, msg_topic, msg_payload, seq);
            }
        }
    }
}

} // namespace