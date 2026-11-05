#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>

namespace dpi {

// A fixed-capacity, multi-producer / multi-consumer queue.
// push() waits while the queue is full, which keeps memory bounded when the
// reader is faster than the workers. close() wakes everyone up: pop() then
// drains what is left and returns false once the queue is empty.
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : capacity_(capacity) {}

    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;

    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        notFull_.wait(lock, [this] { return items_.size() < capacity_ || closed_; });
        if (closed_) return false;
        items_.push_back(std::move(item));
        notEmpty_.notify_one();
        return true;
    }

    bool pop(T& out) {
        std::unique_lock<std::mutex> lock(mutex_);
        notEmpty_.wait(lock, [this] { return !items_.empty() || closed_; });
        if (items_.empty()) return false;
        out = std::move(items_.front());
        items_.pop_front();
        notFull_.notify_one();
        return true;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable notEmpty_;
    std::condition_variable notFull_;
    std::deque<T> items_;
    size_t capacity_;
    bool closed_ = false;
};

}  // namespace dpi
