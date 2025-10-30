use indexmap::IndexSet;
use siphasher::sip::SipHasher;
use std::hash::Hasher;

/// Maximum number of message hashes to track
const MAX_SEEN_MESSAGES: usize = 40_000;

/// Tracks message hashes to detect duplicates using a fixed-size FIFO buffer
pub struct MessageTracker {
    seen_hashes: IndexSet<u64>,
}

impl MessageTracker {
    /// Creates a new MessageTracker with pre-allocated capacity
    pub fn new() -> Self {
        Self {
            seen_hashes: IndexSet::with_capacity(MAX_SEEN_MESSAGES),
        }
    }

    /// Checks if a message is a duplicate and adds it to the tracker if not
    /// Returns true if the message was already seen
    pub fn is_duplicate(&mut self, message_hash: u64) -> bool {
        // O(1) lookup for existing hash
        if self.seen_hashes.contains(&message_hash) {
            return true;
        }

        // Insert new hash
        self.seen_hashes.insert(message_hash);

        // Maintain fixed capacity by removing oldest (first inserted) hash
        if self.seen_hashes.len() > MAX_SEEN_MESSAGES {
            self.seen_hashes.shift_remove_index(0);
        }

        false
    }

    /// Returns the number of currently tracked message hashes
    #[allow(dead_code)]
    pub fn tracked_count(&self) -> usize {
        self.seen_hashes.len()
    }

    /// Clears all tracked message hashes
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.seen_hashes.clear();
    }
}

/// Hashes a binary message using AHash for fast, high-quality hashing
pub fn hash_binary_message(data: &[u8]) -> u64 {
    let mut hasher = SipHasher::new();
    hasher.write(data);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_detection() {
        let mut tracker = MessageTracker::new();
        let msg1 = hash_binary_message(b"test1");
        let msg2 = hash_binary_message(b"test2");

        // First occurrence is not a duplicate
        assert!(!tracker.is_duplicate(msg1));
        // Second occurrence is a duplicate
        assert!(tracker.is_duplicate(msg1));
        // Different message is not a duplicate
        assert!(!tracker.is_duplicate(msg2));
        // Second message becomes duplicate
        assert!(tracker.is_duplicate(msg2));
    }

    #[test]
    fn test_capacity_limit() {
        let mut tracker = MessageTracker::new();

        // Fill beyond capacity
        for i in 0..MAX_SEEN_MESSAGES + 10 {
            tracker.is_duplicate(i as u64);
        }

        // Verify size is maintained
        assert_eq!(tracker.tracked_count(), MAX_SEEN_MESSAGES);

        // Verify oldest messages were removed (FIFO)
        assert!(!tracker.is_duplicate((MAX_SEEN_MESSAGES + 10) as u64));
        assert!(!tracker.seen_hashes.contains(&0));
        assert!(!tracker.seen_hashes.contains(&1));
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"test message";
        let hash1 = hash_binary_message(data);
        let hash2 = hash_binary_message(data);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Different input should produce different hash
        let hash3 = hash_binary_message(b"different message");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_clear() {
        let mut tracker = MessageTracker::new();
        let msg = hash_binary_message(b"test");

        assert!(!tracker.is_duplicate(msg));
        assert!(tracker.is_duplicate(msg));

        tracker.clear();
        assert_eq!(tracker.tracked_count(), 0);
        assert!(!tracker.is_duplicate(msg));
    }
}
