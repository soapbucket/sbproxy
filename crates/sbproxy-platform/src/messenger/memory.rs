//! Bounded in-memory messenger using std::sync::mpsc channels.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Mutex;

use anyhow::Result;

use super::{Message, Messenger};

/// In-memory messenger backed by bounded mpsc channels.
///
/// Each subscription creates a bounded channel. If a subscriber falls behind and
/// the channel fills up, publishes to that subscriber are silently dropped to
/// prevent back-pressure from blocking producers.
pub struct MemoryMessenger {
    channels: Mutex<HashMap<String, Vec<SyncSender<Message>>>>,
    max_pending: usize,
}

impl MemoryMessenger {
    /// Create a new in-memory messenger.
    ///
    /// - `max_pending`: maximum number of buffered messages per subscriber channel.
    pub fn new(max_pending: usize) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            max_pending,
        }
    }
}

impl Messenger for MemoryMessenger {
    fn publish(&self, msg: &Message) -> Result<()> {
        let mut channels = self.channels.lock().unwrap();
        if let Some(senders) = channels.get_mut(&msg.topic) {
            // Remove disconnected senders and send to the rest.
            senders.retain(|sender| {
                // try_send: non-blocking. If the channel is full or disconnected, drop the message.
                sender.try_send(msg.clone()).is_ok()
            });
        }
        Ok(())
    }

    fn subscribe(&self, topic: &str) -> Result<Box<dyn Iterator<Item = Message> + Send>> {
        let (tx, rx) = mpsc::sync_channel::<Message>(self.max_pending);
        let mut channels = self.channels.lock().unwrap();
        channels.entry(topic.to_string()).or_default().push(tx);
        Ok(Box::new(ChannelIterator { rx }))
    }
}

/// Iterator adapter over a mpsc::Receiver. Blocks on `next()` until a message
/// arrives or the channel is closed.
struct ChannelIterator {
    rx: Receiver<Message>,
}

impl Iterator for ChannelIterator {
    type Item = Message;

    fn next(&mut self) -> Option<Message> {
        self.rx.recv().ok()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::thread;

    fn make_msg(topic: &str, payload: serde_json::Value) -> Message {
        Message {
            topic: topic.to_string(),
            payload,
            timestamp: 1000,
        }
    }

    #[test]
    fn publish_and_subscribe() {
        let messenger = MemoryMessenger::new(10);
        let sub = messenger.subscribe("events").unwrap();

        messenger
            .publish(&make_msg("events", json!({"action": "created"})))
            .unwrap();

        // Drop the messenger so the channel closes and the iterator terminates.
        drop(messenger);

        let messages: Vec<_> = sub.collect();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload["action"], "created");
    }

    #[test]
    fn multiple_subscribers() {
        let messenger = MemoryMessenger::new(10);
        let sub1 = messenger.subscribe("events").unwrap();
        let sub2 = messenger.subscribe("events").unwrap();

        messenger
            .publish(&make_msg("events", json!("hello")))
            .unwrap();
        drop(messenger);

        let msgs1: Vec<_> = sub1.collect();
        let msgs2: Vec<_> = sub2.collect();
        assert_eq!(msgs1.len(), 1);
        assert_eq!(msgs2.len(), 1);
    }

    #[test]
    fn topic_filtering() {
        let messenger = MemoryMessenger::new(10);
        let sub_a = messenger.subscribe("topic_a").unwrap();
        let sub_b = messenger.subscribe("topic_b").unwrap();

        messenger
            .publish(&make_msg("topic_a", json!("for_a")))
            .unwrap();
        messenger
            .publish(&make_msg("topic_b", json!("for_b")))
            .unwrap();
        drop(messenger);

        let msgs_a: Vec<_> = sub_a.collect();
        let msgs_b: Vec<_> = sub_b.collect();
        assert_eq!(msgs_a.len(), 1);
        assert_eq!(msgs_a[0].payload, json!("for_a"));
        assert_eq!(msgs_b.len(), 1);
        assert_eq!(msgs_b[0].payload, json!("for_b"));
    }

    #[test]
    fn drops_messages_when_channel_full() {
        let messenger = MemoryMessenger::new(1);
        let sub = messenger.subscribe("events").unwrap();

        // Publish 3 messages into a channel with capacity 1.
        messenger.publish(&make_msg("events", json!(1))).unwrap();
        messenger.publish(&make_msg("events", json!(2))).unwrap();
        messenger.publish(&make_msg("events", json!(3))).unwrap();
        drop(messenger);

        let messages: Vec<_> = sub.collect();
        // Only the first message fits in the buffer; the rest are dropped.
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, json!(1));
    }

    #[test]
    fn publish_to_nonexistent_topic_is_ok() {
        let messenger = MemoryMessenger::new(10);
        let result = messenger.publish(&make_msg("nobody_listening", json!(null)));
        assert!(result.is_ok());
    }

    #[test]
    fn threaded_publish_subscribe() {
        let messenger = std::sync::Arc::new(MemoryMessenger::new(100));
        let sub = messenger.subscribe("work").unwrap();

        let m = messenger.clone();
        let producer = thread::spawn(move || {
            for i in 0..5 {
                m.publish(&make_msg("work", json!(i))).unwrap();
            }
            // Small delay then drop the Arc to eventually close the channel.
            drop(m);
        });

        // Wait for producer to finish.
        producer.join().unwrap();
        // Drop the original Arc so the channel closes.
        drop(messenger);

        let messages: Vec<_> = sub.collect();
        assert_eq!(messages.len(), 5);
    }
}
