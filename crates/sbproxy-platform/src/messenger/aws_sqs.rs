//! AWS SQS messenger backend.
//!
//! Publishes messages with `SendMessage` and subscribes with `ReceiveMessage`
//! (long-polling, `WaitTimeSeconds=20`).  Authentication uses a bearer token
//! passed in the `Authorization` header (i.e. a pre-signed URL or API gateway
//! token).  For full SQS API-key signing, replace `api_key` with real AWS
//! Signature V4 signing.
//!
//! # SQS semantics vs. pub/sub
//! SQS is a queue, not a fan-out bus.  Each received message is deleted after
//! `subscribe` returns it.  Multiple subscribers on the same queue compete for
//! messages (work-queue pattern).

use anyhow::{anyhow, Context, Result};

use super::{Message, Messenger};

// --- Config ---

/// Configuration for [`SqsMessenger`].
pub struct SqsConfig {
    /// Fully-qualified SQS queue URL, e.g.
    /// `https://sqs.us-east-1.amazonaws.com/123456789012/my-queue`.
    pub queue_url: String,
    /// AWS region, e.g. `"us-east-1"`.
    pub region: String,
    /// Bearer token / API key sent in the `Authorization` header.
    pub api_key: String,
}

// --- SqsMessenger ---

/// AWS SQS-backed messenger.
///
/// Uses `ureq` for blocking HTTP calls to the SQS HTTP query API.
pub struct SqsMessenger {
    config: SqsConfig,
    client: ureq::Agent,
}

impl SqsMessenger {
    /// Create a new SQS messenger.
    pub fn new(config: SqsConfig) -> Self {
        Self {
            config,
            client: ureq::Agent::new(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.api_key)
    }

    /// Delete a received message by its receipt handle so it is not re-delivered.
    fn delete_message(&self, receipt_handle: &str) -> Result<()> {
        self.client
            .post(&self.config.queue_url)
            .set("Authorization", &self.auth_header())
            .send_form(&[
                ("Action", "DeleteMessage"),
                ("ReceiptHandle", receipt_handle),
                ("Version", "2012-11-05"),
            ])
            .context("SQS DeleteMessage")?;
        Ok(())
    }

    /// Poll for one message with a 20-second long-poll.
    fn receive_one(&self) -> Result<Option<(Message, String)>> {
        let resp = self
            .client
            .post(&self.config.queue_url)
            .set("Authorization", &self.auth_header())
            .set("Accept", "application/json")
            .send_form(&[
                ("Action", "ReceiveMessage"),
                ("WaitTimeSeconds", "20"),
                ("MaxNumberOfMessages", "1"),
                ("Version", "2012-11-05"),
            ])
            .context("SQS ReceiveMessage")?;

        let body: serde_json::Value = resp.into_json().context("parse SQS response")?;
        parse_receive_response(body)
    }
}

/// Parse the SQS `ReceiveMessage` JSON response.
///
/// Expected shape (simplified SQS JSON response):
/// ```json
/// {
///   "ReceiveMessageResponse": {
///     "ReceiveMessageResult": {
///       "Message": { "Body": "...", "ReceiptHandle": "..." }
///     }
///   }
/// }
/// ```
fn parse_receive_response(body: serde_json::Value) -> Result<Option<(Message, String)>> {
    // Navigate the nested SQS response envelope.
    let result = body
        .get("ReceiveMessageResponse")
        .and_then(|r| r.get("ReceiveMessageResult"));

    let msg_val = match result.and_then(|r| r.get("Message")) {
        Some(m) => m,
        None => return Ok(None), // Queue is empty.
    };

    let body_str = msg_val
        .get("Body")
        .and_then(|b| b.as_str())
        .ok_or_else(|| anyhow!("missing Body in SQS message"))?;

    let receipt = msg_val
        .get("ReceiptHandle")
        .and_then(|r| r.as_str())
        .ok_or_else(|| anyhow!("missing ReceiptHandle in SQS message"))?
        .to_string();

    let message: Message =
        serde_json::from_str(body_str).context("deserialize Message from SQS body")?;
    Ok(Some((message, receipt)))
}

impl Messenger for SqsMessenger {
    /// Send a message to the SQS queue.
    ///
    /// Command: `POST {queue_url}` with `Action=SendMessage&MessageBody={json}`
    fn publish(&self, msg: &Message) -> Result<()> {
        let body = serde_json::to_string(msg).context("serialize message")?;
        self.client
            .post(&self.config.queue_url)
            .set("Authorization", &self.auth_header())
            .send_form(&[
                ("Action", "SendMessage"),
                ("MessageBody", &body),
                ("Version", "2012-11-05"),
            ])
            .context("SQS SendMessage")?;
        Ok(())
    }

    /// Subscribe by long-polling the SQS queue.
    ///
    /// The returned iterator blocks up to 20 seconds per `next()` call.
    /// Each message is deleted from the queue after being returned.
    fn subscribe(&self, _topic: &str) -> Result<Box<dyn Iterator<Item = Message> + Send>> {
        // Clone everything needed for the iterator.
        let queue_url = self.config.queue_url.clone();
        let region = self.config.region.clone();
        let api_key = self.config.api_key.clone();
        Ok(Box::new(SqsIterator::new(queue_url, region, api_key)))
    }
}

// --- Iterator ---

struct SqsIterator {
    messenger: SqsMessenger,
}

impl SqsIterator {
    fn new(queue_url: String, region: String, api_key: String) -> Self {
        Self {
            messenger: SqsMessenger::new(SqsConfig {
                queue_url,
                region,
                api_key,
            }),
        }
    }
}

impl Iterator for SqsIterator {
    type Item = Message;

    fn next(&mut self) -> Option<Message> {
        loop {
            match self.messenger.receive_one() {
                Ok(Some((msg, receipt))) => {
                    // Best-effort delete; ignore errors.
                    let _ = self.messenger.delete_message(&receipt);
                    return Some(msg);
                }
                Ok(None) => continue,  // empty poll, retry
                Err(_) => return None, // connection error, stop iteration
            }
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_msg(topic: &str, payload: serde_json::Value) -> Message {
        Message {
            topic: topic.to_string(),
            payload,
            timestamp: 1000,
        }
    }

    #[test]
    fn config_fields() {
        let cfg = SqsConfig {
            queue_url: "https://sqs.us-east-1.amazonaws.com/123/my-queue".into(),
            region: "us-east-1".into(),
            api_key: "token123".into(),
        };
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.api_key, "token123");
    }

    #[test]
    fn parse_valid_receive_response() {
        let msg = make_msg("test.topic", json!({"key": "value"}));
        let body_str = serde_json::to_string(&msg).unwrap();

        let response = json!({
            "ReceiveMessageResponse": {
                "ReceiveMessageResult": {
                    "Message": {
                        "Body": body_str,
                        "ReceiptHandle": "handle-abc-123"
                    }
                }
            }
        });

        let result = parse_receive_response(response).unwrap();
        assert!(result.is_some());
        let (parsed_msg, receipt) = result.unwrap();
        assert_eq!(parsed_msg.topic, "test.topic");
        assert_eq!(parsed_msg.payload["key"], "value");
        assert_eq!(receipt, "handle-abc-123");
    }

    #[test]
    fn parse_empty_queue_response() {
        let response = json!({
            "ReceiveMessageResponse": {
                "ReceiveMessageResult": {}
            }
        });

        let result = parse_receive_response(response).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_invalid_body_returns_error() {
        let response = json!({
            "ReceiveMessageResponse": {
                "ReceiveMessageResult": {
                    "Message": {
                        "Body": "not-valid-json",
                        "ReceiptHandle": "handle"
                    }
                }
            }
        });

        let result = parse_receive_response(response);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "requires a live SQS endpoint"]
    fn live_publish_subscribe() {
        let messenger = SqsMessenger::new(SqsConfig {
            queue_url: "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue".into(),
            region: "us-east-1".into(),
            api_key: "test-token".into(),
        });
        messenger
            .publish(&make_msg("events", json!({"action": "created"})))
            .unwrap();
        let mut sub = messenger.subscribe("events").unwrap();
        let msg = sub.next().unwrap();
        assert_eq!(msg.payload["action"], "created");
    }
}
