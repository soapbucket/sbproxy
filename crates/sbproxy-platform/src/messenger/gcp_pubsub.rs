//! GCP Pub/Sub messenger backend.
//!
//! Publishes messages with the `projects.topics.publish` REST endpoint and
//! subscribes with `projects.subscriptions.pull` (blocking-style long poll).
//!
//! Authentication uses a static bearer token (`access_token`).  For production
//! use, replace the static token with a GCP service-account token source.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use super::{Message, Messenger};

// --- Config ---

/// Configuration for [`GcpPubSubMessenger`].
pub struct GcpPubSubConfig {
    /// GCP project ID, e.g. `"my-project"`.
    pub project: String,
    /// Pub/Sub topic name, e.g. `"my-topic"`.
    pub topic: String,
    /// Pub/Sub subscription name, e.g. `"my-sub"`.
    pub subscription: String,
    /// OAuth2 bearer access token for the GCP API.
    pub access_token: String,
}

// --- GcpPubSubMessenger ---

/// GCP Pub/Sub-backed messenger.
///
/// Uses `ureq` for blocking HTTP calls to the Pub/Sub REST API.
pub struct GcpPubSubMessenger {
    config: GcpPubSubConfig,
    client: ureq::Agent,
}

impl GcpPubSubMessenger {
    /// Create a new GCP Pub/Sub messenger.
    pub fn new(config: GcpPubSubConfig) -> Self {
        Self {
            config,
            client: ureq::Agent::new(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.access_token)
    }

    fn publish_url(&self) -> String {
        format!(
            "https://pubsub.googleapis.com/v1/projects/{}/topics/{}:publish",
            self.config.project, self.config.topic
        )
    }

    fn pull_url(&self) -> String {
        format!(
            "https://pubsub.googleapis.com/v1/projects/{}/subscriptions/{}:pull",
            self.config.project, self.config.subscription
        )
    }

    fn ack_url(&self) -> String {
        format!(
            "https://pubsub.googleapis.com/v1/projects/{}/subscriptions/{}:acknowledge",
            self.config.project, self.config.subscription
        )
    }

    /// Acknowledge a message so it is not re-delivered.
    fn ack(&self, ack_id: &str) -> Result<()> {
        let body = serde_json::json!({ "ackIds": [ack_id] });
        self.client
            .post(&self.ack_url())
            .set("Authorization", &self.auth_header())
            .send_json(body)
            .context("Pub/Sub acknowledge")?;
        Ok(())
    }

    /// Pull one message from the subscription.
    fn pull_one(&self) -> Result<Option<(Message, String)>> {
        let body = serde_json::json!({ "maxMessages": 1 });
        let resp = self
            .client
            .post(&self.pull_url())
            .set("Authorization", &self.auth_header())
            .send_json(body)
            .context("Pub/Sub pull")?;

        let json: serde_json::Value = resp.into_json().context("parse Pub/Sub pull response")?;
        parse_pull_response(json)
    }
}

/// Parse the Pub/Sub `pull` response.
///
/// Expected shape:
/// ```json
/// {
///   "receivedMessages": [{
///     "ackId": "...",
///     "message": {
///       "data": "<base64>",
///       "messageId": "..."
///     }
///   }]
/// }
/// ```
fn parse_pull_response(body: serde_json::Value) -> Result<Option<(Message, String)>> {
    let messages = match body.get("receivedMessages").and_then(|m| m.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => return Ok(None),
    };

    let received = &messages[0];

    let ack_id = received
        .get("ackId")
        .and_then(|a| a.as_str())
        .ok_or_else(|| anyhow!("missing ackId"))?
        .to_string();

    let data_b64 = received
        .get("message")
        .and_then(|m| m.get("data"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow!("missing message.data"))?;

    let data_bytes = B64.decode(data_b64).context("base64 decode Pub/Sub data")?;
    let message: Message = serde_json::from_slice(&data_bytes).context("deserialize Message")?;

    Ok(Some((message, ack_id)))
}

impl Messenger for GcpPubSubMessenger {
    /// Publish by posting a base64-encoded JSON message to the topic.
    fn publish(&self, msg: &Message) -> Result<()> {
        let json_bytes = serde_json::to_vec(msg).context("serialize message")?;
        let encoded = B64.encode(&json_bytes);

        let body = serde_json::json!({
            "messages": [{ "data": encoded }]
        });

        self.client
            .post(&self.publish_url())
            .set("Authorization", &self.auth_header())
            .send_json(body)
            .context("Pub/Sub publish")?;
        Ok(())
    }

    /// Subscribe by repeatedly pulling from the subscription.
    ///
    /// Each received message is acknowledged before being yielded to the caller.
    fn subscribe(&self, _topic: &str) -> Result<Box<dyn Iterator<Item = Message> + Send>> {
        let project = self.config.project.clone();
        let topic = self.config.topic.clone();
        let subscription = self.config.subscription.clone();
        let access_token = self.config.access_token.clone();
        Ok(Box::new(PubSubIterator::new(
            project,
            topic,
            subscription,
            access_token,
        )))
    }
}

// --- Iterator ---

struct PubSubIterator {
    messenger: GcpPubSubMessenger,
}

impl PubSubIterator {
    fn new(project: String, topic: String, subscription: String, access_token: String) -> Self {
        Self {
            messenger: GcpPubSubMessenger::new(GcpPubSubConfig {
                project,
                topic,
                subscription,
                access_token,
            }),
        }
    }
}

impl Iterator for PubSubIterator {
    type Item = Message;

    fn next(&mut self) -> Option<Message> {
        loop {
            match self.messenger.pull_one() {
                Ok(Some((msg, ack_id))) => {
                    // Best-effort ack; ignore errors.
                    let _ = self.messenger.ack(&ack_id);
                    return Some(msg);
                }
                Ok(None) => {
                    // No messages; back off briefly before retrying.
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    continue;
                }
                Err(_) => return None,
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
        let cfg = GcpPubSubConfig {
            project: "my-project".into(),
            topic: "my-topic".into(),
            subscription: "my-sub".into(),
            access_token: "ya29.token".into(),
        };
        assert_eq!(cfg.project, "my-project");
        assert_eq!(cfg.subscription, "my-sub");
    }

    #[test]
    fn url_generation() {
        let m = GcpPubSubMessenger::new(GcpPubSubConfig {
            project: "proj".into(),
            topic: "top".into(),
            subscription: "sub".into(),
            access_token: "tok".into(),
        });
        assert!(m.publish_url().contains("/topics/top:publish"));
        assert!(m.pull_url().contains("/subscriptions/sub:pull"));
        assert!(m.ack_url().contains("/subscriptions/sub:acknowledge"));
    }

    #[test]
    fn parse_valid_pull_response() {
        let msg = make_msg("events", json!({"action": "created"}));
        let json_bytes = serde_json::to_vec(&msg).unwrap();
        let encoded = B64.encode(&json_bytes);

        let response = json!({
            "receivedMessages": [{
                "ackId": "ack-handle-xyz",
                "message": {
                    "data": encoded,
                    "messageId": "12345"
                }
            }]
        });

        let result = parse_pull_response(response).unwrap();
        assert!(result.is_some());
        let (parsed, ack_id) = result.unwrap();
        assert_eq!(parsed.topic, "events");
        assert_eq!(parsed.payload["action"], "created");
        assert_eq!(ack_id, "ack-handle-xyz");
    }

    #[test]
    fn parse_empty_pull_response() {
        let response = json!({ "receivedMessages": [] });
        let result = parse_pull_response(response).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_missing_messages_field() {
        let response = json!({});
        let result = parse_pull_response(response).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_invalid_base64_returns_error() {
        let response = json!({
            "receivedMessages": [{
                "ackId": "ack",
                "message": { "data": "!!!not-valid-b64!!!" }
            }]
        });
        let result = parse_pull_response(response);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "requires a live GCP Pub/Sub endpoint"]
    fn live_publish_subscribe() {
        let messenger = GcpPubSubMessenger::new(GcpPubSubConfig {
            project: "my-project".into(),
            topic: "my-topic".into(),
            subscription: "my-sub".into(),
            access_token: "ya29.token".into(),
        });
        messenger
            .publish(&make_msg("events", json!({"action": "created"})))
            .unwrap();
        let mut sub = messenger.subscribe("events").unwrap();
        let msg = sub.next().unwrap();
        assert_eq!(msg.payload["action"], "created");
    }
}
