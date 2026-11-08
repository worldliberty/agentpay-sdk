//! The merchant's `text/event-stream` answer as it passes through the paying
//! proxy: OpenAI chat-completion chunks (`data:` events) mixed with MPP
//! payment events (`payment-need-voucher`, which the proxy answers, and
//! `payment-receipt`, which says what the merchant has charged so far).

use base64::Engine;
use serde_json::Value;

/// One server-sent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// `event:` name; `message` when absent.
    pub name: String,
    /// `data:` lines joined with `\n`.
    pub data: String,
}

/// Splits a byte stream into events; chunks may end anywhere, even inside a
/// UTF-8 character.
#[derive(Default)]
pub struct EventParser {
    buffer: Vec<u8>,
}

impl EventParser {
    /// Adds `chunk` and returns the events it completes.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Event> {
        self.buffer
            .extend(chunk.iter().copied().filter(|byte| *byte != b'\r'));
        let mut events = Vec::new();
        while let Some(end) = self.buffer.windows(2).position(|pair| pair == b"\n\n") {
            let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
            if let Some(event) = parse_block(&String::from_utf8_lossy(&block)) {
                events.push(event);
            }
        }
        events
    }
}

fn parse_block(block: &str) -> Option<Event> {
    let mut name = None;
    let mut data: Vec<&str> = Vec::new();
    for line in block.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            name = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    (name.is_some() || !data.is_empty()).then(|| Event {
        name: name.unwrap_or_else(|| "message".into()),
        data: data.join("\n"),
    })
}

/// The text a chat-completion chunk adds, if any (`[DONE]` and usage-only
/// chunks add none).
pub fn delta_text(data: &str) -> Option<String> {
    let chunk: Value = serde_json::from_str(data).ok()?;
    let text = chunk["choices"][0]["delta"]["content"].as_str()?;
    (!text.is_empty()).then(|| text.to_string())
}

/// What a merchant receipt says about the session channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub channel_id: String,
    /// Total the merchant has charged on this channel (base units): `spent`,
    /// else `acceptedCumulative`.
    pub spent: u128,
}

impl Receipt {
    /// A receipt from JSON (a `payment-receipt` event's data).
    pub fn from_json(value: &Value) -> Option<Self> {
        let amount = |key: &str| value[key].as_str().and_then(|text| text.parse().ok());
        Some(Self {
            channel_id: value["channelId"]
                .as_str()
                .or_else(|| value["reference"].as_str())?
                .to_ascii_lowercase(),
            spent: amount("spent").or_else(|| amount("acceptedCumulative"))?,
        })
    }

    /// A receipt from the `Payment-Receipt` header (base64url JSON).
    pub fn from_header(header: &str) -> Option<Self> {
        let raw = header.trim().trim_end_matches('=');
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .ok()?;
        Self::from_json(&serde_json::from_slice(&json).ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_split_anywhere_and_payment_events_are_named() {
        let stream = "data: {\"choices\":[{\"delta\":{\"content\":\"Hé\"}}]}\r\n\r\n\
                      event: payment-need-voucher\ndata: {\"requiredCumulative\":\"1232\"}\n\n\
                      : keep-alive\n\ndata: [DONE]\n\n";
        let bytes = stream.as_bytes();
        let mut parser = EventParser::default();
        let mut events = Vec::new();
        // One byte at a time, splitting the two-byte `é` too.
        for byte in bytes {
            events.extend(parser.push(std::slice::from_ref(byte)));
        }
        let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
        assert_eq!(names, ["message", "payment-need-voucher", "message"]);
        assert_eq!(delta_text(&events[0].data).as_deref(), Some("Hé"));
        assert_eq!(delta_text(&events[2].data), None);
    }

    #[test]
    fn receipts_come_from_events_and_headers() {
        let json = serde_json::json!({
            "method": "tempo", "intent": "session", "status": "success",
            "channelId": "0xABC", "acceptedCumulative": "1232", "spent": "1200"
        });
        let receipt = Receipt::from_json(&json).expect("receipt");
        assert_eq!(receipt.channel_id, "0xabc");
        assert_eq!(receipt.spent, 1200);
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());
        assert_eq!(Receipt::from_header(&header), Some(receipt));
        let accepted_only = serde_json::json!({"channelId": "0x1", "acceptedCumulative": "616"});
        assert_eq!(
            Receipt::from_json(&accepted_only).map(|r| r.spent),
            Some(616)
        );
        assert_eq!(Receipt::from_header("not base64!"), None);
    }
}
