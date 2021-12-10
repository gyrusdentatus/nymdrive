use crate::socks::SocksRequest;
use serde::{Deserialize, Serialize};

/// Identifier of a connection, should be large enough chosen randomly since it's used as a crude
/// authentication mechanism. An attacker that can guess a connection id can potentially inject data
/// into the stream.
pub type ConnectionId = [u8; 32];

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Packet {
    pub stream: ConnectionId,
    /// The last received packet (idx 0 is never used and sent in the beginning). We use any packet
    /// to send ACKs to not waste dedicated packets on it.
    pub ack: usize,
    pub payload: Payload,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Payload {
    /// Sent by the client to establish a connection with the exit node and make it forward all
    /// traffic to a specified `target`
    Establish(SocksRequest),
    /// Sent by client or server to stream data to the other side
    Data {
        /// packet counter, begins at 1
        idx: usize,
        data: Vec<u8>,
    },
    /// Sent by the client to give the Server more SURBs to stream data the other way. Sent by the
    /// server if it received more SURBs than needed right now. This behavior is intended to make it
    /// unobservable if the client is receiving traffic.
    SURB,
}

impl Packet {
    pub fn get_idx(&self) -> Option<usize> {
        match self.payload {
            Payload::Establish { .. } => Some(0),
            Payload::Data { idx, .. } => Some(idx),
            Payload::SURB => None,
        }
    }
}
