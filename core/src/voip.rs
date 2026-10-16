//! Low-latency VoIP controller for Telegram (Stage A+B).
//!
//! - 20 ms Opus frames flow through the wait-free `SpScRing<AudioFrame>`.
//! - Call signaling is encoded with the existing MTProto 2.0 transport/crypto.
//! - UniFFI exposes a non-blocking controller to Kotlin/Android.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::net;
use crate::ring::SpScRing;

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum VoipState {
    Idle,
    Ringing,
    Active,
    Ended,
}

#[derive(uniffi::Record, Clone, Default)]
pub struct AudioFrame {
    pub pts_ms: u64,
    pub data: Vec<u8>,
}

impl From<u8> for VoipState {
    fn from(v: u8) -> Self {
        match v {
            1 => VoipState::Ringing,
            2 => VoipState::Active,
            3 => VoipState::Ended,
            _ => VoipState::Idle,
        }
    }
}

impl From<VoipState> for u8 {
    fn from(s: VoipState) -> Self {
        match s {
            VoipState::Idle => 0,
            VoipState::Ringing => 1,
            VoipState::Active => 2,
            VoipState::Ended => 3,
        }
    }
}

#[derive(uniffi::Object)]
pub struct VoipController {
    outbound: SpScRing<AudioFrame>,
    inbound: SpScRing<AudioFrame>,
    state: AtomicU8,
}

#[uniffi::export]
impl VoipController {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            outbound: SpScRing::new(),
            inbound: SpScRing::new(),
            state: AtomicU8::new(0),
        }
    }

    pub fn state(&self) -> VoipState {
        VoipState::from(self.state.load(Ordering::Acquire))
    }

    pub fn set_state(&self, s: VoipState) {
        self.state.store(u8::from(s), Ordering::Release);
    }

    /// Non-blocking enqueue of a captured 20 ms frame.
    pub fn capture_frame(&self, frame: AudioFrame) -> bool {
        self.outbound.push(frame)
    }

    /// Non-blocking dequeue of the next playout frame.
    pub fn playout_frame(&self) -> Option<AudioFrame> {
        self.inbound.try_pop()
    }

    /// Deliver a remotely received 20 ms frame to the playout queue.
    pub fn deliver_frame(&self, frame: AudioFrame) -> bool {
        self.inbound.push(frame)
    }

    /// Dequeue the next outbound (encoded) frame for transmission.
    pub fn take_outbound(&self) -> Option<AudioFrame> {
        self.outbound.try_pop()
    }

    /// Build an MTProto 2.0 signaling frame (call initiate/accept/hangup payload).
    pub fn signaling_frame(
        &self,
        auth_key_id: u64,
        auth_key: Vec<u8>,
        msg_key: Vec<u8>,
        salt: u64,
        session_id: u64,
        msg_id: i64,
        seq_no: i32,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        let msg_key_fixed: [u8; 16] = msg_key.as_slice().try_into()
            .unwrap_or([0u8; 16]);
        let frame = net::encode_mtproto_frame(
            auth_key_id,
            &auth_key,
            &msg_key_fixed,
            salt,
            session_id,
            msg_id,
            seq_no,
            &payload,
        );
        frame.to_vec()
    }
}
EOF
echo created