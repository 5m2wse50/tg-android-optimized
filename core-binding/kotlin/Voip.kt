package org.telegram.messenger.voip

import org.telegram.messenger.crypto.MtprotoKeys

// Hand-mirrored Kotlin binding for UniFFI `VoipController` + `AudioFrame`.
// Authoritative version is (re)generated in CI by uniffi-bindgen.

data class AudioFrame(val ptsMs: Long, val data: ByteArray)

enum class VoipState { Idle, Ringing, Active, Ended }

class VoipController private constructor() {
    external fun state(): VoipState
    external fun setState(state: VoipState)
    external fun captureFrame(frame: AudioFrame): Boolean
    external fun playoutFrame(): AudioFrame?
    external fun deliverFrame(frame: AudioFrame): Boolean
    external fun takeOutbound(): AudioFrame?
    external fun signalingFrame(
        authKeyId: Long,
        authKey: ByteArray,
        msgKey: ByteArray,
        salt: Long,
        sessionId: Long,
        msgId: Long,
        seqNo: Int,
        payload: ByteArray
    ): ByteArray

    companion object {
        init { System.loadLibrary("tgcore") }
        @JvmStatic
        fun create(): VoipController = VoipController()
    }
}
