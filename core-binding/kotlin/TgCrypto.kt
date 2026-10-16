package org.telegram.messenger.crypto

// Hand-mirrored Kotlin binding for the UniFFI-generated `tg-core` CryptoEngine.
// Authoritative version is (re)generated in CI by:
//   uniffi-bindgen generate core/src/lib.rs --language kotlin --out-dir core-binding/kotlin
// Kept here so the sources stay browsable and the project compiles offline in IDEs.

data class IgeResult(val data: ByteArray, val iv: ByteArray)

data class MtprotoKeys(val aesKey: ByteArray, val iv: ByteArray)

class CryptoEngine private constructor() {

    external fun aesIgeEncrypt(key: ByteArray, data: ByteArray, iv: ByteArray): IgeResult

    external fun aesIgeDecrypt(key: ByteArray, data: ByteArray, iv: ByteArray): IgeResult

    external fun sha256(data: ByteArray): ByteArray

    external fun deriveMtprotoKeys(authKey: ByteArray, msgKey: ByteArray): MtprotoKeys

    companion object {
        init {
            System.loadLibrary("tgcore")
        }

        @JvmStatic
        fun create(): CryptoEngine = CryptoEngine()
    }
}
