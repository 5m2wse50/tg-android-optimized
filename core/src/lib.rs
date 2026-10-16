mod mtproto_crypto;
pub mod net;
pub mod ring;
pub mod voip;

use mtproto_crypto::{aes_ige_decrypt, aes_ige_encrypt, derive_mtproto_keys, sha256};

/// UniFFI-exposed key bundle.
#[derive(uniffi::Record)]
pub struct MtprotoKeys {
    pub aes_key: Vec<u8>,
    pub iv: Vec<u8>,
}

/// UniFFI-exposed result of an IGE pass (encrypted/decrypted buffer + chained IV).
#[derive(uniffi::Record)]
pub struct IgeResult {
    pub data: Vec<u8>,
    pub iv: Vec<u8>,
}

/// Stateful crypto entry point exposed to Kotlin via UniFFI.
#[derive(uniffi::Object)]
pub struct CryptoEngine {}

#[uniffi::export]
impl CryptoEngine {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {}
    }

    pub fn aes_ige_encrypt(&self, key: Vec<u8>, data: Vec<u8>, iv: Vec<u8>) -> IgeResult {
        let mut data = data;
        let mut iv = iv;
        aes_ige_encrypt(&key, &mut data, &mut iv);
        IgeResult { data, iv }
    }

    pub fn aes_ige_decrypt(&self, key: Vec<u8>, data: Vec<u8>, iv: Vec<u8>) -> IgeResult {
        let mut data = data;
        let mut iv = iv;
        aes_ige_decrypt(&key, &mut data, &mut iv);
        IgeResult { data, iv }
    }

    pub fn sha256(&self, data: Vec<u8>) -> Vec<u8> {
        sha256(&data).to_vec()
    }

    pub fn derive_mtproto_keys(&self, auth_key: Vec<u8>, msg_key: Vec<u8>) -> MtprotoKeys {
        let k = derive_mtproto_keys(&auth_key, &msg_key);
        MtprotoKeys {
            aes_key: k.aes_key.to_vec(),
            iv: k.iv.to_vec(),
        }
    }
}

uniffi::setup_scaffolding!();
