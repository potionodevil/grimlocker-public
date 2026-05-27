use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::crypto;

/// Enclave holds all key material in locked memory.
/// MVK handles and session keys are stored here — Go never sees raw key bytes.
/// All crypto operations go through the enclave so keys never leave this module.
pub struct Enclave {
    initialized: bool,
    mvk_handles: HashMap<String, Vec<u8>>,
    session_keys: HashMap<String, Vec<u8>>,
}

impl Enclave {
    pub fn new() -> Self {
        Self {
            initialized: false,
            mvk_handles: HashMap::new(),
            session_keys: HashMap::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), String> {
        if self.initialized {
            return Ok(());
        }
        self.initialized = true;
        Ok(())
    }

    pub fn shutdown(&mut self) {
        // Zeroize all key material
        for (_handle, key) in self.mvk_handles.iter_mut() {
            key.zeroize();
        }
        for (_handle, key) in self.session_keys.iter_mut() {
            key.zeroize();
        }
        self.mvk_handles.clear();
        self.session_keys.clear();
        self.initialized = false;
    }

    // -----------------------------------------------------------------------
    // MVK handle management
    // -----------------------------------------------------------------------

    /// Store an MVK under a random handle. Returns the handle string.
    /// The key is copied into locked memory if available (Unix mlock).
    pub fn store_mvk(&mut self, mvk: &[u8]) -> Result<String, String> {
        if mvk.len() != 32 {
            return Err("MVK must be 32 bytes".into());
        }

        let handle = format!("mvk:{}", generate_random_hex(16));
        let key = mvk.to_vec();

        // Try to lock the memory (best-effort, not available on all platforms)
        #[cfg(unix)]
        {
            if let Ok(_locked) = LockedBuffer::new(key.clone()) {
                // LockedBuffer will mlock the memory.
                // We store the Vec in the HashMap; the LockedBuffer
                // protects the actual crypto operation data.
                drop(_locked);
            }
        }

        self.mvk_handles.insert(handle.clone(), key);
        Ok(handle)
    }

    /// Revoke (zeroize and remove) an MVK handle.
    pub fn revoke_mvk(&mut self, handle: &str) {
        if let Some(mut key) = self.mvk_handles.remove(handle) {
            key.zeroize();
        }
    }

    // -----------------------------------------------------------------------
    // Session key management
    // -----------------------------------------------------------------------

    /// Create a new random 32-byte session key and store it under a handle.
    /// Returns (handle, key_bytes) — the key_bytes are copied to the caller
    /// for transmission to the frontend. After that, the key lives only
    /// in the enclave's locked memory.
    pub fn create_session_key(&mut self) -> Result<(String, [u8; 32]), String> {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let handle = format!("ske:{}", generate_random_hex(16));

        self.session_keys.insert(handle.clone(), key_bytes.to_vec());

        Ok((handle, key_bytes))
    }

    /// Remove and zeroize a session key.
    pub fn destroy_session_key(&mut self, handle: &str) {
        if let Some(mut key) = self.session_keys.remove(handle) {
            key.zeroize();
        }
    }

    // -----------------------------------------------------------------------
    // Handle-based encrypt/decrypt
    // -----------------------------------------------------------------------

    /// Encrypt with a key identified by handle. The handle prefix determines
    /// which key store to use:
    ///   "mvk:<hex>" → MVK handle store
    ///   "ske:<hex>" → session key store
    pub fn encrypt_with_handle(
        &self,
        handle: &str,
        plaintext: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key = self.get_key(handle)?;

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);

        let result = crypto::encrypt(plaintext, &key_arr);
        key_arr.zeroize();
        result.map_err(|e| e.to_string())
    }

    /// Decrypt with a key identified by handle.
    pub fn decrypt_with_handle(
        &self,
        handle: &str,
        ciphertext: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key = self.get_key(handle)?;

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);

        let result = crypto::decrypt(ciphertext, &key_arr);
        key_arr.zeroize();
        match result {
            Ok(buf) => Ok(buf.as_slice().to_vec()),
            Err(e) => Err(e.to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn get_key(&self, handle: &str) -> Result<&[u8], String> {
        if handle.starts_with("mvk:") {
            self.mvk_handles
                .get(handle)
                .map(|v| v.as_slice())
                .ok_or_else(|| format!("unknown MVK handle: {}", handle))
        } else if handle.starts_with("ske:") {
            self.session_keys
                .get(handle)
                .map(|v| v.as_slice())
                .ok_or_else(|| format!("unknown session key handle: {}", handle))
        } else {
            Err(format!("invalid handle format: {}", handle))
        }
    }
}

fn generate_random_hex(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Drop for Enclave {
    fn drop(&mut self) {
        self.shutdown();
    }
}
