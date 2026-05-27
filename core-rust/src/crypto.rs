use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

#[cfg(unix)]
use nix::sys::mman;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LockedBuffer {
    data: Vec<u8>,
    #[cfg(unix)]
    locked: bool,
}

impl LockedBuffer {
    pub fn new(data: Vec<u8>) -> Result<Self, Error> {
        let buf = Self {
            data,
            #[cfg(unix)]
            locked: false,
        };

        #[cfg(unix)]
        {
            let mut buf_mut = buf;
            buf_mut.lock_memory()?;
            return Ok(buf_mut);
        }

        #[cfg(not(unix))]
        Ok(buf)
    }

    #[cfg(unix)]
    fn lock_memory(&mut self) -> Result<(), Error> {
        if self.data.is_empty() {
            return Ok(());
        }

        let ptr = self.data.as_ptr() as *const libc::c_void;
        let len = self.data.len();

        unsafe {
            mman::mlock(ptr, len).map_err(|e| Error::MemoryLock(format!("mlock failed: {}", e)))?;
        }

        self.locked = true;
        Ok(())
    }

    #[cfg(unix)]
    fn unlock_memory(&mut self) {
        if self.locked && !self.data.is_empty() {
            let ptr = self.data.as_ptr() as *const libc::c_void;
            let len = self.data.len();
            unsafe {
                let _ = mman::munlock(ptr, len);
            }
            self.locked = false;
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(unix)]
impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.unlock_memory();
    }
}

pub fn generate_nonce() -> [u8; 12] {
    ChaCha20Poly1305::generate_nonce(&mut OsRng).into()
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = generate_nonce();

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| Error::Encryption(format!("ChaCha20-Poly1305 encrypt failed: {}", e)))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// encrypt_with_nonce encrypts plaintext with the given key and explicit nonce.
/// This is used by the CGO raw encrypt function where Go provides the nonce.
pub fn encrypt_with_nonce(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8],
    _aad: &[u8],
) -> Result<Vec<u8>, Error> {
    if nonce.len() != 12 {
        return Err(Error::Encryption("nonce must be 12 bytes".into()));
    }

    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce_obj = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|e| Error::Encryption(format!("ChaCha20-Poly1305 encrypt failed: {}", e)))?;

    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<LockedBuffer, Error> {
    if ciphertext.len() < 12 {
        return Err(Error::Decryption("ciphertext too short (no nonce)".into()));
    }

    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let payload = &ciphertext[12..];

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| Error::Decryption(format!("ChaCha20-Poly1305 decrypt failed: {}", e)))?;

    LockedBuffer::new(plaintext)
}

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<[u8; 32], Error> {
    use blake3::Hasher;
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut hasher = Hasher::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let ikm = hasher.finalize().as_bytes().to_vec();

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"grimlocker-master-key", &mut okm)
        .map_err(|e| Error::KeyDerivation(format!("HKDF expand failed: {}", e)))?;

    Ok(okm)
}

#[cfg(unix)]
pub fn create_guard_pages(size: usize) -> Result<*mut u8, Error> {
    use nix::sys::mman::{mmap, mprotect, munmap, MapFlags, ProtFlags};
    use nix::unistd::sysconf;
    use nix::unistd::SysconfVar;

    let page_size = sysconf(SysconfVar::PAGE_SIZE)
        .ok()
        .flatten()
        .unwrap_or(4096) as usize;

    let total_size = page_size + size + page_size;
    let aligned_size = (total_size + page_size - 1) & !(page_size - 1);

    let ptr = unsafe {
        mmap(
            None,
            std::num::NonZeroUsize::new(aligned_size).unwrap(),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .map_err(|e| Error::MemoryAlloc(format!("mmap failed: {}", e)))?
    };

    let guard_before = ptr.as_ptr();
    let guard_after = unsafe { ptr.as_ptr().add(page_size + size) };

    unsafe {
        mprotect(
            guard_before as *mut libc::c_void,
            page_size,
            ProtFlags::PROT_NONE,
        )
        .map_err(|e| Error::MemoryAlloc(format!("guard page before: {}", e)))?;

        mprotect(
            guard_after as *mut libc::c_void,
            page_size,
            ProtFlags::PROT_NONE,
        )
        .map_err(|e| Error::MemoryAlloc(format!("guard page after: {}", e)))?;
    }

    let data_ptr = unsafe { ptr.as_ptr().add(page_size) };
    Ok(data_ptr as *mut u8)
}

#[cfg(unix)]
pub fn free_guard_pages(ptr: *mut u8, size: usize) -> Result<(), Error> {
    use nix::sys::mman::munmap;
    use nix::unistd::sysconf;
    use nix::unistd::SysconfVar;

    let page_size = sysconf(SysconfVar::PAGE_SIZE)
        .ok()
        .flatten()
        .unwrap_or(4096) as usize;

    let total_size = page_size + size + page_size;
    let aligned_size = (total_size + page_size - 1) & !(page_size - 1);

    let start = unsafe { ptr.sub(page_size) };

    unsafe {
        munmap(start as *mut libc::c_void, aligned_size)
            .map_err(|e| Error::MemoryAlloc(format!("munmap failed: {}", e)))?;
    }

    Ok(())
}
