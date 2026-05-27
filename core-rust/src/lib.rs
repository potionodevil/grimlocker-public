#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Mutex;

use zeroize::Zeroize;

mod coordinates;
mod crypto;
mod enclave;
mod time_guard;
mod wipe;

use coordinates::{Coordinate, CoordinateResult};
use enclave::Enclave;

// ---------------------------------------------------------------------------
// Global enclave instance — initialized once, holds all key material.
// ---------------------------------------------------------------------------
lazy_static::lazy_static! {
    static ref ENCLAVE: Mutex<Enclave> = Mutex::new(Enclave::new());
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Coordinates error: {0}")]
    Coordinates(String),

    #[error("Wipe error: {0}")]
    Wipe(String),

    #[error("Time integrity violation: {0}")]
    TimeIntegrity(String),

    #[error("Memory lock error: {0}")]
    MemoryLock(String),

    #[error("Memory allocation error: {0}")]
    MemoryAlloc(String),

    #[error("Enclave error: {0}")]
    Enclave(String),
}

const ENTROPY_CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~ ";

// ===========================================================================
// Phase 1: Existing CGO exports (preserved for backward compatibility)
// ===========================================================================

#[no_mangle]
pub extern "C" fn generate_entropy_file(path: *const c_char, line_count: usize) -> *mut c_char {
    if path.is_null() {
        return cstr_result("ERROR: null path");
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return cstr_result("ERROR: invalid path encoding"),
    };

    match do_generate_entropy_file(&path_str, line_count) {
        Ok(_) => cstr_result("OK"),
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

fn do_generate_entropy_file(path: &str, line_count: usize) -> Result<(), String> {
    use rand::RngCore;
    use std::fs::OpenOptions;
    use std::io::{BufWriter, Write};

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("open file: {}", e))?;

    let mut writer = BufWriter::new(file);
    let mut rng = rand::thread_rng();
    let mut line_buf = vec![0u8; 120];

    for line_num in 0..line_count {
        let line_len = 80 + (rng.next_u32() as usize % 41);

        for i in 0..line_len {
            let idx = (rng.next_u32() as usize) % ENTROPY_CHARSET.len();
            line_buf[i] = ENTROPY_CHARSET[idx];
        }

        writer
            .write_all(&line_buf[..line_len])
            .map_err(|e| format!("write line {}: {}", line_num, e))?;
        writer
            .write_all(b"\n")
            .map_err(|e| format!("write newline {}: {}", line_num, e))?;

        if line_num % 1000 == 0 {
            writer
                .flush()
                .map_err(|e| format!("flush at {}: {}", line_num, e))?;
        }
    }

    writer.flush().map_err(|e| format!("final flush: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    line_buf.zeroize();

    Ok(())
}

#[no_mangle]
pub extern "C" fn extract_key_from_coordinates(
    path: *const c_char,
    coords_json: *const c_char,
    out_key: *mut u8,
    out_key_len: usize,
) -> *mut c_char {
    if path.is_null() || coords_json.is_null() || out_key.is_null() {
        return cstr_result("ERROR: null pointer");
    }

    if out_key_len < 32 {
        return cstr_result("ERROR: key buffer too small (need 32 bytes)");
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return cstr_result("ERROR: invalid path encoding"),
    };

    let coords_json_str = match unsafe { CStr::from_ptr(coords_json) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return cstr_result("ERROR: invalid JSON encoding"),
    };

    match do_extract_key(&path_str, &coords_json_str, out_key, out_key_len) {
        Ok(_) => cstr_result("OK"),
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

fn do_extract_key(
    path: &str,
    coords_json: &str,
    out_key: *mut u8,
    out_key_len: usize,
) -> Result<(), String> {
    let coords: Vec<Coordinate> =
        serde_json::from_str(coords_json).map_err(|e| format!("parse coordinates JSON: {}", e))?;

    let entropy_data = std::fs::read(path).map_err(|e| format!("read entropy file: {}", e))?;

    match coordinates::parse_coordinates(&entropy_data, &coords) {
        Ok(CoordinateResult::DerivedKey(key)) => {
            let key_bytes = key.0.as_slice();
            if key_bytes.len() > out_key_len {
                return Err("derived key exceeds output buffer".into());
            }

            unsafe {
                ptr::copy_nonoverlapping(key_bytes.as_ptr(), out_key, key_bytes.len());
            }

            Ok(())
        }
        Ok(CoordinateResult::PanicTrigger) => Err("PANIC_TRIGGER_DETECTED".into()),
        Err(e) => Err(format!("coordinate extraction: {}", e)),
    }
}

#[no_mangle]
pub extern "C" fn secure_zero(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }

    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        slice.zeroize();
    }
}

#[no_mangle]
pub extern "C" fn generate_random_coordinates(
    entropy_path: *const c_char,
    count: usize,
    out_json: *mut c_char,
    out_json_len: usize,
) -> *mut c_char {
    if entropy_path.is_null() || out_json.is_null() || count == 0 {
        return cstr_result("ERROR: null pointer or zero count");
    }

    let path_str = match unsafe { CStr::from_ptr(entropy_path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return cstr_result("ERROR: invalid path encoding"),
    };

    match do_generate_random_coordinates(&path_str, count, out_json, out_json_len) {
        Ok(_) => cstr_result("OK"),
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

fn do_generate_random_coordinates(
    path: &str,
    count: usize,
    out_json: *mut c_char,
    out_json_len: usize,
) -> Result<(), String> {
    use rand::Rng;

    let entropy_data = std::fs::read(path).map_err(|e| format!("read entropy file: {}", e))?;

    let mut rng = rand::thread_rng();
    let mut coords = Vec::with_capacity(count);

    let current_block: usize = 0;
    let mut current_line: usize = 0;
    let mut current_char: usize = 0;
    let mut in_newline = false;
    let mut line_starts: Vec<(usize, usize, usize)> = Vec::new();

    for (_i, &byte) in entropy_data.iter().enumerate() {
        if in_newline {
            in_newline = false;
            current_line += 1;
            current_char = 0;
            if byte == b'\r' {
                continue;
            }
        }

        if byte == b'\n' || byte == b'\r' {
            current_char = 0;
            in_newline = true;
            continue;
        }

        if current_char == 0 {
            line_starts.push((current_block, current_line, _i));
        }

        current_char += 1;
    }

    if line_starts.is_empty() {
        return Err("entropy file has no valid lines".into());
    }

    for _ in 0..count {
        let line_idx = rng.gen_range(0..line_starts.len());
        let (block, line, offset) = line_starts[line_idx];

        let remaining_in_line = entropy_data[offset..]
            .iter()
            .take_while(|&&b| b != b'\n' && b != b'\r')
            .count();

        if remaining_in_line == 0 {
            continue;
        }

        let char_idx = rng.gen_range(0..remaining_in_line);

        coords.push(Coordinate {
            block,
            line,
            char_index: char_idx,
        });
    }

    let json_str =
        serde_json::to_string(&coords).map_err(|e| format!("serialize coordinates: {}", e))?;

    let json_bytes = json_str.as_bytes();
    let copy_len = std::cmp::min(json_bytes.len(), out_json_len.saturating_sub(1));

    unsafe {
        ptr::copy_nonoverlapping(json_bytes.as_ptr(), out_json as *mut u8, copy_len);
        *(out_json.add(copy_len)) = 0;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn grimcore_derive_workspace_key(
    master_key: *const u8,
    master_key_len: usize,
    workspace_id: *const c_char,
    out_key: *mut u8,
    out_key_len: usize,
) -> *mut c_char {
    if master_key.is_null() || workspace_id.is_null() || out_key.is_null() {
        return cstr_result("ERROR: null pointer");
    }

    if out_key_len < 32 {
        return cstr_result("ERROR: out_key_len must be at least 32");
    }

    let mk_slice = unsafe { std::slice::from_raw_parts(master_key, master_key_len) };

    let ws_id_cstr = unsafe { CStr::from_ptr(workspace_id) };
    let ws_id_str = match ws_id_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return cstr_result("ERROR: workspace_id is not valid UTF-8"),
    };

    match coordinates::derive_workspace_key(mk_slice, ws_id_str) {
        Ok(derived_key) => {
            unsafe {
                ptr::copy_nonoverlapping(derived_key.as_ptr(), out_key, 32);
            }
            cstr_result("OK")
        }
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

// ===========================================================================
// Phase 1.1: Secure wipe CGO export
// ===========================================================================

/// grimcore_secure_wipe performs a 7-pass secure file wipe via the Rust core.
/// Returns "OK" on success or "ERROR: ..." on failure.
#[no_mangle]
pub extern "C" fn grimcore_secure_wipe(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return cstr_result("ERROR: null path");
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return cstr_result("ERROR: invalid path encoding"),
    };

    match wipe::secure_wipe(&path_str) {
        Ok(()) => cstr_result("OK"),
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

// ===========================================================================
// Phase 1.2: Encrypt/Decrypt CGO exports (raw key, for backward compat)
// ===========================================================================

/// grimcore_encrypt_raw encrypts plaintext with a 32-byte key using
/// ChaCha20-Poly1305. Returns nonce(12) + ciphertext+tag.
/// ciphertext_out must be at least plaintext_len + 28 bytes.
/// ciphertext_len_out is set to the actual output length.
#[no_mangle]
pub extern "C" fn grimcore_encrypt_raw(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_len_out: *mut usize,
) -> *mut c_char {
    if key.is_null()
        || nonce.is_null()
        || plaintext.is_null()
        || ciphertext_out.is_null()
        || ciphertext_len_out.is_null()
    {
        return cstr_result("ERROR: null pointer");
    }

    if key_len != 32 {
        return cstr_result("ERROR: key must be 32 bytes");
    }
    if nonce_len != 12 {
        return cstr_result("ERROR: nonce must be 12 bytes");
    }

    let key_bytes = unsafe { std::slice::from_raw_parts(key, key_len) };
    let nonce_bytes = unsafe { std::slice::from_raw_parts(nonce, nonce_len) };
    let plaintext_bytes = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let aad_bytes = if aad.is_null() || aad_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key_bytes);

    match crypto::encrypt_with_nonce(plaintext_bytes, &key_arr, nonce_bytes, aad_bytes) {
        Ok(ct) => {
            let len = ct.len();
            unsafe {
                ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext_out, len);
                *ciphertext_len_out = len;
            }
            key_arr.zeroize();
            cstr_result("OK")
        }
        Err(e) => {
            key_arr.zeroize();
            cstr_result(&format!("ERROR: {}", e))
        }
    }
}

/// grimcore_decrypt_raw decrypts nonce(12)+ciphertext+tag with a 32-byte key.
/// plaintext_out must be at least ciphertext_len bytes.
/// plaintext_len_out is set to the actual output length.
#[no_mangle]
pub extern "C" fn grimcore_decrypt_raw(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext_out: *mut u8,
    plaintext_len_out: *mut usize,
) -> *mut c_char {
    if key.is_null()
        || nonce.is_null()
        || ciphertext.is_null()
        || plaintext_out.is_null()
        || plaintext_len_out.is_null()
    {
        return cstr_result("ERROR: null pointer");
    }

    if key_len != 32 {
        return cstr_result("ERROR: key must be 32 bytes");
    }
    if nonce_len != 12 {
        return cstr_result("ERROR: nonce must be 12 bytes");
    }

    let key_bytes = unsafe { std::slice::from_raw_parts(key, key_len) };
    let nonce_bytes = unsafe { std::slice::from_raw_parts(nonce, nonce_len) };
    let ciphertext_bytes = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let aad_bytes = if aad.is_null() || aad_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key_bytes);

    // Combine nonce + ciphertext for decrypt function
    let mut blob = Vec::with_capacity(12 + ciphertext_len);
    blob.extend_from_slice(nonce_bytes);
    blob.extend_from_slice(ciphertext_bytes);

    match crypto::decrypt(&blob, &key_arr) {
        Ok(plaintext) => {
            let pt_bytes = plaintext.as_slice();
            let len = pt_bytes.len();
            unsafe {
                ptr::copy_nonoverlapping(pt_bytes.as_ptr(), plaintext_out, len);
                *plaintext_len_out = len;
            }
            key_arr.zeroize();
            cstr_result("OK")
        }
        Err(e) => {
            key_arr.zeroize();
            cstr_result(&format!("ERROR: {}", e))
        }
    }
}

// ===========================================================================
// Phase 2: Enclave lifecycle CGO exports
// ===========================================================================

/// grimcore_init initializes the secure enclave. Must be called before any
/// other grimcore_* function. Returns "OK" or "ERROR: ...".
#[no_mangle]
pub extern "C" fn grimcore_init() -> *mut c_char {
    let mut enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return cstr_result("ERROR: enclave mutex poisoned"),
    };

    match enclave.init() {
        Ok(()) => cstr_result("OK"),
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

/// grimcore_shutdown destroys the secure enclave, zeroing all key material.
#[no_mangle]
pub extern "C" fn grimcore_shutdown() {
    let mut enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return,
    };
    enclave.shutdown();
}

// ===========================================================================
// Phase 2.3: Session key management via enclave
// ===========================================================================

/// grimcore_session_create creates a per-session encryption key and stores it
/// in the enclave under the given handle. The session key bytes are copied
/// to session_key_out (32 bytes) for transmission to the frontend.
/// Returns "OK" or "ERROR: ...".
#[no_mangle]
pub extern "C" fn grimcore_session_create(
    session_key_out: *mut u8,
    session_key_len: usize,
) -> *mut c_char {
    if session_key_out.is_null() {
        return cstr_result("ERROR: null pointer");
    }
    if session_key_len < 32 {
        return cstr_result("ERROR: session_key_out must be at least 32 bytes");
    }

    let mut enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return cstr_result("ERROR: enclave mutex poisoned"),
    };

    match enclave.create_session_key() {
        Ok((handle, key_bytes)) => {
            unsafe {
                ptr::copy_nonoverlapping(key_bytes.as_ptr(), session_key_out, 32);
            }
            // Return handle as C string — caller must free with free_cstring
            match CString::new(handle) {
                Ok(c) => c.into_raw(),
                Err(_) => cstr_result("ERROR: handle conversion failed"),
            }
        }
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

/// grimcore_session_destroy removes a session key from the enclave.
#[no_mangle]
pub extern "C" fn grimcore_session_destroy(handle: *const c_char) {
    if handle.is_null() {
        return;
    }

    let handle_str = match unsafe { CStr::from_ptr(handle) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return,
    };

    let mut enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return,
    };
    enclave.destroy_session_key(&handle_str);
}

// ===========================================================================
// Phase 2.4: Handle-based encrypt/decrypt via enclave
// ===========================================================================

/// grimcore_encrypt_handle encrypts plaintext using a key stored in the
/// enclave under the given handle. The handle can be an MVK handle
/// ("mvk:<hex>") or a session key handle ("ske:<hex>").
/// Returns: nonce(12) + ciphertext+tag written to ciphertext_out.
#[no_mangle]
pub extern "C" fn grimcore_encrypt_handle(
    handle: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_len_out: *mut usize,
) -> *mut c_char {
    if handle.is_null()
        || plaintext.is_null()
        || ciphertext_out.is_null()
        || ciphertext_len_out.is_null()
    {
        return cstr_result("ERROR: null pointer");
    }

    let handle_str = match unsafe { CStr::from_ptr(handle) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return cstr_result("ERROR: invalid handle encoding"),
    };

    let plaintext_bytes = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let aad_bytes = if aad.is_null() || aad_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };

    let enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return cstr_result("ERROR: enclave mutex poisoned"),
    };

    match enclave.encrypt_with_handle(&handle_str, plaintext_bytes, aad_bytes) {
        Ok(ct) => {
            let len = ct.len();
            unsafe {
                ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext_out, len);
                *ciphertext_len_out = len;
            }
            cstr_result("OK")
        }
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

/// grimcore_decrypt_handle decrypts nonce(12)+ciphertext+tag using a key
/// stored in the enclave under the given handle.
#[no_mangle]
pub extern "C" fn grimcore_decrypt_handle(
    handle: *const c_char,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext_out: *mut u8,
    plaintext_len_out: *mut usize,
) -> *mut c_char {
    if handle.is_null()
        || ciphertext.is_null()
        || plaintext_out.is_null()
        || plaintext_len_out.is_null()
    {
        return cstr_result("ERROR: null pointer");
    }

    let handle_str = match unsafe { CStr::from_ptr(handle) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return cstr_result("ERROR: invalid handle encoding"),
    };

    let ciphertext_bytes = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let aad_bytes = if aad.is_null() || aad_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };

    let enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return cstr_result("ERROR: enclave mutex poisoned"),
    };

    match enclave.decrypt_with_handle(&handle_str, ciphertext_bytes, aad_bytes) {
        Ok(pt) => {
            let len = pt.len();
            unsafe {
                ptr::copy_nonoverlapping(pt.as_ptr(), plaintext_out, len);
                *plaintext_len_out = len;
            }
            cstr_result("OK")
        }
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

// ===========================================================================
// Phase 2.5: SKE (Session Key Encryption) via enclave
// ===========================================================================

/// grimcore_ske_encrypt encrypts plaintext with the session key identified
/// by the handle. Returns nonce(12) + ciphertext+tag.
#[no_mangle]
pub extern "C" fn grimcore_ske_encrypt(
    handle: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_len_out: *mut usize,
) -> *mut c_char {
    // SKE is just encrypt_handle without AAD
    grimcore_encrypt_handle(
        handle,
        plaintext,
        plaintext_len,
        std::ptr::null(),
        0,
        ciphertext_out,
        ciphertext_len_out,
    )
}

/// grimcore_ske_decrypt decrypts nonce(12)+ciphertext+tag with the session
/// key identified by the handle.
#[no_mangle]
pub extern "C" fn grimcore_ske_decrypt(
    handle: *const c_char,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext_out: *mut u8,
    plaintext_len_out: *mut usize,
) -> *mut c_char {
    // SKE is just decrypt_handle without AAD
    grimcore_decrypt_handle(
        handle,
        ciphertext,
        ciphertext_len,
        std::ptr::null(),
        0,
        plaintext_out,
        plaintext_len_out,
    )
}

// ===========================================================================
// Phase 2: MVK handle management via enclave
// ===========================================================================

/// grimcore_mvk_store stores a 32-byte MVK in the enclave and returns a
/// handle string. The MVK is held in locked memory (mlock/VirtualLock)
/// and is zeroized when removed.
/// Returns a C string handle (caller must free with free_cstring).
#[no_mangle]
pub extern "C" fn grimcore_mvk_store(mvk: *const u8, mvk_len: usize) -> *mut c_char {
    if mvk.is_null() {
        return cstr_result("ERROR: null pointer");
    }
    if mvk_len != 32 {
        return cstr_result("ERROR: MVK must be 32 bytes");
    }

    let mvk_bytes = unsafe { std::slice::from_raw_parts(mvk, mvk_len) };

    let mut enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return cstr_result("ERROR: enclave mutex poisoned"),
    };

    match enclave.store_mvk(mvk_bytes) {
        Ok(handle) => match CString::new(handle) {
            Ok(c) => c.into_raw(),
            Err(_) => cstr_result("ERROR: handle conversion failed"),
        },
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

/// grimcore_mvk_revoke removes and zeroizes an MVK from the enclave.
#[no_mangle]
pub extern "C" fn grimcore_mvk_revoke(handle: *const c_char) {
    if handle.is_null() {
        return;
    }

    let handle_str = match unsafe { CStr::from_ptr(handle) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return,
    };

    let mut enclave = match ENCLAVE.lock() {
        Ok(e) => e,
        Err(_) => return,
    };
    enclave.revoke_mvk(&handle_str);
}

// ===========================================================================
// Phase 1.3: BLAKE3 coordinate derivation (direct CGO export)
// ===========================================================================

/// grimcore_derive_coordinate extracts bytes at offsets from entropy data
/// and derives a 32-byte key using BLAKE3 → HKDF-SHA256.
/// This is the CORRECT implementation (Rust uses real BLAKE3, Go uses SHA-256
/// as a workaround which produces different keys).
/// offsets_json is a JSON array of integers [offset1, offset2, ...].
#[no_mangle]
pub extern "C" fn grimcore_derive_coordinate(
    entropy_data: *const u8,
    entropy_data_len: usize,
    offsets_json: *const c_char,
    out_key: *mut u8,
    out_key_len: usize,
) -> *mut c_char {
    if entropy_data.is_null() || offsets_json.is_null() || out_key.is_null() {
        return cstr_result("ERROR: null pointer");
    }
    if out_key_len < 32 {
        return cstr_result("ERROR: out_key must be at least 32 bytes");
    }

    let entropy = unsafe { std::slice::from_raw_parts(entropy_data, entropy_data_len) };
    let offsets_str = match unsafe { CStr::from_ptr(offsets_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return cstr_result("ERROR: invalid offsets JSON"),
    };

    let offsets: Vec<i64> = match serde_json::from_str(offsets_str) {
        Ok(v) => v,
        Err(e) => return cstr_result(&format!("ERROR: parse offsets: {}", e)),
    };

    // Extract bytes at offsets from entropy data
    let mut extracted = Vec::with_capacity(offsets.len());
    for &offset in &offsets {
        if offset < 0 || (offset as usize) >= entropy.len() {
            return cstr_result(&format!(
                "ERROR: offset {} out of range (max {})",
                offset,
                entropy.len()
            ));
        }
        extracted.push(entropy[offset as usize]);
    }

    // BLAKE3 → HKDF-SHA256 derivation (matches coordinates.rs derive_key)
    match coordinates::derive_key_from_extracted(&extracted) {
        Ok(key) => {
            unsafe {
                ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32.min(out_key_len));
            }
            cstr_result("OK")
        }
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

// ===========================================================================
// Argon2id key derivation via Rust
// ===========================================================================

/// grimcore_derive_argon2id derives a key from password using Argon2id.
/// This is intended to replace Go's argon2.IDKey for phase 3.
#[no_mangle]
pub extern "C" fn grimcore_derive_argon2id(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    _time: u32,
    _memory: u32,
    _threads: u8,
    key_len: u32,
    out_key: *mut u8,
    out_key_buf_len: usize,
) -> *mut c_char {
    if password.is_null() || salt.is_null() || out_key.is_null() {
        return cstr_result("ERROR: null pointer");
    }

    if (key_len as usize) > out_key_buf_len {
        return cstr_result("ERROR: output buffer too small");
    }

    let password_bytes = unsafe { std::slice::from_raw_parts(password, password_len) };
    let salt_bytes = unsafe { std::slice::from_raw_parts(salt, salt_len) };

    match crypto::derive_key_from_password(&String::from_utf8_lossy(password_bytes), salt_bytes) {
        Ok(key) => {
            let key_len_usize = key_len as usize;
            unsafe {
                ptr::copy_nonoverlapping(key.as_ptr(), out_key, key_len_usize.min(key.len()));
            }
            cstr_result("OK")
        }
        Err(e) => cstr_result(&format!("ERROR: {}", e)),
    }
}

// ===========================================================================
// Utilities
// ===========================================================================

fn cstr_result(msg: &str) -> *mut c_char {
    match CString::new(msg) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            let fallback = CString::new("ERROR: internal conversion failure").unwrap();
            fallback.into_raw()
        }
    }
}

#[no_mangle]
pub extern "C" fn free_cstring(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
