use std::io::{self, BufRead, Write};
use std::thread;
use std::time::Duration;

mod coordinates;
mod crypto;
mod time_guard;
mod wipe;

use coordinates::CoordinateResult;
use time_guard::TimeGuard;

const LOCKDOWN_MINUTES: i64 = 200;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("IPC error: {0}")]
    Ipc(String),

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

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Vault locked: {0}")]
    Locked(String),
}

fn main() {
    let result = run();
    if let Err(e) = result {
        eprintln!("[ERROR] {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    println!("========================================");
    println!("  GRIMLOCKER v0.1.0 - Zero-Trust Vault");
    println!("========================================");
    println!();

    let db_path = std::env::var("GRIMLOCKER_DB_PATH")
        .unwrap_or_else(|_| "/var/lib/grimlocker/vault.gdb".to_string());

    let socket_path =
        std::env::var("GRIMLOCKER_SOCKET").unwrap_or_else(|_| "/tmp/grimlocker.sock".to_string());

    let cookie_b64 = std::env::var("GRIMLOCKER_COOKIE").map_err(|_| {
        Error::Ipc("GRIMLOCKER_COOKIE not set. Start grimdb-go daemon first.".into())
    })?;

    let cookie =
        base64_decode(&cookie_b64).ok_or_else(|| Error::Ipc("Invalid cookie format".into()))?;

    if cookie.len() != 32 {
        return Err(Error::Ipc(format!(
            "Cookie must be 32 bytes, got {}",
            cookie.len()
        )));
    }

    println!("[1/4] Connecting to GrimDB daemon...");
    let mut client = IpcClient::connect(&socket_path, &cookie)?;
    println!("      Connected.");
    println!();

    println!("[2/4] Reading vault header...");
    let header = client.get_header()?;
    println!("      Header loaded.");
    println!("      Failed attempts: {}", header.failed_attempts);
    println!(
        "      Override attempts left: {}",
        header.override_attempts_left
    );
    println!();

    let time_guard = TimeGuard::new(header.monotonic_boot_ticks, header.wallclock_last_seen);

    if let Err(e) = time_guard.check_integrity() {
        eprintln!("[CRITICAL] {}", e);
        eprintln!("[CRITICAL] Initiating emergency wipe...");
        wipe::secure_wipe(&db_path)?;
        return Err(Error::TimeIntegrity(
            "Vault wiped due to time manipulation".into(),
        ));
    }

    if header.failed_attempts >= 3 {
        println!("[LOCKDOWN] Vault is in lockdown mode.");
        println!();

        if time_guard.is_lockdown_expired(header.lockdown_timestamp, LOCKDOWN_MINUTES) {
            println!(
                "[CRITICAL] Lockdown window ({} min) has expired.",
                LOCKDOWN_MINUTES
            );
            println!("[CRITICAL] Initiating self-destruct...");
            trigger_wipe(&mut client, &db_path)?;
            return Err(Error::Locked("Vault wiped: lockdown expired".into()));
        }

        if header.override_attempts_left == 0 {
            println!("[CRITICAL] All override attempts exhausted.");
            println!("[CRITICAL] Initiating self-destruct...");
            trigger_wipe(&mut client, &db_path)?;
            return Err(Error::Locked(
                "Vault wiped: override attempts exhausted".into(),
            ));
        }

        return handle_lockdown_override(&mut client, &time_guard, &db_path, header);
    }

    handle_master_password(&mut client, &time_guard, &db_path, header)
}

fn handle_master_password(
    client: &mut IpcClient,
    time_guard: &TimeGuard,
    db_path: &str,
    header: Header,
) -> Result<(), Error> {
    println!("[3/4] Enter Master Password:");
    let password = read_password()?;

    if password.is_empty() {
        return Err(Error::AuthFailed);
    }

    let ciphertext = client.get_ciphertext()?;

    if ciphertext.is_empty() {
        println!();
        println!("[INFO] Vault is empty. Initializing new vault...");
        return initialize_new_vault(client, &password);
    }

    let salt = b"grimlocker-master-salt-v1";
    let key = crypto::derive_key_from_password(&password, salt)?;

    match crypto::decrypt(&ciphertext, &key) {
        Ok(plaintext) => {
            println!();
            println!("[SUCCESS] Vault unlocked!");
            println!("[INFO] Decrypted payload size: {} bytes", plaintext.len());
            println!(
                "[INFO] Password: {}",
                String::from_utf8_lossy(plaintext.as_slice())
            );

            client.update_header(Header {
                failed_attempts: 0,
                lockdown_timestamp: 0,
                override_attempts_left: 4,
                monotonic_boot_ticks: time_guard.get_current_monotonic_ticks(),
                wallclock_last_seen: time_guard.get_current_wallclock()?,
            })?;

            Ok(())
        }
        Err(e) => {
            println!();
            println!("[FAILED] Incorrect password.");

            client.update_header(Header {
                failed_attempts: header.failed_attempts + 1,
                lockdown_timestamp: if header.failed_attempts + 1 >= 3 {
                    time_guard.get_current_wallclock()?
                } else {
                    header.lockdown_timestamp
                },
                override_attempts_left: 4,
                monotonic_boot_ticks: time_guard.get_current_monotonic_ticks(),
                wallclock_last_seen: time_guard.get_current_wallclock()?,
            })?;

            if header.failed_attempts + 1 >= 3 {
                println!("[LOCKDOWN] Entering lockdown mode.");
            }

            Err(e)
        }
    }
}

fn handle_lockdown_override(
    client: &mut IpcClient,
    time_guard: &TimeGuard,
    db_path: &str,
    header: Header,
) -> Result<(), Error> {
    println!("[3/4] Enter Coordinate Passphrase:");
    println!("      (Format: block,line,char per line. Enter empty line to submit.)");
    println!();

    let mut input_lines = Vec::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| Error::Coordinates(format!("read input: {}", e)))?;
        if line.trim().is_empty() {
            break;
        }
        input_lines.push(line);
    }

    let input = input_lines.join("\n");
    let coords = coordinates::parse_coordinate_input(&input)?;

    let entropy_file_path = std::env::var("GRIMLOCKER_ENTROPY_FILE")
        .unwrap_or_else(|_| "/var/lib/grimlocker/entropy.txt".to_string());

    let entropy_file = std::fs::read(&entropy_file_path)
        .map_err(|e| Error::Coordinates(format!("read entropy file: {}", e)))?;

    match coordinates::parse_coordinates(&entropy_file, &coords)? {
        CoordinateResult::PanicTrigger => {
            println!();
            println!("[PANIC] Emergency wipe triggered.");
            show_fake_loading_screen();
            trigger_wipe(client, db_path)?;
            Err(Error::Locked("Vault wiped: panic trigger".into()))
        }
        CoordinateResult::DerivedKey(key) => {
            println!();
            println!("[VERIFY] Processing coordinate key...");

            let ciphertext = client.get_ciphertext()?;

            match crypto::decrypt(
                &ciphertext,
                key.0
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::KeyDerivation("key must be 32 bytes".into()))?,
            ) {
                Ok(plaintext) => {
                    println!("[SUCCESS] Override accepted! Vault unlocked.");
                    println!("[INFO] Decrypted payload size: {} bytes", plaintext.len());

                    client.update_header(Header {
                        failed_attempts: 0,
                        lockdown_timestamp: 0,
                        override_attempts_left: 4,
                        monotonic_boot_ticks: time_guard.get_current_monotonic_ticks(),
                        wallclock_last_seen: time_guard.get_current_wallclock()?,
                    })?;

                    Ok(())
                }
                Err(_) => {
                    println!("[FAILED] Incorrect coordinates.");

                    client.update_header(Header {
                        failed_attempts: header.failed_attempts,
                        lockdown_timestamp: header.lockdown_timestamp,
                        override_attempts_left: header.override_attempts_left.saturating_sub(1),
                        monotonic_boot_ticks: time_guard.get_current_monotonic_ticks(),
                        wallclock_last_seen: time_guard.get_current_wallclock()?,
                    })?;

                    let new_header = client.get_header()?;
                    if new_header.override_attempts_left == 0 {
                        println!("[CRITICAL] All override attempts exhausted.");
                        trigger_wipe(client, db_path)?;
                        return Err(Error::Locked("Vault wiped: override exhausted".into()));
                    }

                    Err(Error::Coordinates(format!(
                        "Incorrect coordinates. {} attempts remaining.",
                        new_header.override_attempts_left
                    )))
                }
            }
        }
    }
}

fn initialize_new_vault(client: &mut IpcClient, password: &str) -> Result<(), Error> {
    let salt = b"grimlocker-master-salt-v1";
    let key = crypto::derive_key_from_password(password, salt)?;

    let initial_data = b"Grimlocker vault initialized";
    let ciphertext = crypto::encrypt(initial_data, &key)?;

    client.update_ciphertext(&ciphertext)?;
    client.update_header(Header {
        failed_attempts: 0,
        lockdown_timestamp: 0,
        override_attempts_left: 4,
        monotonic_boot_ticks: 0,
        wallclock_last_seen: 0,
    })?;

    println!("[SUCCESS] New vault initialized.");
    Ok(())
}

fn trigger_wipe(client: &mut IpcClient, db_path: &str) -> Result<(), Error> {
    let _ = client.trigger_wipe();
    wipe::secure_wipe(db_path)?;
    println!("[WIPE] Vault file has been securely destroyed.");
    Ok(())
}

fn show_fake_loading_screen() {
    print!("Verifying coordinates...");
    io::stdout().flush().ok();
    thread::sleep(Duration::from_millis(800));
    println!(" OK");

    print!("Decrypting vault...");
    io::stdout().flush().ok();
    thread::sleep(Duration::from_millis(1200));
    println!(" OK");

    print!("Loading entries...");
    io::stdout().flush().ok();
    thread::sleep(Duration::from_millis(600));
    println!(" Done.");
}

fn read_password() -> Result<String, Error> {
    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .map_err(|e| Error::Io(e))?;
    Ok(password.trim().to_string())
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let mut buf = [0u8; 4];
    let mut idx = 0;

    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let val = alphabet.iter().position(|&a| a == c)?;
        buf[idx] = val as u8;
        idx += 1;
        if idx == 4 {
            result.push((buf[0] << 2) | (buf[1] >> 4));
            result.push((buf[1] << 4) | (buf[2] >> 2));
            result.push((buf[2] << 6) | buf[3]);
            idx = 0;
        }
    }

    if idx == 2 {
        result.push((buf[0] << 2) | (buf[1] >> 4));
    } else if idx == 3 {
        result.push((buf[0] << 2) | (buf[1] >> 4));
        result.push((buf[1] << 4) | (buf[2] >> 2));
    }

    Some(result)
}

#[derive(Debug, Clone)]
struct Header {
    failed_attempts: u8,
    lockdown_timestamp: i64,
    override_attempts_left: u8,
    monotonic_boot_ticks: u64,
    wallclock_last_seen: i64,
}

struct IpcClient {
    #[cfg(unix)]
    socket: std::os::unix::net::UnixStream,
    #[cfg(windows)]
    socket: std::fs::File,
}

impl IpcClient {
    fn connect(path: &str, cookie: &[u8]) -> Result<Self, Error> {
        #[cfg(unix)]
        let socket = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| Error::Ipc(format!("connect to {}: {}", path, e)))?;

        #[cfg(windows)]
        let socket = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| Error::Ipc(format!("connect to {}: {}", path, e)))?;

        let mut client = Self { socket };

        client.send_message(ipc::MSG_ACK, cookie)?;

        let (msg_type, payload) = client.read_message()?;
        if msg_type != ipc::MSG_ACK {
            return Err(Error::AuthFailed);
        }
        if payload != cookie {
            return Err(Error::AuthFailed);
        }

        Ok(client)
    }

    fn get_header(&mut self) -> Result<Header, Error> {
        self.send_message(ipc::MSG_GET_HEADER, &[])?;
        let (msg_type, payload) = self.read_message()?;
        if msg_type != ipc::MSG_HEADER {
            return Err(Error::Ipc(format!(
                "expected MSG_HEADER, got 0x{:02x}",
                msg_type
            )));
        }
        if payload.len() != 26 {
            return Err(Error::Ipc(format!(
                "header payload size: got {}, want 26",
                payload.len()
            )));
        }

        Ok(Header {
            failed_attempts: payload[0],
            lockdown_timestamp: i64::from_be_bytes(payload[1..9].try_into().unwrap()),
            override_attempts_left: payload[9],
            monotonic_boot_ticks: u64::from_be_bytes(payload[10..18].try_into().unwrap()),
            wallclock_last_seen: i64::from_be_bytes(payload[18..26].try_into().unwrap()),
        })
    }

    fn get_ciphertext(&mut self) -> Result<Vec<u8>, Error> {
        self.send_message(ipc::MSG_GET_CIPHERTEXT, &[])?;
        let (msg_type, payload) = self.read_message()?;
        if msg_type != ipc::MSG_CIPHERTEXT {
            return Err(Error::Ipc(format!(
                "expected MSG_CIPHERTEXT, got 0x{:02x}",
                msg_type
            )));
        }
        Ok(payload)
    }

    fn update_header(&mut self, header: Header) -> Result<(), Error> {
        let mut buf = [0u8; 26];
        buf[0] = header.failed_attempts;
        buf[1..9].copy_from_slice(&header.lockdown_timestamp.to_be_bytes());
        buf[9] = header.override_attempts_left;
        buf[10..18].copy_from_slice(&header.monotonic_boot_ticks.to_be_bytes());
        buf[18..26].copy_from_slice(&header.wallclock_last_seen.to_be_bytes());

        self.send_message(ipc::MSG_UPDATE_HEADER, &buf)?;
        let (msg_type, _) = self.read_message()?;
        if msg_type != ipc::MSG_ACK {
            return Err(Error::Ipc(format!("expected ACK, got 0x{:02x}", msg_type)));
        }
        Ok(())
    }

    fn update_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
        self.send_message(ipc::MSG_UPDATE_CIPHERTEXT, ciphertext)?;
        let (msg_type, _) = self.read_message()?;
        if msg_type != ipc::MSG_ACK {
            return Err(Error::Ipc(format!("expected ACK, got 0x{:02x}", msg_type)));
        }
        Ok(())
    }

    fn trigger_wipe(&mut self) -> Result<(), Error> {
        self.send_message(ipc::MSG_TRIGGER_WIPE, &[])?;
        Ok(())
    }

    fn send_message(&mut self, msg_type: u8, payload: &[u8]) -> Result<(), Error> {
        use std::io::Write;

        let msg_len = (1 + payload.len()) as u32;
        let len_buf = msg_len.to_be_bytes();

        self.socket
            .write_all(&len_buf)
            .map_err(|e| Error::Ipc(format!("write length: {}", e)))?;

        let mut msg = vec![msg_type];
        msg.extend_from_slice(payload);

        self.socket
            .write_all(&msg)
            .map_err(|e| Error::Ipc(format!("write message: {}", e)))?;

        self.socket
            .flush()
            .map_err(|e| Error::Ipc(format!("flush: {}", e)))?;

        Ok(())
    }

    fn read_message(&mut self) -> Result<(u8, Vec<u8>), Error> {
        use std::io::Read;

        let mut len_buf = [0u8; 4];
        self.socket
            .read_exact(&mut len_buf)
            .map_err(|e| Error::Ipc(format!("read length: {}", e)))?;

        let msg_len = u32::from_be_bytes(len_buf);
        if msg_len == 0 {
            return Err(Error::Ipc("zero-length message".into()));
        }

        let mut buf = vec![0u8; msg_len as usize];
        self.socket
            .read_exact(&mut buf)
            .map_err(|e| Error::Ipc(format!("read payload: {}", e)))?;

        let msg_type = buf[0];
        let payload = buf[1..].to_vec();

        Ok((msg_type, payload))
    }
}

mod ipc {
    pub const MSG_GET_HEADER: u8 = 0x01;
    pub const MSG_HEADER: u8 = 0x02;
    pub const MSG_GET_CIPHERTEXT: u8 = 0x03;
    pub const MSG_CIPHERTEXT: u8 = 0x04;
    pub const MSG_UPDATE_HEADER: u8 = 0x05;
    pub const MSG_UPDATE_CIPHERTEXT: u8 = 0x06;
    pub const MSG_TRIGGER_WIPE: u8 = 0x07;
    pub const MSG_ACK: u8 = 0x08;
    pub const MSG_ERROR: u8 = 0x09;
    pub const MSG_PANIC_WIPE: u8 = 0x0A;
}
