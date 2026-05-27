use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::Error;

static mut BOOT_INSTANT: Option<Instant> = None;

pub struct TimeGuard {
    boot_instant: Instant,
    boot_ticks: u64,
    wallclock_last_seen: i64,
}

impl TimeGuard {
    pub fn new(boot_ticks: u64, wallclock_last_seen: i64) -> Self {
        let now = Instant::now();
        unsafe {
            BOOT_INSTANT = Some(now);
        }

        Self {
            boot_instant: now,
            boot_ticks,
            wallclock_last_seen,
        }
    }

    pub fn check_integrity(&self) -> Result<(), Error> {
        self.check_wallclock()?;
        self.check_monotonic()?;
        Ok(())
    }

    fn check_wallclock(&self) -> Result<(), Error> {
        let now_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::TimeIntegrity(format!("system time before epoch: {}", e)))?
            .as_secs() as i64;

        if now_wall < self.wallclock_last_seen {
            let delta = self.wallclock_last_seen - now_wall;
            return Err(Error::TimeIntegrity(format!(
                "TIME MANIPULATION DETECTED: clock moved backwards by {} seconds",
                delta
            )));
        }

        if now_wall - self.wallclock_last_seen > 86400 * 365 {
            return Err(Error::TimeIntegrity(
                "ANOMALY: wall clock jumped forward more than 1 year".into(),
            ));
        }

        Ok(())
    }

    fn check_monotonic(&self) -> Result<(), Error> {
        let elapsed = self.boot_instant.elapsed().as_secs();

        if elapsed < self.boot_ticks {
            return Err(Error::TimeIntegrity(format!(
                "MONOTONIC ANOMALY: elapsed {}s < stored {}s",
                elapsed, self.boot_ticks
            )));
        }

        Ok(())
    }

    pub fn get_current_monotonic_ticks(&self) -> u64 {
        self.boot_instant.elapsed().as_secs()
    }

    pub fn get_current_wallclock(&self) -> Result<i64, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::TimeIntegrity(format!("system time: {}", e)))?;

        Ok(now.as_secs() as i64)
    }

    pub fn is_lockdown_expired(&self, lockdown_timestamp: i64, lockdown_minutes: i64) -> bool {
        let now = match self.get_current_wallclock() {
            Ok(ts) => ts,
            Err(_) => return false,
        };

        let expiry = lockdown_timestamp + (lockdown_minutes * 60);
        now >= expiry
    }
}

pub fn get_boot_instant() -> Option<Instant> {
    unsafe { BOOT_INSTANT }
}
