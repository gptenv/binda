//! An NTP-disciplined [`TimeSource`].
//!
//! Liveness is only meaningful if every node agrees on roughly the same
//! clock; trusting each machine's unsynchronized local clock would let a
//! fast clock evict a client early or a slow one let a dead client's
//! domains sit unreclaimed. [`NtpTimeSource`] periodically queries a list
//! of trusted NTP servers with a minimal SNTP (RFC 4330) client, computes
//! this host's offset from them, and applies that offset to
//! [`SystemTime::now`] on every [`TimeSource::now_millis`] call.

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::liveness::TimeSource;

/// Seconds between 1900-01-01 (the NTP epoch) and 1970-01-01 (the Unix
/// epoch).
const NTP_UNIX_EPOCH_DELTA_SECS: u64 = 2_208_988_800;

/// Default public NTP servers polled if the caller doesn't supply its own.
pub const DEFAULT_NTP_SERVERS: &[&str] = &[
    "pool.ntp.org:123",
    "time.cloudflare.com:123",
    "time.google.com:123",
];

/// How often the background sync thread re-queries the NTP servers.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(300);

/// How long to wait for a single server's reply before trying the next.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// A [`TimeSource`] whose reading is the local clock plus an offset
/// measured against trusted NTP servers, refreshed by a background thread.
#[derive(Clone)]
pub struct NtpTimeSource {
    offset_millis: Arc<AtomicI64>,
    synced: Arc<AtomicBool>,
}

impl NtpTimeSource {
    /// Perform one blocking synchronization pass immediately (so the
    /// offset is known before the caller starts trusting it), then spawn
    /// a background thread that repeats the sync every `poll_interval`.
    pub fn spawn(servers: Vec<String>, poll_interval: Duration) -> Self {
        let offset_millis = Arc::new(AtomicI64::new(0));
        let synced = Arc::new(AtomicBool::new(false));

        let source = Self {
            offset_millis: offset_millis.clone(),
            synced: synced.clone(),
        };
        source.sync_once(&servers);

        std::thread::spawn(move || loop {
            std::thread::sleep(poll_interval);
            let probe = Self {
                offset_millis: offset_millis.clone(),
                synced: synced.clone(),
            };
            probe.sync_once(&servers);
        });

        source
    }

    /// Convenience constructor using [`DEFAULT_NTP_SERVERS`] and
    /// [`DEFAULT_POLL_INTERVAL`].
    pub fn spawn_default() -> Self {
        Self::spawn(
            DEFAULT_NTP_SERVERS.iter().map(|s| s.to_string()).collect(),
            DEFAULT_POLL_INTERVAL,
        )
    }

    /// Whether at least one sync attempt has ever succeeded.
    pub fn is_synced(&self) -> bool {
        self.synced.load(Ordering::SeqCst)
    }

    fn sync_once(&self, servers: &[String]) {
        for server in servers {
            match query_offset_millis(server) {
                Ok(offset) => {
                    self.offset_millis.store(offset, Ordering::SeqCst);
                    self.synced.store(true, Ordering::SeqCst);
                    return;
                }
                Err(_) => continue,
            }
        }
        // Every configured server was unreachable; keep the last known
        // offset rather than snapping back to an unverified local clock.
    }
}

impl TimeSource for NtpTimeSource {
    fn now_millis(&self) -> u64 {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let adjusted = local + self.offset_millis.load(Ordering::SeqCst);
        adjusted.max(0) as u64
    }
}

/// Query one NTP server and return this host's clock offset in
/// milliseconds (positive means the local clock is behind the server).
fn query_offset_millis(server: &str) -> io::Result<i64> {
    let addr = server
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for NTP server"))?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT))?;
    socket.set_write_timeout(Some(QUERY_TIMEOUT))?;
    socket.connect(addr)?;

    let mut packet = [0u8; 48];
    packet[0] = 0b00_100_011; // LI=0 (no warning), VN=4, Mode=3 (client)

    let t1 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    write_ntp_timestamp(&mut packet[40..48], t1);

    socket.send(&packet)?;
    let mut reply = [0u8; 48];
    let n = socket.recv(&mut reply)?;
    if n < 48 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short NTP reply",
        ));
    }
    let t4 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Receive Timestamp (T2): when the server received our request.
    let t2 = read_ntp_timestamp(&reply[32..40]);
    // Transmit Timestamp (T3): when the server sent this reply.
    let t3 = read_ntp_timestamp(&reply[40..48]);

    let t1_ms = t1.as_millis() as i64;
    let t2_ms = t2.as_millis() as i64;
    let t3_ms = t3.as_millis() as i64;
    let t4_ms = t4.as_millis() as i64;

    // Standard SNTP clock offset formula: ((T2 - T1) + (T3 - T4)) / 2.
    let offset = ((t2_ms - t1_ms) + (t3_ms - t4_ms)) / 2;
    Ok(offset)
}

fn write_ntp_timestamp(buf: &mut [u8], since_unix_epoch: Duration) {
    let secs = since_unix_epoch.as_secs() + NTP_UNIX_EPOCH_DELTA_SECS;
    let frac = ((since_unix_epoch.subsec_nanos() as u64) << 32) / 1_000_000_000;
    buf[0..4].copy_from_slice(&(secs as u32).to_be_bytes());
    buf[4..8].copy_from_slice(&(frac as u32).to_be_bytes());
}

fn read_ntp_timestamp(buf: &[u8]) -> Duration {
    let secs = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as u64;
    let frac = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as u64;
    let unix_secs = secs.saturating_sub(NTP_UNIX_EPOCH_DELTA_SECS);
    let nanos = (frac * 1_000_000_000) >> 32;
    Duration::new(unix_secs, nanos as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_round_trips_through_ntp_encoding() {
        let original = Duration::new(1_700_000_000, 500_000_000);
        let mut buf = [0u8; 8];
        write_ntp_timestamp(&mut buf, original);
        let decoded = read_ntp_timestamp(&buf);
        // Sub-second precision is lossy; allow a small tolerance.
        let diff = decoded.abs_diff(original);
        assert!(diff < Duration::from_millis(1));
    }

    #[test]
    fn unsynced_source_falls_back_to_zero_offset() {
        let source = NtpTimeSource {
            offset_millis: Arc::new(AtomicI64::new(0)),
            synced: Arc::new(AtomicBool::new(false)),
        };
        assert!(!source.is_synced());
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let reported = source.now_millis();
        assert!(reported.abs_diff(local) < 1000);
    }
}
