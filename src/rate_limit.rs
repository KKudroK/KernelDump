//! Average payload write rate, with bounded waits for cancellation.
use std::time::{Duration, Instant};

pub struct RateLimiter {
    begin: Instant,
    bytes: u64,
    bytes_per_second: Option<u64>,
}
impl RateLimiter {
    pub fn new(mbps: Option<u64>) -> Self {
        Self {
            begin: Instant::now(),
            bytes: 0,
            bytes_per_second: mbps.map(|v| v * 1_000_000),
        }
    }
    /// Charge actual writes, never sparse holes. False means cancellation.
    pub fn account(&mut self, bytes: usize, cancelled: impl Fn() -> bool) -> bool {
        self.bytes = self.bytes.saturating_add(bytes as u64);
        let Some(bps) = self.bytes_per_second else {
            return !cancelled();
        };
        let expected = Duration::from_secs_f64(self.bytes as f64 / bps as f64);
        loop {
            if cancelled() {
                return false;
            }
            let remaining = expected.saturating_sub(self.begin.elapsed());
            if remaining.is_zero() {
                return true;
            }
            std::thread::sleep(remaining.min(Duration::from_millis(20)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rate_limit_waits_beyond_one_quarter_second() {
        let start = Instant::now();
        let mut rate = RateLimiter::new(Some(1));
        assert!(rate.account(350_000, || false));
        assert!(start.elapsed() >= Duration::from_millis(350));
    }
    #[test]
    fn cancellation_interrupts_long_rate_wait() {
        let start = Instant::now();
        let mut rate = RateLimiter::new(Some(1));
        assert!(!rate.account(10_000_000, || start.elapsed() >= Duration::from_millis(30)));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
