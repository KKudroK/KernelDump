//! One size contract for range records produced and consumed by this tool.
use crate::Result;
use serde_json::Value;
use std::io::{self, Write};

// Includes the terminating newline. Reference-rich records can exceed 1 MiB
// even with the normal candidate limits. This cap is not eagerly allocated.
pub(crate) const RECORD_LIMIT: usize = 8 * 1024 * 1024;

struct Bounded<W> {
    inner: W,
    bytes: usize,
}
impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(data.len())
            .filter(|n| *n < RECORD_LIMIT)
            .ok_or_else(|| io::Error::other("range record exceeds 8MiB bound"))?;
        self.inner.write_all(data)?;
        self.bytes = next;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn check_size(value: &Value) -> Result<()> {
    serde_json::to_writer(
        Bounded {
            inner: io::sink(),
            bytes: 0,
        },
        value,
    )?;
    Ok(())
}

pub(crate) fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut output = Bounded {
        inner: Vec::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut output, value)?;
    output.inner.push(b'\n');
    Ok(output.inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn newline_is_included_in_the_shared_record_limit() {
        let boundary = Value::String("a".repeat(RECORD_LIMIT - 3));
        assert_eq!(encode(&boundary).unwrap().len(), RECORD_LIMIT);
        check_size(&boundary).unwrap();
        let over = Value::String("a".repeat(RECORD_LIMIT - 2));
        assert!(check_size(&over).is_err());
        assert!(encode(&over).is_err());
    }
}
