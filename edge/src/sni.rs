//! The name a presenter's browser asks for, from the first TLS record (its ClientHello's
//! server_name extension). The edge reads only this: nothing is decrypted.

/// A TLS record is at most 2^14 bytes plus its framing.
pub const MAX_RECORD: usize = 16 * 1024 + 256;

/// The host name in a ClientHello record, lower-cased; None when it is not one or has none.
pub fn name(record: &[u8]) -> Option<String> {
    let mut p = Reader { b: record, at: 0 };
    if p.u8()? != 22 {
        return None; // not a handshake
    }
    p.skip(4)?; // version, length
    if p.u8()? != 1 {
        return None; // not a ClientHello
    }
    p.skip(3 + 2 + 32)?; // length, version, random
    let session = p.u8()? as usize;
    p.skip(session)?;
    let suites = p.u16()? as usize;
    p.skip(suites)?;
    let compression = p.u8()? as usize;
    p.skip(compression)?;
    let end = p.at + p.u16()? as usize;
    while p.at + 4 <= end {
        let (kind, len) = (p.u16()?, p.u16()? as usize);
        if kind != 0 {
            p.skip(len)?;
            continue;
        }
        p.skip(2)?; // the list's length
        if p.u8()? != 0 {
            return None; // not a host name
        }
        let n = p.u16()? as usize;
        let name = std::str::from_utf8(p.take(n)?).ok()?.to_ascii_lowercase();
        let valid = !name.is_empty() && name.len() <= 253 && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.');
        return valid.then_some(name);
    }
    None
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at + n)?;
        self.at += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn not_a_client_hello_has_no_name() {
        assert_eq!(super::name(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(super::name(&[22, 3, 1, 0, 2, 1]), None);
    }
}
