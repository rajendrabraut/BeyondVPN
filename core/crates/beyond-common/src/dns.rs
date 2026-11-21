//! Minimal, allocation-light DNS wire-format helpers (RFC 1035).
//!
//! The gateway only needs to read the question of a query (for logging and
//! filtering) and synthesise a "sinkhole" answer for blocked names. Full
//! resolution is delegated to the upstream resolver.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Byte offset where the question section ends.
    pub end: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("packet too short")]
    Short,
    #[error("not a query")]
    NotQuery,
    #[error("no question")]
    NoQuestion,
    #[error("bad label")]
    BadLabel,
}

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

pub fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        _ => "OTHER",
    }
}

/// Parse the first question of a DNS query.
pub fn parse_query(pkt: &[u8]) -> Result<Question, DnsError> {
    if pkt.len() < 12 {
        return Err(DnsError::Short);
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    if pkt[2] & 0x80 != 0 {
        return Err(DnsError::NotQuery);
    }
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qd == 0 {
        return Err(DnsError::NoQuestion);
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = *pkt.get(i).ok_or(DnsError::Short)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            // Compression pointers are not valid in a question; reject.
            return Err(DnsError::BadLabel);
        }
        let label = pkt.get(i..i + len).ok_or(DnsError::Short)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            // Keep logs printable and safe.
            let c = b.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
                name.push(c as char);
            } else {
                return Err(DnsError::BadLabel);
            }
        }
        i += len;
        if name.len() > 253 {
            return Err(DnsError::BadLabel);
        }
    }
    let rest = pkt.get(i..i + 4).ok_or(DnsError::Short)?;
    Ok(Question {
        id,
        name,
        qtype: u16::from_be_bytes([rest[0], rest[1]]),
        qclass: u16::from_be_bytes([rest[2], rest[3]]),
        end: i + 4,
    })
}

/// Build a sinkhole response: A -> 0.0.0.0, AAAA -> ::, everything else NXDOMAIN.
pub fn blocked_response(query: &[u8], q: &Question) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.end + 32);
    out.extend_from_slice(&query[0..2]); // id
    let rd = query[2] & 0x01;
    let opcode = query[2] & 0x78;
    out.push(0x80 | opcode | 0x04 | rd); // QR, opcode, AA, RD
    let answer = q.qtype == TYPE_A || q.qtype == TYPE_AAAA;
    out.push(0x80 | if answer { 0 } else { 3 }); // RA + rcode
    out.extend_from_slice(&[0, 1]); // qdcount
    out.extend_from_slice(&[0, if answer { 1 } else { 0 }]); // ancount
    out.extend_from_slice(&[0, 0, 0, 0]); // ns, ar
    out.extend_from_slice(&query[12..q.end]);
    if answer {
        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]); // IN
        out.extend_from_slice(&300u32.to_be_bytes());
        let rdlen: u16 = if q.qtype == TYPE_A { 4 } else { 16 };
        out.extend_from_slice(&rdlen.to_be_bytes());
        out.extend(std::iter::repeat_n(0u8, rdlen as usize));
    }
    out
}

/// Build a query packet (used in tests and health checks).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0, 1]);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query() {
        let p = build_query(0xBEEF, "WWW.Example.com.", TYPE_A);
        let q = parse_query(&p).unwrap();
        assert_eq!(q.id, 0xBEEF);
        assert_eq!(q.name, "www.example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.end, p.len());
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_query(&[0; 4]), Err(DnsError::Short));
        let mut p = build_query(1, "a.b", TYPE_A);
        p[2] |= 0x80;
        assert_eq!(parse_query(&p), Err(DnsError::NotQuery));
        let mut p = build_query(1, "a.b", TYPE_A);
        p[13] = b'\n';
        assert_eq!(parse_query(&p), Err(DnsError::BadLabel));
        let mut p = build_query(1, "abc.def", TYPE_A);
        p.truncate(15);
        assert_eq!(parse_query(&p), Err(DnsError::Short));
    }

    #[test]
    fn sinkhole_a_and_nxdomain() {
        let p = build_query(7, "ads.test", TYPE_A);
        let q = parse_query(&p).unwrap();
        let r = blocked_response(&p, &q);
        assert_eq!(&r[0..2], &[0, 7]);
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(r[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        assert_eq!(&r[r.len() - 4..], &[0, 0, 0, 0]);

        let p = build_query(8, "ads.test", 16);
        let q = parse_query(&p).unwrap();
        let r = blocked_response(&p, &q);
        assert_eq!(r[3] & 0x0f, 3);
        assert_eq!(r.len(), q.end);
    }
}
