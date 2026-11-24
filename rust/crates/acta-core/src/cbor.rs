//! Deterministic CBOR (RFC 8949 Section 4.2.1) for machine objects.
//!
//! Author: Gavin Blacklock
//!
//! Encoder rules: shortest-form integers and length arguments, no
//! indefinite-length items, map keys sorted bytewise lexicographically
//! by their deterministic encodings.
//!
//! Decoder rules: the decoder is validating, not lenient. It rejects
//! non-shortest forms, indefinite lengths, unsorted or duplicate map
//! keys, trailing bytes, floats, tags, and any other type outside the
//! admitted set. Reject, never repair (blueprint rule D6): a lenient
//! decoder is how implementations fork.

use crate::error::{ActaError, Result};
use std::collections::BTreeMap;

/// The admitted CBOR value set. Integers are the only numbers: there
/// is deliberately no float variant, so a float is unrepresentable in
/// a decoded Acta object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    /// Major type 7, simple value false or true.
    Bool(bool),
    /// Major type 7, simple value null.
    Null,
    /// Major types 0 and 1, within i64 range.
    Int(i64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3, valid UTF-8 enforced at decode time by String.
    Text(String),
    /// Major type 4.
    Array(Vec<CborValue>),
    /// Major type 5. BTreeMap keeps iteration deterministic; the
    /// encoder additionally sorts by encoded key bytes, which is the
    /// RFC 8949 Section 4.2.1 order and differs from text order when
    /// key lengths differ.
    Map(BTreeMap<String, CborValue>),
}

fn encode_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= 0xff {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Encode a value in deterministic CBOR form.
pub fn encode(value: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &CborValue, out: &mut Vec<u8>) {
    match value {
        CborValue::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        CborValue::Null => out.push(0xf6),
        CborValue::Int(n) => {
            if *n >= 0 {
                encode_head(0, *n as u64, out);
            } else {
                // Major type 1 encodes -1 - n.
                encode_head(1, (-1i128 - *n as i128) as u64, out);
            }
        }
        CborValue::Bytes(bytes) => {
            encode_head(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CborValue::Text(text) => {
            encode_head(3, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        CborValue::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        CborValue::Map(map) => {
            // Sort entries by their encoded key bytes (RFC 8949
            // Section 4.2.1 core deterministic ordering).
            let mut entries: Vec<(Vec<u8>, &CborValue)> = map
                .iter()
                .map(|(k, v)| (encode(&CborValue::Text(k.clone())), v))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            encode_head(5, entries.len() as u64, out);
            for (key_bytes, v) in entries {
                out.extend_from_slice(&key_bytes);
                encode_into(v, out);
            }
        }
    }
}

/// Maximum nesting depth admitted by the decoder. Hostile input
/// nesting deeper than this is rejected, never recursed into
/// (re-audit finding N3: the parse path must not panic or overflow
/// the stack on adversarial lengths or nesting).
const MAX_DEPTH: usize = 128;

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        // Checked arithmetic: a declared length near usize::MAX
        // must be an error, not an overflow panic (finding N3).
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ActaError::UnexpectedEof)?;
        if end > self.bytes.len() {
            return Err(ActaError::UnexpectedEof);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Reject a declared item count that cannot fit in the bytes
    /// remaining: every array element and every map entry occupies
    /// at least one byte, so a larger count is impossible input.
    /// Checked before any allocation is sized by it (finding N3).
    fn check_count(&self, len: u64) -> Result<()> {
        let remaining = (self.bytes.len() - self.pos) as u64;
        if len > remaining {
            return Err(ActaError::NonCanonicalCbor(format!(
                "declared length {len} exceeds the {remaining} bytes remaining"
            )));
        }
        Ok(())
    }

    fn read_argument(&mut self, info: u8) -> Result<u64> {
        match info {
            0..=23 => Ok(info as u64),
            24 => {
                let b = self.take(1)?[0] as u64;
                if b < 24 {
                    return Err(ActaError::NonCanonicalCbor(
                        "non-shortest one-byte argument".into(),
                    ));
                }
                Ok(b)
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= 0xff {
                    return Err(ActaError::NonCanonicalCbor(
                        "non-shortest two-byte argument".into(),
                    ));
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= 0xffff {
                    return Err(ActaError::NonCanonicalCbor(
                        "non-shortest four-byte argument".into(),
                    ));
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= 0xffff_ffff {
                    return Err(ActaError::NonCanonicalCbor(
                        "non-shortest eight-byte argument".into(),
                    ));
                }
                Ok(v)
            }
            31 => Err(ActaError::NonCanonicalCbor(
                "indefinite-length items are forbidden".into(),
            )),
            other => Err(ActaError::UnsupportedCborType(format!(
                "reserved additional information {other}"
            ))),
        }
    }

    fn decode_item(&mut self) -> Result<CborValue> {
        if self.depth >= MAX_DEPTH {
            return Err(ActaError::NonCanonicalCbor(format!(
                "nesting deeper than {MAX_DEPTH} levels is not admitted"
            )));
        }
        self.depth += 1;
        let result = self.decode_item_inner();
        self.depth -= 1;
        result
    }

    fn decode_item_inner(&mut self) -> Result<CborValue> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let info = first & 0x1f;
        match major {
            0 => {
                let v = self.read_argument(info)?;
                if v > i64::MAX as u64 {
                    return Err(ActaError::UnsupportedCborType(
                        "unsigned integer outside i64 range".into(),
                    ));
                }
                Ok(CborValue::Int(v as i64))
            }
            1 => {
                let arg = self.read_argument(info)?;
                let value = -1i128 - arg as i128;
                if value < i64::MIN as i128 {
                    return Err(ActaError::UnsupportedCborType(
                        "negative integer outside i64 range".into(),
                    ));
                }
                Ok(CborValue::Int(value as i64))
            }
            2 => {
                let len = self.read_argument(info)?;
                self.check_count(len)?;
                Ok(CborValue::Bytes(self.take(len as usize)?.to_vec()))
            }
            3 => {
                let len = self.read_argument(info)?;
                self.check_count(len)?;
                let raw = self.take(len as usize)?;
                let text = String::from_utf8(raw.to_vec()).map_err(|_| {
                    ActaError::NonCanonicalCbor("text string is not valid UTF-8".into())
                })?;
                Ok(CborValue::Text(text))
            }
            4 => {
                let len = self.read_argument(info)?;
                self.check_count(len)?;
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    items.push(self.decode_item()?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let len = self.read_argument(info)?;
                self.check_count(len)?;
                let mut map = BTreeMap::new();
                let mut prev_key_bytes: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let key_start = self.pos;
                    let key = self.decode_item()?;
                    let key_bytes = self.bytes[key_start..self.pos].to_vec();
                    if let Some(prev) = &prev_key_bytes {
                        if key_bytes <= *prev {
                            return Err(ActaError::NonCanonicalCbor(
                                "map keys are unsorted or duplicated".into(),
                            ));
                        }
                    }
                    prev_key_bytes = Some(key_bytes);
                    let key_text = match key {
                        CborValue::Text(t) => t,
                        _ => {
                            return Err(ActaError::UnsupportedCborType(
                                "map keys must be text strings".into(),
                            ))
                        }
                    };
                    let value = self.decode_item()?;
                    map.insert(key_text, value);
                }
                Ok(CborValue::Map(map))
            }
            6 => Err(ActaError::UnsupportedCborType(
                "tags are not admitted in Acta objects".into(),
            )),
            7 => match info {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                _ => Err(ActaError::UnsupportedCborType(format!(
                    "simple or floating-point value with info {info} is not admitted"
                ))),
            },
            _ => unreachable!(),
        }
    }
}

/// Decode exactly one deterministic CBOR item; trailing bytes reject.
pub fn decode(bytes: &[u8]) -> Result<CborValue> {
    let mut decoder = Decoder {
        bytes,
        pos: 0,
        depth: 0,
    };
    let value = decoder.decode_item()?;
    if decoder.pos != bytes.len() {
        return Err(ActaError::TrailingBytes);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_map(pairs: Vec<(&str, CborValue)>) -> CborValue {
        CborValue::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    #[test]
    fn round_trip() {
        let value = text_map(vec![
            ("a", CborValue::Int(1)),
            ("b", CborValue::Array(vec![CborValue::Bool(true), CborValue::Null])),
            ("neg", CborValue::Int(-257)),
            ("bytes", CborValue::Bytes(vec![0, 1, 2, 255])),
        ]);
        let encoded = encode(&value);
        assert_eq!(decode(&encoded).unwrap(), value);
    }

    #[test]
    fn shortest_form_enforced() {
        // 23 encoded in two-byte form is non-canonical.
        assert!(decode(&[0x18, 0x17]).is_err());
        // 24 in one-byte argument form is canonical.
        assert_eq!(decode(&[0x18, 0x18]).unwrap(), CborValue::Int(24));
        // Indefinite-length array is forbidden.
        assert!(decode(&[0x9f, 0x01, 0xff]).is_err());
        // Floats are not admitted.
        assert!(decode(&[0xf9, 0x3c, 0x00]).is_err());
        // Trailing bytes reject.
        assert!(decode(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn map_key_order_is_encoded_byte_order() {
        // "b" (length 1) encodes before "aa" (length 2) under RFC 8949
        // Section 4.2.1, the reverse of plain text order for this pair.
        let value = text_map(vec![
            ("aa", CborValue::Int(1)),
            ("b", CborValue::Int(2)),
        ]);
        let encoded = encode(&value);
        assert_eq!(decode(&encoded).unwrap(), value);
        // Hand-built unsorted encoding: keys in text order, which is
        // not encoded-byte order here, must reject.
        let mut bad = vec![0xa2u8];
        bad.extend_from_slice(&encode(&CborValue::Text("aa".into())));
        bad.extend_from_slice(&encode(&CborValue::Int(1)));
        bad.extend_from_slice(&encode(&CborValue::Text("b".into())));
        bad.extend_from_slice(&encode(&CborValue::Int(2)));
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn encode_is_idempotent_through_decode() {
        let value = text_map(vec![("x", CborValue::Text("y".into()))]);
        let once = encode(&value);
        let twice = encode(&decode(&once).unwrap());
        assert_eq!(once, twice);
    }

    /// Re-audit finding N3: hostile declared lengths must be
    /// errors, never capacity-overflow panics or allocation
    /// attempts. The inputs are the re-audit's exact probes.
    #[test]
    fn test_n3_huge_declared_lengths_rejected_without_panic() {
        // Array header declaring length 2^64 - 1.
        let mut array = vec![0x9bu8];
        array.extend_from_slice(&[0xff; 8]);
        assert!(decode(&array).is_err());
        // Byte-string header declaring length 2^64 - 1.
        let mut bytes = vec![0x5bu8];
        bytes.extend_from_slice(&[0xff; 8]);
        assert!(decode(&bytes).is_err());
        // Text header declaring length 2^64 - 1.
        let mut text = vec![0x7bu8];
        text.extend_from_slice(&[0xff; 8]);
        assert!(decode(&text).is_err());
        // Map header declaring length 2^64 - 1.
        let mut map = vec![0xbbu8];
        map.extend_from_slice(&[0xff; 8]);
        assert!(decode(&map).is_err());
        // A plausible but impossible count: 5 elements, 1 byte left.
        assert!(decode(&[0x85, 0x01]).is_err());
    }

    /// Re-audit finding N3: pathological nesting is rejected at
    /// the depth limit instead of overflowing the stack.
    #[test]
    fn test_n3_deep_nesting_rejected_without_stack_overflow() {
        let mut nested = vec![0x81u8; 500];
        nested.push(0x01);
        assert!(decode(&nested).is_err());
        // Nesting within the limit still decodes.
        let mut shallow = vec![0x81u8; 10];
        shallow.push(0x01);
        assert!(decode(&shallow).is_ok());
    }
}
