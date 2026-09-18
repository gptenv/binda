//! Punycode (RFC 3492) encode/decode, used to translate BINDA's native
//! Unicode domain labels to and from the ASCII-only label form legacy
//! RFC1035 DNS clients require (see [`crate::dns`]).

use thiserror::Error;

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;
const DELIMITER: char = '-';

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PunycodeError {
    #[error("punycode input contains an invalid basic code point")]
    InvalidInput,
    #[error("punycode overflow while encoding or decoding")]
    Overflow,
}

fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    delta /= if first_time { DAMP } else { 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

fn digit_to_char(digit: u32) -> char {
    if digit < 26 {
        (b'a' + digit as u8) as char
    } else {
        (b'0' + (digit - 26) as u8) as char
    }
}

fn char_to_digit(c: char) -> Option<u32> {
    match c {
        'a'..='z' => Some(c as u32 - 'a' as u32),
        'A'..='Z' => Some(c as u32 - 'A' as u32),
        '0'..='9' => Some(c as u32 - '0' as u32 + 26),
        _ => None,
    }
}

/// Encode a single label's Unicode text into the bare Punycode string
/// (without the `xn--` ACE prefix).
pub fn encode(input: &str) -> Result<String, PunycodeError> {
    let chars: Vec<char> = input.chars().collect();
    let basic: Vec<char> = chars.iter().copied().filter(|c| c.is_ascii()).collect();
    let mut output = String::new();
    for c in &basic {
        output.push(*c);
    }
    let mut handled = basic.len() as u32;
    let total = chars.len() as u32;
    if !basic.is_empty() {
        output.push(DELIMITER);
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;

    while handled < total {
        let min_code_point = chars
            .iter()
            .map(|&c| c as u32)
            .filter(|&cp| cp >= n)
            .min()
            .ok_or(PunycodeError::Overflow)?;

        delta = delta
            .checked_add((min_code_point - n).checked_mul(handled + 1).ok_or(PunycodeError::Overflow)?)
            .ok_or(PunycodeError::Overflow)?;
        n = min_code_point;

        for &c in &chars {
            let cp = c as u32;
            if cp < n {
                delta = delta.checked_add(1).ok_or(PunycodeError::Overflow)?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(digit_to_char(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit_to_char(q));
                bias = adapt(delta, handled + 1, handled == basic.len() as u32);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }

    Ok(output)
}

/// Decode a bare Punycode string (without the `xn--` prefix) back into its
/// original Unicode text.
pub fn decode(input: &str) -> Result<String, PunycodeError> {
    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut output: Vec<char> = Vec::new();

    let (basic, extended) = match input.rfind(DELIMITER) {
        Some(pos) => (&input[..pos], &input[pos + 1..]),
        None => ("", input),
    };
    for c in basic.chars() {
        if !c.is_ascii() {
            return Err(PunycodeError::InvalidInput);
        }
        output.push(c);
    }

    let mut chars = extended.chars().peekable();
    while chars.peek().is_some() {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let c = chars.next().ok_or(PunycodeError::InvalidInput)?;
            let digit = char_to_digit(c).ok_or(PunycodeError::InvalidInput)?;
            i = i
                .checked_add(digit.checked_mul(w).ok_or(PunycodeError::Overflow)?)
                .ok_or(PunycodeError::Overflow)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t).ok_or(PunycodeError::Overflow)?;
            k += BASE;
        }
        let num_points = output.len() as u32 + 1;
        bias = adapt(i - old_i, num_points, old_i == 0);
        n = n.checked_add(i / num_points).ok_or(PunycodeError::Overflow)?;
        i %= num_points;
        let ch = char::from_u32(n).ok_or(PunycodeError::InvalidInput)?;
        output.insert(i as usize, ch);
        i += 1;
    }

    Ok(output.into_iter().collect())
}

/// ASCII-Compatible Encoding of one domain label: passes pure-ASCII labels
/// through unchanged, and prefixes non-ASCII labels with `xn--` per IDNA.
pub fn label_to_ascii(label: &str) -> Result<String, PunycodeError> {
    if label.is_ascii() {
        Ok(label.to_string())
    } else {
        Ok(format!("xn--{}", encode(label)?))
    }
}

/// Reverse of [`label_to_ascii`].
pub fn label_from_ascii(label: &str) -> Result<String, PunycodeError> {
    match label.strip_prefix("xn--") {
        Some(rest) => decode(rest),
        None => Ok(label.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_pure_ascii_label() {
        let ascii = label_to_ascii("example").unwrap();
        assert_eq!(ascii, "example");
        assert_eq!(label_from_ascii(&ascii).unwrap(), "example");
    }

    #[test]
    fn round_trips_emoji_label() {
        let ascii = label_to_ascii("🔥").unwrap();
        assert!(ascii.starts_with("xn--"));
        assert_eq!(label_from_ascii(&ascii).unwrap(), "🔥");
    }

    #[test]
    fn round_trips_mixed_script_label() {
        let original = "مرحبا";
        let ascii = label_to_ascii(original).unwrap();
        assert!(ascii.starts_with("xn--"));
        assert_eq!(label_from_ascii(&ascii).unwrap(), original);
    }

    #[test]
    fn round_trips_known_vector() {
        // "ü" from RFC 3492 §7.1 examples encodes to "tda".
        let ascii = label_to_ascii("ü").unwrap();
        assert_eq!(ascii, "xn--tda");
        assert_eq!(label_from_ascii(&ascii).unwrap(), "ü");
    }
}
