//! A library to provide Cross-site request forgery protection.
//!
//! Getting this right can be tricky, and this library aims to provide the
//! primitives to be able to do this without making it too easy to get it
//! wrong. Remember though, this needs to be coupled with the HTTP layer
//! correctly as well in order to ensure it provide protection.
//!
//! # Warning
//!
//! This library provides primitives, and is meant to be used as a building
//! block. The suggested way to use this is to write a library to integrate
//! this with your favorite HTTP stack. For example, if you're using
//! [actix](https://actix.rs/) then don't use this directly but instead go use
//! [actix-xsrf](https://docs.rs/actix-xsrf).
//!
//! # Usage
//!
//! The library uses what seems to now be the standard method used by various
//! popular frameworks.
//! - A `CookieToken` is issued and stored in the cookie or the session.
//!   Remember to use a secure signed cookie.
//! - From this `CookieToken`, one or more `RequestToken`s can be issued.
//!   You can issue one per request, or multiple. Any number of them can be
//!   validated against the original `CookieToken`.
//! - The `RequestToken` should either be embedded in your HTML form, or sent
//!   via a HTTP header (often the case for requests initiated in JavaScript).
//! - The server side should validate this under the right circumstances.
//!
//! # Notes
//! - [`rand`](https://docs.rs/rand) is used to generate cryptographically
//!   secure tokens.
//! - `RequestToken`s use a one-time-pad and are xor-ed with the `CookieToken`
//!    to protect against [BREACH](http://breachattack.com/).
//! - [`subtle`](https://docs.rs/subtle) is used to protect against timing
//!   attacks.
use rand::{thread_rng, Rng};
use subtle::ConstantTimeEq;

const TOKEN_LEN: usize = 32;
const ENCODED_LEN: usize = 44;
static BC: base64::Config = base64::URL_SAFE;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid xsrf token")]
    InvalidToken,
    #[error("xsrf token mismatch")]
    TokenMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct CookieToken {
    data: [u8; TOKEN_LEN],
}

impl ToString for CookieToken {
    fn to_string(&self) -> String {
        base64::encode_config(&self.data, BC)
    }
}

impl std::convert::TryFrom<&str> for CookieToken {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        if value.len() != ENCODED_LEN {
            return Err(Error::InvalidToken);
        }
        let mut t = Self {
            data: [0; TOKEN_LEN],
        };
        if base64::decode_config_slice(value, BC, &mut t.data).is_err() {
            return Err(Error::InvalidToken);
        }
        Ok(t)
    }
}

impl CookieToken {
    pub fn new() -> CookieToken {
        let mut t = Self {
            data: [0; TOKEN_LEN],
        };
        thread_rng().fill(&mut t.data);
        t
    }

    pub fn gen_req_token(&self) -> RequestToken {
        let mut t = RequestToken {
            otp: [0; TOKEN_LEN],
            mask: [0; TOKEN_LEN],
        };
        thread_rng().fill(&mut t.otp);
        xor_into(&t.otp, &self.data, &mut t.mask);
        t
    }

    pub fn verify_req_token(&self, token: RequestToken) -> Result<()> {
        let mut expected = [0; TOKEN_LEN];
        xor_into(&token.otp, &token.mask, &mut expected);
        let eq: bool = expected.ct_eq(&self.data).into();
        if eq {
            Ok(())
        } else {
            Err(Error::TokenMismatch)
        }
    }
}

pub struct RequestToken {
    otp: [u8; TOKEN_LEN],
    mask: [u8; TOKEN_LEN],
}

impl ToString for RequestToken {
    fn to_string(&self) -> String {
        let mut s = String::with_capacity(ENCODED_LEN * 2);
        base64::encode_config_buf(self.otp, BC, &mut s);
        base64::encode_config_buf(self.mask, BC, &mut s);
        s
    }
}

impl std::convert::TryFrom<&str> for RequestToken {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        if value.len() != ENCODED_LEN * 2 {
            return Err(Error::InvalidToken);
        }
        let mut t = Self {
            otp: [0; TOKEN_LEN],
            mask: [0; TOKEN_LEN],
        };
        if base64::decode_config_slice(&value[..ENCODED_LEN], BC, &mut t.otp).is_err() {
            return Err(Error::InvalidToken);
        }
        if base64::decode_config_slice(&value[ENCODED_LEN..], BC, &mut t.mask).is_err() {
            return Err(Error::InvalidToken);
        }
        Ok(t)
    }
}

fn xor_into(a: &[u8], b: &[u8], into: &mut [u8]) {
    let l = a.len();
    debug_assert_eq!(b.len(), l);
    debug_assert_eq!(into.len(), l);
    a.iter()
        .zip(b.iter())
        .enumerate()
        .for_each(|(index, (a, b))| into[index] = a ^ b)
}

#[cfg(test)]
mod tests {
    use super::{CookieToken, RequestToken, ENCODED_LEN};
    use std::convert::TryInto;

    #[test]
    fn cookie_token_to_from_string() {
        let original = CookieToken::new();
        let s = original.to_string();
        assert_eq!(s.len(), ENCODED_LEN);
        let decoded: CookieToken = s.as_str().try_into().unwrap();
        assert_eq!(original.data, decoded.data);
    }

    #[test]
    fn request_token_to_from_string() {
        let ct = CookieToken::new();
        let original = ct.gen_req_token();
        let s = original.to_string();
        assert_eq!(s.len(), ENCODED_LEN * 2);
        let decoded: RequestToken = s.as_str().try_into().unwrap();
        assert_eq!(original.otp, decoded.otp);
        assert_eq!(original.mask, decoded.mask);
    }

    #[test]
    fn gen_and_verify_req_token() {
        let ct = CookieToken::new();
        let rt = ct.gen_req_token();
        ct.verify_req_token(rt).unwrap();
    }
}
