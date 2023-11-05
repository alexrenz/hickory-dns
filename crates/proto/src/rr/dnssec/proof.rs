// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNSSEC related Proof of record authenticity

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "backtrace")]
use crate::ExtBacktrace;
use crate::{
    error::{DnsSecError, ProtoError},
    rr::Name,
};

use super::Algorithm;

/// Represents the status of a DNSSEC verified record.
///
/// see [RFC 4035, DNSSEC Protocol Modifications, March 2005](https://datatracker.ietf.org/doc/html/rfc4035#section-4.3)
/// ```text
/// 4.3.  Determining Security Status of Data
///
///   A security-aware resolver MUST be able to determine whether it should
///   expect a particular RRset to be signed.  More precisely, a
///   security-aware resolver must be able to distinguish between four
///   cases:
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Proof {
    /// An RRset for which the resolver is able to build a chain of
    ///   signed DNSKEY and DS RRs from a trusted security anchor to the
    ///   RRset.  In this case, the RRset should be signed and is subject to
    ///   signature validation, as described above.
    Secure = 3,

    /// An RRset for which the resolver knows that it has no chain
    ///   of signed DNSKEY and DS RRs from any trusted starting point to the
    ///   RRset.  This can occur when the target RRset lies in an unsigned
    ///   zone or in a descendent of an unsigned zone.  In this case, the
    ///   RRset may or may not be signed, but the resolver will not be able
    ///   to verify the signature.
    Insecure = 2,

    /// An RRset for which the resolver believes that it ought to be
    ///   able to establish a chain of trust but for which it is unable to
    ///   do so, either due to signatures that for some reason fail to
    ///   validate or due to missing data that the relevant DNSSEC RRs
    ///   indicate should be present.  This case may indicate an attack but
    ///   may also indicate a configuration error or some form of data
    ///   corruption.
    Bogus = 1,

    /// An RRset for which the resolver is not able to
    ///   determine whether the RRset should be signed, as the resolver is
    ///   not able to obtain the necessary DNSSEC RRs.  This can occur when
    ///   the security-aware resolver is not able to contact security-aware
    ///   name servers for the relevant zones.
    Indeterminate = 0,
}

impl Proof {
    /// Returns true if this Proof represents a validated DNSSEC record
    #[inline]
    pub fn is_secure(&self) -> bool {
        *self == Self::Secure
    }

    /// Returns true if this Proof represents a validated to be insecure DNSSEC record,
    ///   meaning the zone is known to be not signed
    #[inline]
    pub fn is_insecure(&self) -> bool {
        *self == Self::Insecure
    }

    /// Returns true if this Proof represents a DNSSEC record that failed validation,
    ///   meaning that the DNSSEC is bad, or other DNSSEC records are incorrect
    #[inline]
    pub fn is_bogus(&self) -> bool {
        *self == Self::Bogus
    }

    /// Either the record has not been verified or
    #[inline]
    pub fn is_indeterminate(&self) -> bool {
        *self == Self::Indeterminate
    }
}

impl Default for Proof {
    /// Returns `Indeterminate` as the default state for Proof as this is the closest to meaning
    ///   that no DNSSEC verification has happened.
    fn default() -> Self {
        Self::Indeterminate
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Bogus => "Bogus",
            Self::Indeterminate => "Indeterminate",
        };

        f.write_str(s)
    }
}

impl PartialOrd for Proof {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Proof {
    /// If self is great than other, it has a strong DNSSEC proof, i.e. Secure is the highest
    ///   Ordering from highest to lowest is: Secure, Insecure, Bogus, Indeterminate
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let this = *self as u8;
        let other = *other as u8;

        this.cmp(&other)
    }
}

#[test]
fn test_order() {
    assert!(Proof::Secure > Proof::Insecure);
    assert!(Proof::Insecure > Proof::Bogus);
    assert!(Proof::Bogus > Proof::Indeterminate);
}

/// The error kind for dnssec errors that get returned in the crate
#[allow(unreachable_pub)]
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum ProofErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Algorithm mismatch between rrsig and dnskey
    #[error("algorithm mismatch rrsig: {rrsig} dnskey: {dnskey}")]
    AlgorithmMismatch { rrsig: Algorithm, dnskey: Algorithm },

    /// A DNSSEC validation error, occured
    #[error("ssl error: {0}")]
    DnsSecError(#[from] DnsSecError),

    /// A DnsKey verification of rrset and rrsig faile
    #[error("dnskey and rrset failed to verify: {name} key_tag: {key_tag}")]
    DnsKeyVerifyRrsig {
        name: Name,
        key_tag: u16,
        error: ProtoError,
    },

    /// A DnsKey was revoked and could not be used for validation
    #[error("dnskey revoked: {name} key_tag: {key_tag}")]
    DnsKeyRevoked { name: Name, key_tag: u16 },

    /// The DnsKey is not marked as a zone key
    #[error("not a zone signing key: {name} key_tag: {key_tag}")]
    NotZoneDnsKey { name: Name, key_tag: u16 },
}

/// The error type for dnssec errors that get returned in the crate
#[derive(Debug, Clone, Error)]
pub struct ProofError {
    proof: Proof,
    kind: ProofErrorKind,
}

impl ProofError {
    /// Create an error with the given Proof and Associated Error
    pub fn new(proof: Proof, kind: ProofErrorKind) -> Self {
        Self { proof, kind }
    }

    /// Get the kind of the error
    pub fn kind(&self) -> &ProofErrorKind {
        &self.kind
    }
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.proof, self.kind)
    }
}