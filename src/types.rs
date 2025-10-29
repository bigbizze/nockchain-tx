#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use core::fmt;

use nockchain_schnorr_rust::{PublicKey, Signature, Tip5Digest};

use crate::noun::{digest_to_noun, Noun};
use crate::zset::{zset_to_noun, ToNoun, ZSet};

/// Alias for the TIP-5 digest used throughout the chain.
pub type HashDigest = Tip5Digest;

/// Block height wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockHeight(pub u64);

impl From<u64> for BlockHeight {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Difference between block heights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockHeightDelta(pub u64);

impl From<u64> for BlockHeightDelta {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// Lightweight source commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub hash: HashDigest,
    pub coinbase: bool,
}

impl Source {
    pub fn new(hash: HashDigest, coinbase: bool) -> Self {
        Self { hash, coinbase }
    }
}

/// Multi-signature lock (m-of-n).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lock {
    pub keys_required: u8,
    pub public_keys: Vec<PublicKey>,
}

impl Lock {
    /// Creates a single-signer lock.
    pub fn single(public_key: PublicKey) -> Self {
        Self {
            keys_required: 1,
            public_keys: vec![public_key],
        }
    }

    /// Validates the lock against basic constraints.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.keys_required == 0 {
            return Err("lock must require at least one key");
        }
        if self.keys_required as usize > self.public_keys.len() {
            return Err("lock requires more keys than provided");
        }
        if self.public_keys.len() > u8::MAX as usize {
            return Err("too many public keys in lock");
        }
        Ok(())
    }
}

/// Supported timelock intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeLockIntent {
    /// No timelock constraint.
    None,
    /// Absolute block height range.
    Absolute {
        min: Option<BlockHeight>,
        max: Option<BlockHeight>,
    },
    /// Relative block height delta.
    Relative {
        min: Option<BlockHeightDelta>,
        max: Option<BlockHeightDelta>,
    },
    AbsoluteAndRelative {
        absolute: TimelockRange,
        relative: TimelockRange,
    },
    /// Explicitly forces the output to have no timelock.
    Neither,
}

impl Default for TimeLockIntent {
    fn default() -> Self {
        Self::None
    }
}

/// Timelock range with optional bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelockRange {
    pub min: Option<u64>,
    pub max: Option<u64>,
}

impl TimelockRange {
    pub fn new(min: Option<u64>, max: Option<u64>) -> Self {
        Self { min, max }
    }

    pub fn empty() -> Self {
        Self {
            min: None,
            max: None,
        }
    }
}

impl TimeLockIntent {
    pub fn as_ranges(&self) -> Option<(TimelockRange, TimelockRange)> {
        match self {
            TimeLockIntent::None => None,
            TimeLockIntent::Absolute { min, max } => Some((
                TimelockRange::new(min.map(|v| v.0), max.map(|v| v.0)),
                TimelockRange::empty(),
            )),
            TimeLockIntent::Relative { min, max } => Some((
                TimelockRange::empty(),
                TimelockRange::new(min.map(|v| v.0), max.map(|v| v.0)),
            )),
            TimeLockIntent::AbsoluteAndRelative { absolute, relative } => {
                Some((absolute.clone(), relative.clone()))
            }
            TimeLockIntent::Neither => {
                let range = TimelockRange::new(Some(0), Some(0));
                Some((range.clone(), range))
            }
        }
    }
}

/// Convenience wrapper for a schnorr signature entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrSignatureEntry {
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl SchnorrSignatureEntry {
    pub fn new(public_key: PublicKey, signature: Signature) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

/// Placeholder type alias for hashed public keys used in witness maps.
pub type PublicKeyHash = HashDigest;

impl ToNoun for Source {
    fn to_noun(&self) -> Noun {
        let hash_noun = digest_to_noun(&self.hash);
        let coinbase = self.coinbase.to_noun();
        Noun::list(&[hash_noun, coinbase])
    }
}

impl ToNoun for Lock {
    fn to_noun(&self) -> Noun {
        let pubkey_zset: ZSet<PublicKey> = self.public_keys.clone().into_iter().collect();
        let pubkeys_noun = zset_to_noun(pubkey_zset.root());
        Noun::list(&[Noun::atom_u64(self.keys_required as u64), pubkeys_noun])
    }
}

impl ToNoun for TimelockRange {
    fn to_noun(&self) -> Noun {
        let min = self.min.to_noun();
        let max = self.max.to_noun();
        Noun::list(&[min, max])
    }
}

impl ToNoun for TimeLockIntent {
    fn to_noun(&self) -> Noun {
        match self.as_ranges() {
            None => Noun::zero(),
            Some((absolute, relative)) => {
                let absolute_noun = absolute.to_noun();
                let relative_noun = relative.to_noun();
                Noun::list(&[absolute_noun, relative_noun])
            }
        }
    }
}

impl ToNoun for PublicKey {
    fn to_noun(&self) -> Noun {
        let point = self.as_point();
        let x = point
            .x
            .0
            .iter()
            .map(|belt| Noun::atom_u64(belt.0))
            .collect::<Vec<_>>();
        let y = point
            .y
            .0
            .iter()
            .map(|belt| Noun::atom_u64(belt.0))
            .collect::<Vec<_>>();
        let inf = point.inf.to_noun();
        Noun::list(&[Noun::list(&x), Noun::list(&y), inf])
    }
}

impl ToNoun for Signature {
    fn to_noun(&self) -> Noun {
        /// Converts an 8-word array to an 8-tuple without null terminator.
        /// Produces [w0 [w1 [w2 [w3 [w4 [w5 [w6 w7]]]]]]]
        fn words_to_tuple(words: &[u32; 8]) -> Noun {
            let mut result = Noun::atom_u64(words[7] as u64);
            for &word in words[..7].iter().rev() {
                result = Noun::cons(Noun::atom_u64(word as u64), result);
            }
            result
        }

        let challenge_tuple = words_to_tuple(&self.challenge_words32());
        let response_tuple = words_to_tuple(&self.response_words32());
        // Signature is a cell [challenge response], not a list
        Noun::cons(challenge_tuple, response_tuple)
    }
}
