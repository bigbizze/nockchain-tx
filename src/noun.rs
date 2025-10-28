
#![allow(dead_code)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(feature = "std")]
use std::{boxed::Box, vec, vec::Vec};

use core::cmp::Ordering;

use ibig::UBig;

use nockchain_math_core::belt::{Belt, PRIME};

use crate::tip::{hash_noun_varlen, hash_ten_cell, tip_dor_compare, Tip5Digest};

/// Minimal noun representation needed for hashing and ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Noun {
    Atom(UBig),
    Cell(Box<Noun>, Box<Noun>),
}

impl Noun {
    pub fn atom_u64(value: u64) -> Self {
        Noun::Atom(UBig::from(value))
    }

    pub fn atom_bool(value: bool) -> Self {
        if value {
            // %.y == 0
            Noun::zero()
        } else {
            // %.n == 1
            Noun::atom_u64(1)
        }
    }

    pub fn zero() -> Self {
        Noun::Atom(UBig::from(0u8))
    }

    pub fn one() -> Self {
        Noun::Atom(UBig::from(1u8))
    }

    pub fn cons(head: Noun, tail: Noun) -> Self {
        Noun::Cell(Box::new(head), Box::new(tail))
    }

    pub fn list(elements: &[Noun]) -> Self {
        elements
            .iter()
            .rev()
            .fold(Noun::zero(), |acc, item| Noun::cons(item.clone(), acc))
    }

    pub fn take_head(&self) -> Option<&Noun> {
        match self {
            Noun::Cell(head, _) => Some(head),
            _ => None,
        }
    }

    pub fn take_tail(&self) -> Option<&Noun> {
        match self {
            Noun::Cell(_, tail) => Some(tail),
            _ => None,
        }
    }

    pub fn as_atom(&self) -> Option<&UBig> {
        match self {
            Noun::Atom(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_atom_u64(&self) -> Option<u64> {
        self.as_atom().and_then(|value| value.try_into().ok())
    }

    pub fn is_atom(&self) -> bool {
        matches!(self, Noun::Atom(_))
    }

    pub fn equals(&self, other: &Noun) -> bool {
        self == other
    }

    /// Converts the noun to belts suitable for hashing (with TIP-5 mod reduction).
    pub fn to_belts(&self) -> Vec<Belt> {
        match self {
            Noun::Atom(value) => {
                let reduced = (value % PRIME) as u64;
                vec![Belt(reduced)]
            }
            Noun::Cell(head, tail) => {
                let mut belts = Vec::new();
                belts.extend_from_slice(&head.to_belts());
                belts.extend_from_slice(&tail.to_belts());
                belts
            }
        }
    }
}

impl From<u64> for Noun {
    fn from(value: u64) -> Self {
        Noun::atom_u64(value)
    }
}

impl From<bool> for Noun {
    fn from(value: bool) -> Self {
        Noun::atom_bool(value)
    }
}

impl From<&[u64]> for Noun {
    fn from(values: &[u64]) -> Self {
        let atoms: Vec<Noun> = values.iter().map(|v| Noun::atom_u64(*v)).collect();
        Noun::list(&atoms)
    }
}

/// Converts a TIP-5 digest into a noun list.
pub fn digest_to_noun(digest: &Tip5Digest) -> Noun {
    Noun::from(&digest[..])
}

/// Hashes an ordered pair of digests using the TIP-5 ten cell function.
pub fn hash_pair(left: &Tip5Digest, right: &Tip5Digest) -> Tip5Digest {
    hash_ten_cell(left, right)
}

/// Produces the TIP-5 digest for this noun.
pub fn hash_noun(noun: &Noun) -> Tip5Digest {
    hash_noun_varlen(noun)
}

/// Performs the dor-tip comparison between two nouns.
pub fn dor_compare(a: &Noun, b: &Noun) -> Ordering {
    tip_dor_compare(a, b)
}
