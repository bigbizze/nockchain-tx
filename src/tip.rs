#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::cmp::Ordering;
use ibig::UBig;

use nockchain_math_core::belt::{Belt, PRIME};
use nockchain_math_core::tip5::hash::{hash_10, hash_varlen};

use crate::noun::Noun;

pub type Tip5Digest = [u64; 5];

fn collect_leaf_sequence_tail_first(noun: &Noun, acc: &mut Vec<UBig>) {
    match noun {
        Noun::Atom(value) => acc.push(value.clone()),
        Noun::Cell(head, tail) => {
            collect_leaf_sequence_tail_first(tail, acc);
            collect_leaf_sequence_tail_first(head, acc);
        }
    }
}

fn collect_dyck(noun: &Noun, out: &mut Vec<u64>) {
    if noun.is_atom() {
        return;
    }
    if let Noun::Cell(head, tail) = noun {
        out.push(0);
        collect_dyck(head, out);
        out.push(1);
        collect_dyck(tail, out);
    }
}

pub fn hash_noun_varlen(noun: &Noun) -> Tip5Digest {
    let mut leaves = Vec::new();
    collect_leaf_sequence_tail_first(noun, &mut leaves);
    leaves.reverse();

    let mut dyck = Vec::new();
    collect_dyck(noun, &mut dyck);

    let mut belts = Vec::with_capacity(1 + leaves.len() + dyck.len());
    belts.push(Belt((leaves.len() as u64) % PRIME));
    for value in leaves {
        let reduced = (&value % PRIME).try_into().unwrap_or(0);
        belts.push(Belt(reduced));
    }
    for bit in dyck {
        belts.push(Belt(bit % PRIME));
    }
    hash_varlen(&mut belts)
}

pub fn hash_ten_cell(left: &Tip5Digest, right: &Tip5Digest) -> Tip5Digest {
    let mut belts: Vec<Belt> = left
        .iter()
        .chain(right.iter())
        .map(|v| Belt(*v % PRIME))
        .collect();
    hash_10(&mut belts)
}

pub fn tip(noun: &Noun) -> Tip5Digest {
    hash_noun_varlen(noun)
}

pub fn double_tip(noun: &Noun) -> Tip5Digest {
    let first = tip(noun);
    hash_ten_cell(&first, &first)
}

fn digest_to_ubig(digest: &Tip5Digest) -> UBig {
    let mut result = UBig::from(0u64);
    let prime = UBig::from(PRIME);
    for (i, limb) in digest.iter().enumerate() {
        let term = UBig::from(*limb) * prime.pow(i);
        result += term;
    }
    result
}

pub fn lth_tip(a: &Tip5Digest, b: &Tip5Digest) -> bool {
    digest_to_ubig(a) < digest_to_ubig(b)
}

pub fn tip_dor_compare(a: &Noun, b: &Noun) -> Ordering {
    if a.equals(b) {
        return Ordering::Equal;
    }
    match (a, b) {
        (Noun::Atom(av), Noun::Atom(bv)) => {
            if av < bv {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        (Noun::Atom(_), Noun::Cell(_, _)) => Ordering::Greater,
        (Noun::Cell(_, _), Noun::Atom(_)) => Ordering::Less,
        (Noun::Cell(ah, at), Noun::Cell(bh, bt)) => {
            let head_cmp = tip_dor_compare(ah, bh);
            if head_cmp == Ordering::Equal {
                tip_dor_compare(at, bt)
            } else {
                head_cmp
            }
        }
    }
}

pub fn gor_tip(a: &Noun, b: &Noun) -> bool {
    let tip_a = tip(a);
    let tip_b = tip(b);
    if tip_a == tip_b {
        tip_dor_compare(a, b) == core::cmp::Ordering::Less
    } else {
        lth_tip(&tip_a, &tip_b)
    }
}

pub fn mor_tip(a: &Noun, b: &Noun) -> bool {
    let tip_a = double_tip(a);
    let tip_b = double_tip(b);
    if tip_a == tip_b {
        tip_dor_compare(a, b) == core::cmp::Ordering::Less
    } else {
        lth_tip(&tip_a, &tip_b)
    }
}
