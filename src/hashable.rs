use crate::noun::{hash_noun, hash_pair, Noun};
use crate::tip::Tip5Digest;
use crate::types::{Lock, Source, TimeLockIntent, TimelockRange};
use crate::v0::Seed;
use crate::zset::{Node, ToNoun, ZSet};
use nockchain_schnorr_rust::PublicKey;

#[derive(Clone)]
enum Hashable {
    Leaf(Noun),
    Hash(Tip5Digest),
    Pair(Box<Hashable>, Box<Hashable>),
}

impl Hashable {
    fn leaf(noun: Noun) -> Self {
        Hashable::Leaf(noun)
    }

    fn hash(digest: Tip5Digest) -> Self {
        Hashable::Hash(digest)
    }

    fn pair(left: Hashable, right: Hashable) -> Self {
        Hashable::Pair(Box::new(left), Box::new(right))
    }
}

fn hash_hashable(value: &Hashable) -> Tip5Digest {
    match value {
        Hashable::Leaf(noun) => hash_noun(noun),
        Hashable::Hash(digest) => *digest,
        Hashable::Pair(left, right) => {
            let left_digest = hash_hashable(left);
            let right_digest = hash_hashable(right);
            hash_pair(&left_digest, &right_digest)
        }
    }
}

fn hashable_timelock_range(range: &TimelockRange) -> Hashable {
    let min_hashable = match range.min {
        None => Hashable::leaf(Noun::zero()),
        Some(value) => Hashable::pair(
            Hashable::leaf(Noun::zero()),
            Hashable::leaf(Noun::atom_u64(value)),
        ),
    };

    let max_hashable = match range.max {
        None => Hashable::leaf(Noun::zero()),
        Some(value) => Hashable::pair(
            Hashable::leaf(Noun::zero()),
            Hashable::leaf(Noun::atom_u64(value)),
        ),
    };

    Hashable::pair(min_hashable, max_hashable)
}

fn hashable_timelock_intent(intent: &TimeLockIntent) -> Hashable {
    match intent.as_ranges() {
        None => Hashable::leaf(Noun::zero()),
        Some((absolute, relative)) => {
            let absolute_hashable = hashable_timelock_range(&absolute);
            let relative_hashable = hashable_timelock_range(&relative);
            Hashable::pair(
                Hashable::leaf(Noun::zero()),
                Hashable::pair(absolute_hashable, relative_hashable),
            )
        }
    }
}

fn hashable_source(source: &Source) -> Hashable {
    let digest = Hashable::hash(source.hash);
    let coinbase = Hashable::leaf(source.coinbase.to_noun());
    Hashable::pair(digest, coinbase)
}

fn hashable_unit_source(source: &Option<Source>) -> Hashable {
    match source {
        None => Hashable::leaf(Noun::zero()),
        Some(src) => Hashable::pair(Hashable::leaf(Noun::zero()), hashable_source(src)),
    }
}

fn hashable_pubkeys(node: Option<&Box<Node<PublicKey>>>) -> Hashable {
    match node {
        None => Hashable::leaf(Noun::zero()),
        Some(node) => {
            let digest = hash_noun(&node.value.to_noun());
            let left = hashable_pubkeys(node.left.as_ref());
            let right = hashable_pubkeys(node.right.as_ref());
            Hashable::pair(Hashable::hash(digest), Hashable::pair(left, right))
        }
    }
}

fn hashable_lock(lock: &Lock) -> Hashable {
    let required = Hashable::leaf(Noun::atom_u64(lock.keys_required as u64));
    let pubkey_zset: ZSet<PublicKey> = lock.public_keys.iter().cloned().collect();
    let pubkeys = hashable_pubkeys(pubkey_zset.root());
    Hashable::pair(required, pubkeys)
}

fn hashable_seed(seed: &Seed) -> Hashable {
    let source = hashable_unit_source(&seed.output_source);
    let recipient = hashable_lock(&seed.recipient);
    let timelock = match &seed.timelock_intent {
        Some(intent) => hashable_timelock_intent(intent),
        None => Hashable::leaf(Noun::zero()),
    };
    let gift = Hashable::leaf(Noun::atom_u64(seed.gift));
    let parent_hash = Hashable::hash(seed.parent_hash);

    Hashable::pair(
        source,
        Hashable::pair(
            recipient,
            Hashable::pair(timelock, Hashable::pair(gift, parent_hash)),
        ),
    )
}

fn hashable_seeds(node: Option<&Box<Node<Seed>>>) -> Hashable {
    match node {
        None => Hashable::leaf(Noun::zero()),
        Some(node) => {
            let current = hashable_seed(&node.value);
            let left = hashable_seeds(node.left.as_ref());
            let right = hashable_seeds(node.right.as_ref());
            Hashable::pair(current, Hashable::pair(left, right))
        }
    }
}

pub fn compute_sig_hash(seeds: &[Seed], fee: u64) -> Tip5Digest {
    let seed_tree: ZSet<Seed> = seeds.iter().cloned().collect();
    let seeds_hashable = hashable_seeds(seed_tree.root());
    let fee_hashable = Hashable::leaf(Noun::atom_u64(fee));
    let combined = Hashable::pair(seeds_hashable, fee_hashable);
    hash_hashable(&combined)
}
