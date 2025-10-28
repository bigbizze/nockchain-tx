#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::vec::Vec;

use nockchain_schnorr_rust::{derive_public_key, sign_digest, SecretKey};

use crate::error::TxError;
use crate::hash::spend_sig_hash;
use crate::noun::{digest_to_noun, Noun};
use crate::types::{HashDigest, Lock, SchnorrSignatureEntry, Source, TimeLockIntent};
use crate::zset::ToNoun;

/// Simplified view of a note for constructing spends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleNote {
    pub assets: u64,
    pub parent_hash: HashDigest,
    pub lock: Lock,
}

impl SimpleNote {
    pub fn new(assets: u64, parent_hash: HashDigest, lock: Lock) -> Self {
        Self {
            assets,
            parent_hash,
            lock,
        }
    }
}

/// Seed describing how value from an input note is distributed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    pub output_source: Option<Source>,
    pub recipient: Lock,
    pub timelock_intent: Option<TimeLockIntent>,
    pub gift: u64,
    pub parent_hash: HashDigest,
}

impl Seed {
    pub fn new(
        output_source: Option<Source>,
        recipient: Lock,
        timelock_intent: Option<TimeLockIntent>,
        gift: u64,
        parent_hash: HashDigest,
    ) -> Self {
        Self {
            output_source,
            recipient,
            timelock_intent,
            gift,
            parent_hash,
        }
    }

    pub fn simple(recipient: Lock, gift: u64, parent_hash: HashDigest) -> Self {
        Self::new(None, recipient, None, gift, parent_hash)
    }

    pub fn from_note(recipient: Lock, note: &SimpleNote) -> Self {
        Self::simple(recipient, note.assets, note.parent_hash)
    }
}

impl ToNoun for Seed {
    fn to_noun(&self) -> Noun {
        let output = self.output_source.to_noun();
        let recipient = self.recipient.to_noun();
        let timelock = self.timelock_intent.to_noun();
        let gift = Noun::atom_u64(self.gift);
        let parent_hash = digest_to_noun(&self.parent_hash);
        Noun::list(&[output, recipient, timelock, gift, parent_hash])
    }
}

/// Signature witness map keyed by hashed public key.
pub type Witness = BTreeMap<Vec<u8>, SchnorrSignatureEntry>;

/// Spend wrapper for v0 transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    seeds: Vec<Seed>,
    fee: u64,
    signatures: Witness,
}

impl Spend {
    pub fn new(seeds: Vec<Seed>, fee: u64) -> Result<Self, TxError> {
        if seeds.is_empty() {
            return Err(TxError::Invalid("spend must include at least one seed"));
        }
        Ok(Self {
            seeds,
            fee,
            signatures: Witness::new(),
        })
    }

    pub fn seeds(&self) -> &[Seed] {
        &self.seeds
    }

    pub fn fee(&self) -> u64 {
        self.fee
    }

    pub fn signatures(&self) -> impl Iterator<Item = &SchnorrSignatureEntry> {
        self.signatures.values()
    }

    pub fn signatures_mut(
        &mut self,
    ) -> impl Iterator<Item = (&Vec<u8>, &mut SchnorrSignatureEntry)> {
        self.signatures.iter_mut()
    }

    pub fn add_signature(&mut self, entry: SchnorrSignatureEntry) {
        let key_bytes = entry.public_key.to_bytes().to_vec();
        self.signatures.insert(key_bytes, entry);
    }

    pub fn sign(&mut self, secret_key: &SecretKey) -> Result<(), TxError> {
        let public_key = derive_public_key(secret_key)?;
        let message = self.sig_hash();
        let signature = sign_digest(secret_key, &message)?;
        self.add_signature(SchnorrSignatureEntry::new(public_key, signature));
        Ok(())
    }

    pub fn sig_hash(&self) -> HashDigest {
        spend_sig_hash(&self.seeds, self.fee)
    }

    pub fn simple_from_note(recipient: Lock, note: &SimpleNote, fee: u64) -> Result<Self, TxError> {
        if fee > note.assets {
            return Err(TxError::Invalid("fee exceeds note assets"));
        }
        let gift = note
            .assets
            .checked_sub(fee)
            .ok_or(TxError::Invalid("insufficient assets for fee"))?;
        let seed = Seed::simple(recipient, gift, note.parent_hash);
        Self::new(vec![seed], fee)
    }

    pub fn simple_from_note_with_refund(
        recipient: Lock,
        refund: Lock,
        note: &SimpleNote,
        gift: u64,
        fee: u64,
    ) -> Result<Self, TxError> {
        let total = gift
            .checked_add(fee)
            .ok_or(TxError::Invalid("gift + fee overflow"))?;
        if total > note.assets {
            return Err(TxError::Invalid("insufficient note assets"));
        }
        let refund_amount = note.assets - total;
        let mut seeds = vec![Seed::simple(recipient, gift, note.parent_hash)];
        if refund_amount > 0 {
            seeds.push(Seed::simple(refund, refund_amount, note.parent_hash));
        }
        Self::new(seeds, fee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nockchain_schnorr_rust::SecretKey;

    fn sample_secret_key() -> SecretKey {
        let bytes = [
            0x1c, 0x15, 0x33, 0x08, 0xa4, 0x97, 0x42, 0x0f, 0xd1, 0x5e, 0x6f, 0x0b, 0x92, 0x8c,
            0xa7, 0x11, 0x6e, 0xb8, 0x32, 0x5c, 0x42, 0xa6, 0x7f, 0x55, 0x3a, 0x62, 0xfa, 0x0c,
            0x19, 0x41, 0x6d, 0x01,
        ];
        SecretKey::from_bytes_le(bytes).expect("valid secret key")
    }

    #[test]
    fn sign_simple_spend() {
        let secret = sample_secret_key();
        let public = secret.public_key().unwrap();
        let recipient_lock = Lock::single(public.clone());
        let note_lock = Lock::single(public.clone());
        let note = SimpleNote::new(5_000, [1, 2, 3, 4, 5], note_lock);
        let mut spend =
            Spend::simple_from_note(recipient_lock, &note, 500).expect("spend construction");
        let digest_before = spend.sig_hash();
        spend.sign(&secret).expect("sign");
        let digest_after = spend.sig_hash();
        assert_eq!(digest_before, digest_after);
        assert_eq!(spend.signatures().count(), 1);
    }
}
