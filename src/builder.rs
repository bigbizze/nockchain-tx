#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use nockchain_schnorr_rust::SecretKey;

use crate::error::TxError;
use crate::v0::{Seed, Spend};

/// Helper for assembling simple spends programmatically.
#[derive(Default)]
pub struct TransactionBuilder {
    seeds: Vec<Seed>,
    fee: u64,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    pub fn add_seed(mut self, seed: Seed) -> Self {
        self.seeds.push(seed);
        self
    }

    pub fn add_seed_ref(&mut self, seed: Seed) {
        self.seeds.push(seed);
    }

    pub fn build_v0(self) -> Result<Spend, TxError> {
        Spend::new(self.seeds, self.fee)
    }

    pub fn sign_v0(self, secret: &SecretKey) -> Result<Spend, TxError> {
        let mut spend = self.build_v0()?;
        spend.sign(secret)?;
        Ok(spend)
    }
}
