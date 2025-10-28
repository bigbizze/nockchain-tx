use crate::hashable::compute_sig_hash;
use crate::tip::Tip5Digest;

pub(crate) fn spend_sig_hash(seeds: &[crate::v0::Seed], fee: u64) -> Tip5Digest {
    compute_sig_hash(seeds, fee)
}
