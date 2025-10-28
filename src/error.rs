use core::fmt;

/// Errors that can occur while constructing or signing transactions.
#[derive(Debug)]
pub enum TxError {
    Schnorr(nockchain_schnorr_rust::SchnorrError),
    Invalid(&'static str),
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxError::Schnorr(err) => write!(f, "schnorr error: {err}"),
            TxError::Invalid(message) => write!(f, "invalid transaction: {message}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxError {}

impl From<nockchain_schnorr_rust::SchnorrError> for TxError {
    fn from(value: nockchain_schnorr_rust::SchnorrError) -> Self {
        TxError::Schnorr(value)
    }
}
