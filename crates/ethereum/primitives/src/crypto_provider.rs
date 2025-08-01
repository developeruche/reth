use alloy_consensus::crypto::{secp256k1::public_key_to_address, CryptoProvider, RecoveryError};
use alloy_primitives::Address;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};

/// RETH crypto backend provider
#[derive(Debug, Clone)]
pub struct RethCryptoProvider;

impl CryptoProvider for RethCryptoProvider {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let sig = RecoverableSignature::from_compact(
            &sig[0..64],
            RecoveryId::try_from(sig[64] as i32).map_err(|_| RecoveryError::new())?,
        )
        .map_err(|_| RecoveryError::new())?;

        let public = SECP256K1
            .recover_ecdsa(&Message::from_digest(*msg), &sig)
            .map_err(|_| RecoveryError::new())?;
        Ok(public_key_to_address(public))
    }
}
