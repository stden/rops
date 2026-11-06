use hybrid_array::typenum::U32;

use crate::*;

#[allow(dead_code, reason = "marker used in tests")]
#[derive(Debug, PartialEq)]
pub struct StubCipher;

impl Cipher for StubCipher {
    const NAME: &'static str = "STUB";

    type NonceSize = U32;
    type AuthorizationTagSize = U32;
    type Error = StubCipherError;

    fn encrypt(
        _nonce: &Nonce<Self::NonceSize>,
        _data_key: &DataKey,
        _in_place_buffer: &mut [u8],
        _associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::Error> {
        #[cfg(test)]
        if ENCRYPT_SUCCEEDS.with(|flag| flag.get()) {
            return Ok(AuthorizationTag::<Self>::mock());
        }
        Err(StubCipherError)
    }

    fn decrypt(
        _nonce: &Nonce<Self::NonceSize>,
        _data_key: &DataKey,
        _in_place_buffer: &mut [u8],
        _associated_data: &[u8],
        _authorization_tag: &AuthorizationTag<Self>,
    ) -> Result<(), Self::Error> {
        Err(StubCipherError)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StubCipherError;

impl std::fmt::Display for StubCipherError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("stub cipher")
    }
}

impl std::error::Error for StubCipherError {}

#[cfg(test)]
thread_local! {
    static ENCRYPT_SUCCEEDS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Makes `StubCipher::encrypt` return a tag until dropped. The default stays `Err`.
#[cfg(test)]
pub(crate) struct StubEncryptSuccess;

#[cfg(test)]
impl StubEncryptSuccess {
    pub(crate) fn arm() -> Self {
        ENCRYPT_SUCCEEDS.with(|flag| flag.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for StubEncryptSuccess {
    fn drop(&mut self) {
        ENCRYPT_SUCCEEDS.with(|flag| flag.set(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_the_error() {
        assert_eq!("stub cipher", StubCipherError.to_string());
    }

    #[cfg(all(feature = "sha2", feature = "age", feature = "aws-kms"))]
    #[test]
    fn succeeds_and_fails_on_one_instantiation() {
        let data_key = DataKey::mock();
        let value = RopsValue::String("value".to_string());
        let key_path = KeyPath::default();
        let modified = LastModifiedDateTime::mock();

        {
            let _guard = StubEncryptSuccess::arm();
            assert!(value.encrypt::<StubCipher>(Nonce::new(), &data_key, &key_path).is_ok());
            assert!(Mac::<SHA512>::mock().encrypt::<StubCipher>(&data_key, &modified).is_ok());
            let saved = SavedMacNonce::new(Mac::<SHA512>::mock(), Nonce::new());
            assert!(Mac::<SHA512>::mock()
                .encrypt_with_saved_nonce::<StubCipher>(&data_key, &modified, saved)
                .is_ok());
            assert!(RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock()
                .encrypt::<StubCipher>(&data_key)
                .is_ok());
            let saved = SavedMacNonce::new(Mac::<SHA512>::mock(), Nonce::new());
            assert!(RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock()
                .encrypt_with_saved_mac_nonce::<StubCipher>(&data_key, saved)
                .is_ok());
        }

        assert!(value.encrypt::<StubCipher>(Nonce::new(), &data_key, &key_path).is_err());
        assert!(Mac::<SHA512>::mock().encrypt::<StubCipher>(&data_key, &modified).is_err());
        let saved = SavedMacNonce::new(Mac::<SHA512>::mock(), Nonce::new());
        assert!(Mac::<SHA512>::mock()
            .encrypt_with_saved_nonce::<StubCipher>(&data_key, &modified, saved)
            .is_err());
        assert!(RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock()
            .encrypt::<StubCipher>(&data_key)
            .is_err());
        let saved = SavedMacNonce::new(Mac::<SHA512>::mock(), Nonce::new());
        assert!(RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock()
            .encrypt_with_saved_mac_nonce::<StubCipher>(&data_key, saved)
            .is_err());
    }
}
