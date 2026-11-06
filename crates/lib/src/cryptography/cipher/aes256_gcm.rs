use aes_gcm::{aes::Aes256, AeadCore, AeadInOut, Aes256Gcm, AesGcm, Key, KeyInit};
use hybrid_array::{typenum::U32, Array, ArraySize};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AES256GCM;

impl AES256GCM {
    pub fn cipher(data_key: &DataKey) -> AesGcm<Aes256, <Self as Cipher>::NonceSize, <Self as Cipher>::AuthorizationTagSize> {
        let key = Key::<Aes256Gcm>::try_from(data_key.as_ref()).expect("data key length matches the AES-256 key size");
        AesGcm::new(&key)
    }
}

fn aes_nonce<T: ArraySize>(nonce: &Nonce<T>) -> &Array<u8, T> {
    <&Array<u8, T>>::try_from(nonce.as_ref()).expect("nonce length matches the AES-GCM nonce size")
}

impl Cipher for AES256GCM {
    const NAME: &'static str = "AES256_GCM";

    type NonceSize = U32;

    type AuthorizationTagSize = <Aes256Gcm as AeadCore>::TagSize;

    type Error = aes_gcm::Error;

    fn encrypt(
        nonce: &Nonce<Self::NonceSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::Error> {
        Self::cipher(data_key)
            .encrypt_inout_detached(aes_nonce(nonce), associated_data, in_place_buffer.into())
            .map(Into::into)
    }

    fn decrypt(
        nonce: &Nonce<Self::NonceSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
        authorization_tag: &AuthorizationTag<Self>,
    ) -> Result<(), Self::Error> {
        Self::cipher(data_key).decrypt_inout_detached(
            aes_nonce(nonce),
            associated_data,
            in_place_buffer.into(),
            authorization_tag.as_ref(),
        )
    }
}
