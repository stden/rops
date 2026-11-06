use derive_more::{AsMut, AsRef};
use hybrid_array::{
    typenum::{Unsigned, U32},
    Array,
};
use zeroize::Zeroize;

use crate::*;

type DataKeySize = U32;

#[derive(Debug, PartialEq, AsRef, AsMut)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct DataKey(RngKey<DataKeySize>);

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0 .0.zeroize()
    }
}

impl DataKey {
    pub const fn byte_size() -> usize {
        DataKeySize::USIZE
    }

    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        DataKey(RngKey::new())
    }

    pub fn empty() -> Self {
        Self(RngKey::empty())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid data key size, expected {0}, got {1}")]
pub struct DataKeySizeError(usize, usize);

impl TryFrom<Vec<u8>> for DataKey {
    type Error = DataKeySizeError;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        if vec.len() != DataKey::byte_size() {
            return Err(DataKeySizeError(DataKey::byte_size(), vec.len()));
        }

        let array = Array::try_from_iter(vec).expect("invalid data key size assertion");
        Ok(Self(RngKey(array)))
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use hybrid_array::Array;

    use crate::*;

    impl MockTestUtil for DataKey {
        fn mock() -> Self {
            Self(RngKey(Array::from([
                254, 79, 93, 103, 195, 165, 169, 238, 35, 187, 236, 95, 222, 243, 40, 26, 130, 128, 59, 176, 15, 195, 55, 93, 129, 212, 57,
                80, 15, 181, 72, 114,
            ])))
        }
    }
}
