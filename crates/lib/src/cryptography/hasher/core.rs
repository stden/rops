use hybrid_array::{Array, ArraySize};

pub trait Hasher: private::SealedHasher {
    type OutputSize: ArraySize;

    fn new() -> Self;

    fn update(&mut self, input: impl AsRef<[u8]>);

    fn finalize(self) -> Array<u8, Self::OutputSize>;
}

mod private {
    pub trait SealedHasher {}

    #[cfg(feature = "sha2")]
    impl SealedHasher for crate::SHA512 {}
}
