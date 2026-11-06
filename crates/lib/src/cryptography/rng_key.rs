use derive_more::{AsMut, AsRef};
use hybrid_array::{Array, ArraySize};
use rand::Rng;

// IMPROVEMENT: replace with generic array
#[derive(Debug, Clone, PartialEq, AsRef, AsMut)]
#[as_ref(forward)]
pub struct RngKey<T: ArraySize>(pub(crate) Array<u8, T>);

impl<T: ArraySize> RngKey<T> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Assumed to be cryptographically secure. Uses ChaCha12 as
        // the PRNG with OS provided RNG (e.g getrandom) for the
        // initial seed.
        //
        // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
        let mut rand = rand::rng();

        let mut inner = Array::default();
        rand.fill_bytes(&mut inner);
        Self(inner)
    }

    pub fn empty() -> Self {
        Self(Array::default())
    }
}

#[cfg(test)]
mod tests {
    use hybrid_array::typenum::Unsigned;

    use super::*;

    type MockArrayLength = hybrid_array::typenum::U32;
    type MockRngKey = RngKey<MockArrayLength>;

    #[test]
    fn new_rng_key_not_zeroed() {
        assert_ne!(&[0; MockArrayLength::USIZE], MockRngKey::new().0.as_slice())
    }

    #[test]
    fn new_rng_key_seems_random() {
        assert_ne!(MockRngKey::new(), MockRngKey::new())
    }
}
