use std::fmt::Debug;

use indexmap::IndexMap;
use serde::{de::DeserializeOwned, Serialize};

use crate::*;

pub trait FileFormatKeyAdapter {
    /// Only strings are allowed to be keys.
    fn validate(self) -> Result<String, FormatToInternalMapError>;

    fn from_internal(key: String) -> Self;
}

impl FileFormatKeyAdapter for String {
    fn validate(self) -> Result<String, FormatToInternalMapError> {
        Ok(self)
    }

    fn from_internal(key: String) -> Self {
        key
    }
}

pub trait FileFormatValueAdapter {
    fn decrypted_to_internal(self) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError>;

    fn decrypted_from_internal(rops_tree: RopsTree<DecryptedMap>) -> Self;

    fn encrypted_to_internal<C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncryption,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError>;

    fn encrypted_from_internal<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self;
}

pub trait FileFormatMapAdapter: Sized + Serialize + DeserializeOwned + PartialEq + Debug
where
    Self: IntoIterator<Item = (Self::Key, Self::Value)>,
{
    type Key: FileFormatKeyAdapter;
    type Value: FileFormatValueAdapter;

    fn with_capacity(capacity: usize) -> Self;

    fn insert(&mut self, key: Self::Key, value: Self::Value);

    fn decrypted_to_internal(self) -> Result<RopsMap<DecryptedMap>, FormatToInternalMapError> {
        let mut tree_map = IndexMap::default();

        for (format_key, format_value) in self {
            let key_string = format_key.validate()?;
            tree_map.insert(key_string, Self::Value::decrypted_to_internal(format_value)?);
        }

        Ok(tree_map.into())
    }

    fn decrypted_from_internal(rops_map: RopsMap<DecryptedMap>) -> Self {
        let mut format_map = Self::with_capacity(rops_map.len());

        for (key, value) in rops_map.0 {
            format_map.insert(Self::Key::from_internal(key), Self::Value::decrypted_from_internal(value));
        }

        format_map
    }

    fn encrypted_to_internal<F, C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncryption,
        recursive_value_fn: F,
    ) -> Result<RopsMap<EncryptedMap<C>>, FormatToInternalMapError>
    where
        F: Fn(Self::Value, ResolvedPartialEncryption) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError>,
    {
        let mut tree_map = IndexMap::default();

        for (format_key, format_value) in self {
            let key_string = format_key.validate()?;
            let mut resolved_partial_encryption = resolved_partial_encryption;

            if let ResolvedPartialEncryption::No(partial_encryption_config) = resolved_partial_encryption {
                resolved_partial_encryption = partial_encryption_config.resolve(&key_string);
            }

            tree_map.insert(key_string, recursive_value_fn(format_value, resolved_partial_encryption)?);
        }

        Ok(tree_map.into())
    }

    fn encrypted_from_internal<C: Cipher>(internal_map: RopsMap<EncryptedMap<C>>) -> Self {
        let mut format_map = Self::with_capacity(internal_map.len());

        for (key, tree) in internal_map.0 {
            format_map.insert(Self::Key::from_internal(key), Self::Value::encrypted_from_internal(tree));
        }

        format_map
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use std::{
        cell::Cell,
        hash::{Hash, Hasher},
    };

    use indexmap::IndexMap;
    use serde::{Deserialize, Serialize};

    use super::{FileFormatKeyAdapter, FileFormatMapAdapter, FileFormatValueAdapter};
    use crate::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct BadKey;

    impl Hash for BadKey {
        fn hash<H: Hasher>(&self, _state: &mut H) {}
    }

    thread_local! {
        static KEY_IS_VALID: Cell<bool> = const { Cell::new(false) };
        static VALUE_FN_FAILS: Cell<bool> = const { Cell::new(false) };
        static DECRYPTED_VALUE_FAILS: Cell<bool> = const { Cell::new(false) };
    }

    impl FileFormatKeyAdapter for BadKey {
        fn validate(self) -> Result<String, FormatToInternalMapError> {
            if KEY_IS_VALID.with(|flag| flag.get()) {
                return Ok("key".to_string());
            }
            Err(FormatToInternalMapError::NonStringKey("bad".to_string()))
        }

        fn from_internal(_key: String) -> Self {
            BadKey
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct BadValue;

    impl FileFormatValueAdapter for BadValue {
        fn decrypted_to_internal(self) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
            if DECRYPTED_VALUE_FAILS.with(|flag| flag.get()) {
                return Err(FormatToInternalMapError::NonStringKey("value".to_string()));
            }
            Ok(RopsTree::Null)
        }

        fn decrypted_from_internal(_tree: RopsTree<DecryptedMap>) -> Self {
            BadValue
        }

        fn encrypted_to_internal<C: Cipher>(
            self,
            _resolved_partial_encryption: ResolvedPartialEncryption,
        ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
            Ok(RopsTree::Null)
        }

        fn encrypted_from_internal<C: Cipher>(_tree: RopsTree<EncryptedMap<C>>) -> Self {
            BadValue
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct BadMap(IndexMap<BadKey, BadValue>);

    impl IntoIterator for BadMap {
        type Item = (BadKey, BadValue);
        type IntoIter = indexmap::map::IntoIter<BadKey, BadValue>;

        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl FileFormatMapAdapter for BadMap {
        type Key = BadKey;
        type Value = BadValue;

        fn with_capacity(capacity: usize) -> Self {
            Self(IndexMap::with_capacity(capacity))
        }

        fn insert(&mut self, key: Self::Key, value: Self::Value) {
            self.0.insert(key, value);
        }
    }

    fn convert_value<C: Cipher>(
        value: BadValue,
        resolved: ResolvedPartialEncryption,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
        if VALUE_FN_FAILS.with(|flag| flag.get()) {
            return Err(FormatToInternalMapError::NonStringKey("value".to_string()));
        }
        value.encrypted_to_internal(resolved)
    }

    #[test]
    fn non_string_keys_fail_both_conversions() {
        assert!(convert_value::<AES256GCM>(BadValue, None.into()).is_ok());

        let mut decrypted = BadMap::with_capacity(1);
        decrypted.insert(BadKey, BadValue);
        assert!(decrypted.decrypted_to_internal().is_err());

        let mut encrypted = BadMap::with_capacity(1);
        encrypted.insert(BadKey, BadValue);
        assert!(encrypted.encrypted_to_internal(None.into(), convert_value::<AES256GCM>).is_err());

        let _ = BadKey::from_internal("key".to_string());
        assert!(matches!(BadValue.decrypted_to_internal().unwrap(), RopsTree::Null));
        let _ = BadValue::decrypted_from_internal(RopsTree::Null);
        let _ = BadValue::encrypted_from_internal::<AES256GCM>(RopsTree::Null);
    }

    #[test]
    fn valid_keys_cover_both_conversion_tails() {
        KEY_IS_VALID.with(|flag| flag.set(true));

        let mut decrypted = BadMap::with_capacity(1);
        decrypted.insert(BadKey, BadValue);
        assert!(decrypted.decrypted_to_internal().is_ok());
        assert!(BadMap::with_capacity(0).decrypted_to_internal().is_ok());

        DECRYPTED_VALUE_FAILS.with(|flag| flag.set(true));
        let mut decrypted = BadMap::with_capacity(1);
        decrypted.insert(BadKey, BadValue);
        assert!(decrypted.decrypted_to_internal().is_err());
        DECRYPTED_VALUE_FAILS.with(|flag| flag.set(false));

        let mut encrypted = BadMap::with_capacity(1);
        encrypted.insert(BadKey, BadValue);
        assert!(encrypted.encrypted_to_internal(None.into(), convert_value::<AES256GCM>).is_ok());

        let config = PartialEncryptionConfig::UnencryptedSuffix("zzz".to_string());
        let mut encrypted = BadMap::with_capacity(1);
        encrypted.insert(BadKey, BadValue);
        assert!(encrypted
            .encrypted_to_internal(ResolvedPartialEncryption::No(&config), convert_value::<AES256GCM>)
            .is_ok());

        assert!(BadMap::with_capacity(0)
            .encrypted_to_internal(None.into(), convert_value::<AES256GCM>)
            .is_ok());

        VALUE_FN_FAILS.with(|flag| flag.set(true));
        let mut encrypted = BadMap::with_capacity(1);
        encrypted.insert(BadKey, BadValue);
        assert!(encrypted.encrypted_to_internal(None.into(), convert_value::<AES256GCM>).is_err());

        KEY_IS_VALID.with(|flag| flag.set(false));
        VALUE_FN_FAILS.with(|flag| flag.set(false));
    }
}
