use std::fmt::Display;

use crate::*;

impl FileFormatTestSuiteUtils for TomlFileFormat {
    fn simple_map(key: impl Display, value: impl Display) -> String {
        format!("{key} = {value}")
    }
}

generate_file_format_test_suite!(TomlFileFormat);

#[cfg(feature = "test-utils")]
mod coverage {
    use toml::Value;

    use super::*;

    fn escape_true() -> ResolvedPartialEncryption<'static> {
        match PartialEncryptionConfig::UnencryptedSuffix(String::new()).resolve("key") {
            ResolvedPartialEncryption::Yes(escape) => ResolvedPartialEncryption::Yes(escape),
            ResolvedPartialEncryption::No(_) => panic!("empty suffix matches every key"),
        }
    }

    fn escape_false() -> ResolvedPartialEncryption<'static> {
        None.into()
    }

    fn datetime() -> Value {
        Value::Datetime("1979-05-27T07:32:00Z".parse().unwrap())
    }

    #[test]
    fn decrypted_datetime_and_nested_errors() {
        assert!(matches!(
            datetime().decrypted_to_internal().unwrap(),
            RopsTree::Leaf(RopsValue::String(_))
        ));

        let table = toml::from_str::<toml::Table>("outer = { name = \"x\" }").unwrap();
        assert!(RopsFileFormatMap::<DecryptedMap, TomlFileFormat>::from_inner_map(table)
            .to_internal()
            .is_ok());

        let array = toml::from_str::<toml::Table>("items = [\"x\"]").unwrap();
        assert!(RopsFileFormatMap::<DecryptedMap, TomlFileFormat>::from_inner_map(array)
            .to_internal()
            .is_ok());
    }

    #[test]
    fn encrypted_scalars_escape_or_reject_plaintext() {
        assert!(Value::Boolean(true).encrypted_to_internal::<StubCipher>(escape_true()).is_ok());
        assert!(Value::Integer(7).encrypted_to_internal::<StubCipher>(escape_true()).is_ok());
        assert!(Value::Float(1.5).encrypted_to_internal::<StubCipher>(escape_true()).is_ok());
        assert!(Value::Float(1.5).encrypted_to_internal::<StubCipher>(escape_false()).is_err());
        assert!(datetime().encrypted_to_internal::<StubCipher>(escape_true()).is_ok());
        assert!(datetime().encrypted_to_internal::<StubCipher>(escape_false()).is_err());
        assert!(Value::String("not-an-enc-value".into())
            .encrypted_to_internal::<StubCipher>(escape_false())
            .is_err());
        assert!(matches!(
            Value::String("plain".into())
                .encrypted_to_internal::<StubCipher>(escape_true())
                .unwrap(),
            RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(_))
        ));
        assert!(matches!(
            Value::String("null".into())
                .encrypted_to_internal::<StubCipher>(escape_false())
                .unwrap(),
            RopsTree::Null
        ));

        let table = toml::from_str::<toml::Table>("outer = { flag = true }").unwrap();
        assert!(RopsFileFormatMap::<EncryptedMap<StubCipher>, TomlFileFormat>::from_inner_map(table)
            .to_internal(None)
            .is_err());

        let array = toml::from_str::<toml::Table>("items = [true]").unwrap();
        assert!(RopsFileFormatMap::<EncryptedMap<StubCipher>, TomlFileFormat>::from_inner_map(array)
            .to_internal(None)
            .is_err());
    }
}
