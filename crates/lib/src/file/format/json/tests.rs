use std::fmt::Display;

use crate::*;

impl FileFormatTestSuiteUtils for JsonFileFormat {
    fn simple_map(key: impl Display, value: impl Display) -> String {
        format!("{{\"{key}\":{value}}}")
    }
}

generate_file_format_test_suite!(JsonFileFormat);

#[cfg(feature = "test-utils")]
mod coverage {
    use serde_json::{Map, Number, Value};

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

    fn map_of(json: &str) -> Map<String, Value> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn decrypted_nested_errors() {
        let object = map_of(r#"{"outer":{"n":18446744073709551615}}"#);
        assert!(RopsFileFormatMap::<DecryptedMap, JsonFileFormat>::from_inner_map(object)
            .to_internal()
            .is_err());

        let array = map_of(r#"{"items":[18446744073709551615]}"#);
        assert!(RopsFileFormatMap::<DecryptedMap, JsonFileFormat>::from_inner_map(array)
            .to_internal()
            .is_err());
    }

    #[test]
    fn encrypted_escape_and_parse_errors() {
        let escaped_bool = Value::Bool(true).encrypted_to_internal::<StubCipher>(escape_true()).unwrap();
        assert!(matches!(
            escaped_bool,
            RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Boolean(true)))
        ));

        let escaped_number = Value::Number(Number::from(12))
            .encrypted_to_internal::<StubCipher>(escape_true())
            .unwrap();
        assert!(matches!(escaped_number, RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(_))));

        assert!(Value::Number(Number::from(u64::MAX))
            .encrypted_to_internal::<StubCipher>(escape_true())
            .is_err());
        assert!(Value::String("not-an-enc-value".to_string())
            .encrypted_to_internal::<StubCipher>(escape_false())
            .is_err());
        assert!(matches!(
            Value::String("plain".to_string())
                .encrypted_to_internal::<StubCipher>(escape_true())
                .unwrap(),
            RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(_))
        ));
        assert!(matches!(
            Value::Null.encrypted_to_internal::<StubCipher>(escape_false()).unwrap(),
            RopsTree::Null
        ));

        let nested = map_of(r#"{"outer":{"flag":true}}"#);
        assert!(
            RopsFileFormatMap::<EncryptedMap<StubCipher>, JsonFileFormat>::from_inner_map(nested)
                .to_internal(None)
                .is_err()
        );

        let sequence = map_of(r#"{"items":[true]}"#);
        assert!(
            RopsFileFormatMap::<EncryptedMap<StubCipher>, JsonFileFormat>::from_inner_map(sequence)
                .to_internal(None)
                .is_err()
        );
    }
}
