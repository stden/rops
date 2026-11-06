use std::fmt::Display;

use crate::*;

impl FileFormatTestSuiteUtils for YamlFileFormat {
    fn simple_map(key: impl Display, value: impl Display) -> String {
        format!("{key}: {value}")
    }
}

generate_file_format_test_suite!(YamlFileFormat);

#[test]
fn plain_integer_key_deserializes_as_string() {
    // noyalib's string-keyed mapping reads a plain `123` key as `"123"`.
    let from_plain = YamlFileFormat::key_value_map::<DecryptedMap>(123, "xxx").to_internal().unwrap();
    let from_quoted = YamlFileFormat::key_value_map::<DecryptedMap>(r#""123""#, "xxx")
        .to_internal()
        .unwrap();
    assert_eq!(from_plain, from_quoted);
}

#[test]
fn non_scalar_key_is_rejected() {
    let parsed = YamlFileFormat::deserialize_from_str::<serde_yaml::Mapping>("? [1, 2]\n: xxx\n");
    assert!(parsed.is_err(), "a sequence key must not become a string map entry");
}

#[cfg(feature = "test-utils")]
mod coverage {
    use serde::Serialize;
    use serde_yaml::Value;

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

    #[test]
    fn serialize_reports_serializer_errors() {
        struct Boom;
        impl Serialize for Boom {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        assert!(YamlFileFormat::serialize_to_string(&Boom).is_err());

        struct Toggle(std::cell::Cell<bool>);
        impl Serialize for Toggle {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if self.0.replace(false) {
                    return Err(serde::ser::Error::custom("toggle"));
                }
                serializer.serialize_unit()
            }
        }
        let toggle = Toggle(std::cell::Cell::new(true));
        assert!(YamlFileFormat::serialize_to_string(&toggle).is_err());
        assert!(YamlFileFormat::serialize_to_string(&toggle).is_ok());
        assert_eq!("a\n", super::super::ensure_trailing_newline("a".to_string()));
        assert_eq!("a\n", super::super::ensure_trailing_newline("a\n".to_string()));
    }

    #[test]
    fn tagged_nested_and_escaped_values() {
        let tagged_bool = serde_yaml::from_str::<Value>("!tag true").unwrap();
        assert!(tagged_bool.decrypted_to_internal().is_ok());

        let tagged_document = "!tag\nn: 18446744073709551615\n";
        assert!(serde_yaml::from_str::<Value>(tagged_document)
            .unwrap()
            .decrypted_to_internal()
            .is_err());
        assert!(serde_yaml::from_str::<Value>(tagged_document)
            .unwrap()
            .encrypted_to_internal::<StubCipher>(escape_true())
            .is_err());

        let nested = serde_yaml::from_str::<serde_yaml::Mapping>("outer:\n  n: 18446744073709551615\n").unwrap();
        assert!(RopsFileFormatMap::<DecryptedMap, YamlFileFormat>::from_inner_map(nested)
            .to_internal()
            .is_err());

        let sequence = serde_yaml::from_str::<serde_yaml::Mapping>("items:\n- 18446744073709551615\n").unwrap();
        assert!(RopsFileFormatMap::<DecryptedMap, YamlFileFormat>::from_inner_map(sequence)
            .to_internal()
            .is_err());

        assert!(Value::Bool(true).encrypted_to_internal::<StubCipher>(escape_true()).is_ok());
        assert!(matches!(
            Value::String("plain".into())
                .encrypted_to_internal::<StubCipher>(escape_true())
                .unwrap(),
            RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(_))
        ));
        assert!(matches!(
            Value::Null.encrypted_to_internal::<StubCipher>(escape_false()).unwrap(),
            RopsTree::Null
        ));
        assert!(Value::String("not-an-enc-value".into())
            .encrypted_to_internal::<StubCipher>(escape_false())
            .is_err());

        let encrypted_nested = serde_yaml::from_str::<serde_yaml::Mapping>("outer:\n  flag: true\n").unwrap();
        assert!(
            RopsFileFormatMap::<EncryptedMap<StubCipher>, YamlFileFormat>::from_inner_map(encrypted_nested)
                .to_internal(None)
                .is_err()
        );

        let encrypted_sequence = serde_yaml::from_str::<serde_yaml::Mapping>("items:\n- true\n").unwrap();
        assert!(
            RopsFileFormatMap::<EncryptedMap<StubCipher>, YamlFileFormat>::from_inner_map(encrypted_sequence)
                .to_internal(None)
                .is_err()
        );
    }
}
