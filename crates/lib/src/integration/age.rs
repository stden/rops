use std::io::{Read, Write};

use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    Decryptor, Recipient,
};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AgeIntegration;

impl AgeIntegration {
    const APPROX_MAX_ARMORED_DATA_KEY_LENGTH: usize = 400;
}

impl Integration for AgeIntegration {
    const NAME: &'static str = "age";
    type KeyId = age::x25519::Recipient;
    type PrivateKey = age::x25519::Identity;
    type Config = AgeConfig;

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId> {
        key_id_str
            .parse()
            .map_err(|err: &str| IntegrationError::KeyIdParsing(anyhow::anyhow!(err)))
    }

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
        private_key_str
            .as_ref()
            .parse()
            .map_err(|err: &str| IntegrationError::PrivateKeyParsing(anyhow::anyhow!(err)))
    }

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String> {
        // IMPROVEMENT: avoid vec box allocation
        let encryptor =
            age::Encryptor::with_recipients([key_id as &dyn Recipient].into_iter()).expect("provided recipients should be non-empty");

        let unarmored = seal_unarmored(encryptor, data_key.as_ref())?;
        let armored = seal_armored(&unarmored)?;
        Ok(String::from_utf8(armored)?)
    }

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
        let private_keys = Self::retrieve_private_keys()?;

        let Some(matched_private_key) = private_keys.into_iter().find(|private_key| &private_key.to_public() == key_id) else {
            return Ok(None);
        };

        let mut unarmored_encrypted_buffer = Vec::with_capacity(Self::APPROX_MAX_ARMORED_DATA_KEY_LENGTH);

        ArmoredReader::new(encrypted_data_key.as_bytes()).read_to_end(&mut unarmored_encrypted_buffer)?;

        let decryptor = Decryptor::new(unarmored_encrypted_buffer.as_slice())?;

        let mut decrypted_data_key_buffer = DataKey::empty();
        let mut reader = decryptor.decrypt(std::iter::once(&matched_private_key as &dyn age::Identity))?;
        reader.read_exact(decrypted_data_key_buffer.as_mut())?;

        Ok(Some(decrypted_data_key_buffer))
    }

    fn select_metadata_units(integration_metadata: &mut IntegrationMetadata) -> &mut IntegrationMetadataUnits<Self> {
        &mut integration_metadata.age
    }
}

#[cfg_attr(test, inline(never))]
fn seal<W: Write>(encryptor: age::Encryptor, output: &mut W, plaintext: &[u8]) -> IntegrationResult<()> {
    let mut encryption_writer = encryptor.wrap_output(output)?;
    encryption_writer.write_all(plaintext)?;
    // Coverage instrumentation shifts the finish write's index, so tests arm that write directly.
    #[cfg(test)]
    io_fail::arm_finish_write_failure();
    encryption_writer.finish()?;
    Ok(())
}

fn armor<W: Write>(output: &mut W, unarmored: &[u8]) -> IntegrationResult<()> {
    let mut armored_writer = ArmoredWriter::wrap_output(output, Format::AsciiArmor)?;
    // Age buffers the body and only writes it from `finish`. This call cannot fail.
    armored_writer
        .write_all(unarmored)
        .expect("age armor buffers the body until finish");
    armored_writer.finish()?;
    Ok(())
}

fn seal_unarmored(encryptor: age::Encryptor, plaintext: &[u8]) -> IntegrationResult<Vec<u8>> {
    // One `?` for both builds. Profdata merges by source location, so a failure
    // injected in the test build also covers the plain `Vec` build.
    #[cfg(test)]
    let mut output = io_fail::unarmored_buffer(DataKey::byte_size());
    #[cfg(not(test))]
    let mut output = Vec::with_capacity(DataKey::byte_size());

    seal(encryptor, &mut output, plaintext)?;

    #[cfg(test)]
    let output = output.into_vec();
    Ok(output)
}

fn seal_armored(unarmored: &[u8]) -> IntegrationResult<Vec<u8>> {
    #[cfg(test)]
    let mut output = io_fail::armored_buffer(AgeIntegration::APPROX_MAX_ARMORED_DATA_KEY_LENGTH);
    #[cfg(not(test))]
    let mut output = Vec::with_capacity(AgeIntegration::APPROX_MAX_ARMORED_DATA_KEY_LENGTH);

    armor(&mut output, unarmored)?;

    #[cfg(test)]
    let mut output = output.into_vec();
    #[cfg(test)]
    if io_fail::take_poison() {
        output.push(0xff);
    }
    Ok(output)
}

#[cfg(test)]
mod io_fail {
    use std::{
        cell::Cell,
        io::{self, Write},
    };

    thread_local! {
        static FAIL_UNARMORED: Cell<Option<u32>> = const { Cell::new(None) };
        static FAIL_ARMORED: Cell<Option<u32>> = const { Cell::new(None) };
        static POISON_ARMOR: Cell<bool> = const { Cell::new(false) };
        static FAIL_FINISH: Cell<bool> = const { Cell::new(false) };
        static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn fail_finish_write() {
        FAIL_FINISH.with(|flag| flag.set(true));
    }

    pub(super) fn arm_finish_write_failure() {
        if FAIL_FINISH.with(|flag| flag.replace(false)) {
            FAIL_NEXT.with(|flag| flag.set(true));
        }
    }

    pub(super) fn fail_unarmored_write(index: u32) {
        FAIL_UNARMORED.with(|fail| fail.set(Some(index)));
    }

    pub(super) fn fail_armored_write(index: u32) {
        FAIL_ARMORED.with(|fail| fail.set(Some(index)));
    }

    pub(super) fn poison_armor() {
        POISON_ARMOR.with(|poison| poison.set(true));
    }

    pub(super) fn reset() {
        FAIL_UNARMORED.with(|fail| fail.set(None));
        FAIL_ARMORED.with(|fail| fail.set(None));
        POISON_ARMOR.with(|poison| poison.set(false));
        FAIL_FINISH.with(|flag| flag.set(false));
        FAIL_NEXT.with(|flag| flag.set(false));
    }

    pub(super) struct HookedVec {
        buf: Vec<u8>,
        fail_on: Option<u32>,
        writes: u32,
    }

    impl HookedVec {
        pub(super) fn into_vec(self) -> Vec<u8> {
            self.buf
        }
    }

    pub(super) fn unarmored_buffer(capacity: usize) -> HookedVec {
        HookedVec {
            buf: Vec::with_capacity(capacity),
            fail_on: FAIL_UNARMORED.with(|fail| fail.take()),
            writes: 0,
        }
    }

    pub(super) fn armored_buffer(capacity: usize) -> HookedVec {
        HookedVec {
            buf: Vec::with_capacity(capacity),
            fail_on: FAIL_ARMORED.with(|fail| fail.take()),
            writes: 0,
        }
    }

    impl Write for HookedVec {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let fail_next = FAIL_NEXT.with(|flag| flag.replace(false));
            if fail_next || self.fail_on == Some(self.writes) {
                return Err(io::Error::other("injected write failure"));
            }
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(super) fn take_poison() -> bool {
        POISON_ARMOR.with(|poison| poison.replace(false))
    }

    pub(super) struct ResetOnDrop;

    impl Drop for ResetOnDrop {
        fn drop(&mut self) {
            reset();
        }
    }
}

mod error {
    use super::*;

    impl From<age::EncryptError> for IntegrationError {
        fn from(encrypt_error: age::EncryptError) -> Self {
            Self::Encryption(encrypt_error.into())
        }
    }

    impl From<age::DecryptError> for IntegrationError {
        fn from(decrypt_error: age::DecryptError) -> Self {
            Self::Decryption(decrypt_error.into())
        }
    }
}

mod key_id {
    use super::*;

    impl AppendIntegrationKey<AgeIntegration> for age::x25519::Recipient {
        fn append_to_metadata_builder(self, integration_metadata_builder: &mut IntegrationMetadataBuilder) {
            integration_metadata_builder.age_key_ids.push(self)
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockDisplayTestUtil for age::x25519::Recipient {
            fn mock_display() -> String {
                "age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569".to_string()
            }
        }

        impl MockTestUtil for age::x25519::Recipient {
            fn mock() -> Self {
                Self::mock_display().parse().unwrap()
            }
        }

        impl MockOtherTestUtil for age::x25519::Recipient {
            fn mock_other() -> Self {
                "age1qazf43xll4ramx3wcn7h2yl9scycxdhrwge8862vv6zj97pafdvq0d5mn6".parse().unwrap()
            }
        }
    }
}

pub use config::AgeConfig;
mod config {
    use serde::{Deserialize, Serialize};
    use serde_with::{serde_as, DisplayFromStr};

    use crate::*;

    #[serde_as]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct AgeConfig {
        #[serde_as(as = "DisplayFromStr")]
        #[serde(rename = "recipient")]
        pub key_id: <AgeIntegration as Integration>::KeyId,
    }

    impl IntegrationConfig<AgeIntegration> for AgeConfig {
        const INCLUDE_DATA_KEY_CREATED_AT: bool = false;

        fn new(key_id: <AgeIntegration as Integration>::KeyId) -> Self {
            Self { key_id }
        }

        fn key_id(&self) -> &<AgeIntegration as Integration>::KeyId {
            &self.key_id
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockTestUtil for AgeConfig {
            fn mock() -> Self {
                Self {
                    key_id: MockTestUtil::mock(),
                }
            }
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl IntegrationTestUtils for AgeIntegration {
        fn mock_private_key_str() -> impl AsRef<str> {
            "AGE-SECRET-KEY-1EQUCGFZH8UZKSZ0Z5N5T234YRNDT4U9H7QNYXWRRNJYDDVXE6FWSCPGNJ7"
        }

        fn mock_encrypted_data_key_str() -> &'static str {
            indoc::indoc! {"
                -----BEGIN AGE ENCRYPTED FILE-----
                YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBKeE9VRHJpNmc4Z1NFeDd6
                L3cybjRHblYvaFUxbk9JZDZ4RFdENGpiNmhZCnZCRXRNSlRZeno0SDlJWXdhT0xl
                Y1BlMzcyYUdVWFJ6WEVMTlRRaDRGbFUKLS0tIGc0V3gzU043MzBUd01BVTVKTEwr
                azRyUldHUXo0cTV2YlZWa2pwcWFweGcKQdFW597WOM0bYfycoA2A0JxjKlrka+lc
                MLuTri7QMM+g8yXcjneEGxjobGIqnvARlzDwcnFMxBoZ5/KRjMipXA==
                -----END AGE ENCRYPTED FILE-----
            "}
        }
    }
}

#[cfg(test)]
mod tests {
    use age::{
        armor::{ArmoredWriter, Format},
        Recipient,
    };

    use super::{io_fail, *};

    generate_integration_test_suite!(AgeIntegration);

    #[test]
    fn rejects_invalid_key_id_and_private_key() {
        assert!(AgeIntegration::parse_key_id("not-a-recipient").is_err());
        assert!(AgeIntegration::parse_private_key("not-a-key").is_err());
    }

    #[test]
    fn converts_age_errors() {
        let _ = IntegrationError::from(age::EncryptError::MissingRecipients);
        let _ = IntegrationError::from(age::DecryptError::DecryptionFailed);
    }

    #[test]
    fn exposes_the_mock_private_key() {
        let _age = AgeIntegration::mock_private_key();
        let _aws = AwsKmsIntegration::mock_private_key();
    }

    #[test]
    #[serial_test::serial]
    fn decrypts_none_without_a_matching_private_key() {
        let _env = EnvGuard::unset(AgeIntegration::private_key_env_var_name());
        let _file = EnvGuard::set(AgeIntegration::private_key_file_path_override_env_var_name(), "/no/such/age-keys");
        let key_id = <AgeIntegration as Integration>::KeyId::mock();
        let decrypted = AgeIntegration::decrypt_data_key(&key_id, AgeIntegration::mock_encrypted_data_key_str()).unwrap();
        assert!(decrypted.is_none());
    }

    #[test]
    #[serial_test::serial]
    fn decrypt_reports_private_key_retrieval_errors() {
        let name = AgeIntegration::private_key_env_var_name();
        let original = std::env::var_os(&name);
        let key_id = <AgeIntegration as Integration>::KeyId::mock();
        let invalid = <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(vec![0xff]);

        for preset in [Some("preset"), None] {
            match preset {
                Some(value) => std::env::set_var(&name, value),
                None => std::env::remove_var(&name),
            }
            let previous = std::env::var_os(&name);
            std::env::set_var(&name, &invalid);
            assert!(AgeIntegration::decrypt_data_key(&key_id, "ignored").is_err());
            restore_env(&name, previous);
        }
        restore_env(&name, original);
    }

    #[test]
    #[serial_test::serial]
    fn decrypt_fails_for_a_ciphertext_addressed_to_someone_else() {
        let _env = EnvGuard::set(
            AgeIntegration::private_key_env_var_name(),
            AgeIntegration::mock_private_key_str().as_ref(),
        );
        let _file = EnvGuard::set(AgeIntegration::private_key_file_path_override_env_var_name(), "/no/such/age-keys");
        let key_id = <AgeIntegration as Integration>::KeyId::mock();
        let other = age::x25519::Identity::generate();
        let recipient = other.to_public();
        let encryptor = age::Encryptor::with_recipients([&recipient as &dyn Recipient].into_iter()).unwrap();
        let mut unarmored = Vec::new();
        let mut writer = encryptor.wrap_output(&mut unarmored).unwrap();
        writer.write_all(DataKey::mock().as_ref()).unwrap();
        writer.finish().unwrap();
        let mut armored = Vec::new();
        let mut armored_writer = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor).unwrap();
        armored_writer.write_all(&unarmored).unwrap();
        armored_writer.finish().unwrap();
        let message = String::from_utf8(armored).unwrap();
        assert!(AgeIntegration::decrypt_data_key(&key_id, &message).is_err());
    }

    fn indexes_that_fail_seal(key_id: &<AgeIntegration as Integration>::KeyId, plaintext: &[u8]) -> Vec<u32> {
        let total = count_seal_writes(key_id, plaintext);
        let mut failed = Vec::new();
        // Drop can add trailing writes after `finish` returns, so the failure is not always in the last few.
        for index in 1..=total.saturating_add(2) {
            io_fail::reset();
            io_fail::fail_unarmored_write(index);
            let mut output = io_fail::unarmored_buffer(plaintext.len().max(1));
            let encryptor = age::Encryptor::with_recipients([key_id as &dyn Recipient].into_iter()).unwrap();
            if seal(encryptor, &mut output, plaintext).is_err() {
                failed.push(index);
            }
        }
        io_fail::reset();
        failed
    }

    #[test]
    fn writer_errors_reach_write_all_and_finish() {
        let key_id = <AgeIntegration as Integration>::KeyId::mock();
        let _guard = io_fail::ResetOnDrop;

        // A full age chunk forces `write_all` to flush. The following write is `finish`.
        let big = vec![0u8; 64 * 1024 + 1];
        let big_failures = indexes_that_fail_seal(&key_id, &big);
        assert!(
            big_failures.len() >= 2,
            "write_all and finish should both fail, got {big_failures:?}"
        );

        let small = vec![0u8; 32];
        let small_failures = indexes_that_fail_seal(&key_id, &small);
        assert!(!small_failures.is_empty(), "finish should fail, got {small_failures:?}");

        io_fail::reset();
        io_fail::fail_finish_write();
        let mut output = io_fail::unarmored_buffer(small.len());
        let encryptor = age::Encryptor::with_recipients([&key_id as &dyn Recipient].into_iter()).unwrap();
        assert!(seal(encryptor, &mut output, &small).is_err());
        io_fail::reset();

        let armor_small = vec![0u8; 64];
        let armor_writes = count_armor_writes(&armor_small);
        let armor_big = vec![0u8; 7_000];
        let start = armor_writes.saturating_sub(4).max(1);
        let armor_failed = (start..=armor_writes.saturating_add(2)).any(|index| {
            io_fail::reset();
            io_fail::fail_armored_write(index);
            let mut output = io_fail::armored_buffer(armor_big.len());
            let failed = armor(&mut output, &armor_big).is_err();
            io_fail::reset();
            failed
        });
        assert!(armor_failed, "armored write_all should fail around index {armor_writes}");

        let mut buffer = io_fail::unarmored_buffer(4);
        assert!(buffer.flush().is_ok());

        let mut counted = CountWriter(0);
        counted.flush().unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn decrypt_rejects_bad_armor_tampered_bodies_and_short_plaintext() {
        AgeIntegration::set_mock_private_key_env_var();
        let key_id = <AgeIntegration as Integration>::KeyId::mock();
        assert!(AgeIntegration::decrypt_data_key(&key_id, "not armor").is_err());

        let mut tampered = AgeIntegration::mock_encrypted_data_key_str().to_string();
        tampered = tampered.replacen("YW", "YQ", 1);
        assert!(AgeIntegration::decrypt_data_key(&key_id, &tampered).is_err());

        let recipient = key_id;
        let encryptor = age::Encryptor::with_recipients([&recipient as &dyn Recipient].into_iter()).unwrap();
        let mut unarmored = Vec::new();
        let mut writer = encryptor.wrap_output(&mut unarmored).unwrap();
        writer.write_all(b"x").unwrap();
        writer.finish().unwrap();
        let mut armored = Vec::new();
        let mut armored_writer = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor).unwrap();
        armored_writer.write_all(&unarmored).unwrap();
        armored_writer.finish().unwrap();
        let short_plaintext = String::from_utf8(armored).unwrap();
        assert!(AgeIntegration::decrypt_data_key(&recipient, &short_plaintext).is_err());
    }

    #[test]
    fn injected_write_and_utf8_failures_are_errors() {
        let key_id = <AgeIntegration as Integration>::KeyId::mock();
        let data_key = DataKey::mock();
        let _guard = io_fail::ResetOnDrop;

        for index in 1..=12 {
            io_fail::fail_unarmored_write(index);
            let _ = AgeIntegration::encrypt_data_key(&key_id, &data_key);
            io_fail::reset();

            io_fail::fail_armored_write(index);
            let _ = AgeIntegration::encrypt_data_key(&key_id, &data_key);
            io_fail::reset();
        }

        io_fail::poison_armor();
        assert!(AgeIntegration::encrypt_data_key(&key_id, &data_key).is_err());
    }

    #[test]
    fn metadata_unit_reports_encryption_failure() {
        io_fail::fail_unarmored_write(1);
        let _guard = io_fail::ResetOnDrop;
        let config = AgeConfig::new(<AgeIntegration as Integration>::KeyId::mock());
        assert!(IntegrationMetadataUnit::<AgeIntegration>::new(config, &DataKey::mock()).is_err());
    }

    #[test]
    fn metadata_builder_reports_age_encryption_failure() {
        io_fail::fail_unarmored_write(1);
        let _guard = io_fail::ResetOnDrop;
        let mut builder = IntegrationMetadataBuilder::default();
        builder.age_key_ids.push(<AgeIntegration as Integration>::KeyId::mock());
        assert!(builder.into_integration_metadata(&DataKey::mock()).is_err());
    }

    #[test]
    fn removing_another_integration_reports_age_reencryption_failure() {
        io_fail::fail_unarmored_write(1);
        let _guard = io_fail::ResetOnDrop;
        let mut metadata = RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock();
        let aws_key_id = <AwsKmsIntegration as Integration>::KeyId::mock();
        assert!(metadata.remove_integration_key::<AwsKmsIntegration>(&aws_key_id).is_err());
    }

    #[test]
    fn removing_an_age_key_reports_reencryption_failure() {
        io_fail::fail_unarmored_write(1);
        let _guard = io_fail::ResetOnDrop;
        let mut metadata = RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock();
        metadata.intregation.age.insert(IntegrationMetadataUnit {
            config: AgeConfig::new(<AgeIntegration as Integration>::KeyId::mock_other()),
            created_at: None,
            encrypted_data_key: "pending".to_string(),
        });
        let key_id = <AgeIntegration as Integration>::KeyId::mock();
        assert!(metadata.remove_integration_key::<AgeIntegration>(&key_id).is_err());
    }

    fn restore_env(name: &str, previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    struct CountWriter(u32);

    impl std::io::Write for CountWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += 1;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn count_seal_writes(key_id: &<AgeIntegration as Integration>::KeyId, plaintext: &[u8]) -> u32 {
        let encryptor = age::Encryptor::with_recipients([key_id as &dyn Recipient].into_iter()).unwrap();
        let mut output = CountWriter(0);
        seal(encryptor, &mut output, plaintext).unwrap();
        output.0
    }

    fn count_armor_writes(unarmored: &[u8]) -> u32 {
        let mut output = CountWriter(0);
        armor(&mut output, unarmored).unwrap();
        output.0
    }

    struct EnvGuard {
        name: String,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn unset(name: String) -> Self {
            let previous = std::env::var_os(&name);
            std::env::remove_var(&name);
            Self { name, previous }
        }

        fn set(name: String, value: &str) -> Self {
            let previous = std::env::var_os(&name);
            std::env::set_var(&name, value);
            Self { name, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(&self.name, value),
                None => std::env::remove_var(&self.name),
            }
        }
    }
}
