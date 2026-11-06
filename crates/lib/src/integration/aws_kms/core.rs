use std::{future::Future, ops::Deref};

use anyhow::anyhow;
use aws_sdk_kms::{config::Credentials, primitives::Blob, Client, Config};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AwsKmsIntegration;

impl Integration for AwsKmsIntegration {
    const NAME: &'static str = "aws_kms";
    type KeyId = AwsKeyId;
    type PrivateKey = AwsPrivateKey;
    type Config = AwsKmsConfig;

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId> {
        key_id_str
            .parse::<Self::KeyId>()
            .map_err(|err| IntegrationError::KeyIdParsing(err.into()))
    }

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
        private_key_str.as_ref().parse()
    }

    // IMPROVEMENT: making these trait methods async might be worth looking once it becomes relevant
    // to call multiple integrations methods in parallel, rather than blocking the thread.

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String> {
        let encrypt_job = find_client(key_id)?
            .ok_or(IntegrationError::Encryption(anyhow!(
                "unable to find private keys for profile: {}",
                key_id.profile
            )))?
            .encrypt()
            .key_id(key_id.key_arn.key_id.deref())
            .plaintext(Blob::new(AsRef::<[u8]>::as_ref(data_key)));

        let encrypted_data_key_string = tokio_blocking(encrypt_job.send())
            .map_err(|error| IntegrationError::Encryption(error.into()))?
            .ciphertext_blob
            .expect("encryption response missing encrypted ciphertext")
            .encode_base64();

        Ok(encrypted_data_key_string)
    }

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
        let mut decoded_bytes = Vec::with_capacity(DataKey::byte_size());
        decoded_bytes
            .decode_base64(encrypted_data_key)
            .map_err(|error| IntegrationError::Decryption(error.into()))?;

        let Some(decypt_client) = find_client(key_id)? else {
            return Ok(None);
        };

        let decrypt_job = decypt_client
            .decrypt()
            .key_id(key_id.key_arn.key_id.deref())
            .ciphertext_blob(Blob::new(decoded_bytes));

        let decrypted_bytes = tokio_blocking(decrypt_job.send())
            .map_err(|error| IntegrationError::Encryption(error.into()))?
            .plaintext
            .expect("decryption response missing decrypted plaintext")
            .into_inner();

        data_key_from_plaintext(decrypted_bytes)
    }

    fn select_metadata_units(integration_metadata: &mut IntegrationMetadata) -> &mut IntegrationMetadataUnits<Self> {
        &mut integration_metadata.kms
    }
}

fn tokio_blocking<O>(future: impl Future<Output = O>) -> O {
    tokio::runtime::Runtime::new().unwrap().block_on(future)
}

fn find_client(key_id: &AwsKeyId) -> IntegrationResult<Option<Client>> {
    let AwsKeyId { profile, key_arn } = key_id;

    let private_keys = AwsKmsIntegration::retrieve_private_keys()?;

    let Some(matching_private_key) = private_keys.into_iter().find(|key| &key.profile == profile) else {
        return Ok(None);
    };

    let config_builder = Config::builder()
        .region(Some(key_arn.region.clone()))
        .credentials_provider(Credentials::new(
            matching_private_key.id,
            matching_private_key.secret,
            None,
            None,
            "rops",
        ));

    // Rebind only in tests. A `mut` binding is unused, and denied, in the non-test build.
    #[cfg(test)]
    let config_builder = match ENDPOINT_OVERRIDE.with(|endpoint| endpoint.get()) {
        Some(endpoint) => config_builder.endpoint_url(endpoint),
        None => config_builder,
    };

    Ok(Some(Client::from_conf(config_builder.build())))
}

fn data_key_from_plaintext(bytes: Vec<u8>) -> IntegrationResult<Option<DataKey>> {
    DataKey::try_from(bytes)
        .map(Some)
        .map_err(|error| IntegrationError::Decryption(error.into()))
}

#[cfg(test)]
thread_local! {
    static ENDPOINT_OVERRIDE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl IntegrationTestUtils for AwsKmsIntegration {
        fn mock_private_key_str() -> impl AsRef<str> {
            AwsPrivateKey::mock_display()
        }

        fn mock_encrypted_data_key_str() -> &'static str {
            "AQICAHiB4ozqhuEpHKVV+bXVXqxUTHq97nhkmOnQqSGLV5d0fAE5vjB9Tx8f5juCR3DPHGWZAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM9th1qt9YvZ2Vgu3TAgEQgDv7GInqnuJJno5ikZvMXQB7c4FLmqAqiuXAUP1NkYUn1OsdWuwdcH6nDKcn6GJ/ddBElY/Cd1tXqwrk7A=="
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    generate_integration_test_suite!(AwsKmsIntegration);

    #[test]
    fn rejects_a_plaintext_with_the_wrong_length() {
        assert!(data_key_from_plaintext(vec![1, 2, 3]).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn find_client_reports_retrieval_profile_and_request_failures() {
        let key_id = AwsKeyId::mock();
        let data_key = DataKey::mock();
        let file_override = AwsKmsIntegration::private_key_file_path_override_env_var_name();
        let _hidden_file = EnvVarGuard::set(&file_override, "/no/such/aws-keys");

        let _not_unicode = EnvVarGuard::set(
            AwsKmsIntegration::private_key_env_var_name(),
            <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(vec![0xff]),
        );
        assert!(AwsKmsIntegration::encrypt_data_key(&key_id, &data_key).is_err());
        drop(_not_unicode);

        let _other_profile = EnvVarGuard::set(AwsKmsIntegration::private_key_env_var_name(), "other.AKIATESTKEYID.secretvalue");
        assert!(AwsKmsIntegration::encrypt_data_key(&key_id, &data_key).is_err());
        assert!(AwsKmsIntegration::decrypt_data_key(&key_id, "QQ").unwrap().is_none());
        drop(_other_profile);

        let _matching = EnvVarGuard::set(
            AwsKmsIntegration::private_key_env_var_name(),
            AwsKmsIntegration::mock_private_key_str().as_ref(),
        );
        ENDPOINT_OVERRIDE.with(|endpoint| endpoint.set(Some("http://127.0.0.1:9")));
        assert!(AwsKmsIntegration::encrypt_data_key(&key_id, &data_key).is_err());
        assert!(AwsKmsIntegration::decrypt_data_key(&key_id, AwsKmsIntegration::mock_encrypted_data_key_str()).is_err());
        ENDPOINT_OVERRIDE.with(|endpoint| endpoint.set(None));

        let _not_unicode = EnvVarGuard::set(
            AwsKmsIntegration::private_key_env_var_name(),
            <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(vec![0xff]),
        );
        assert!(AwsKmsIntegration::decrypt_data_key(&key_id, "YQ==").is_err());
        assert!(AwsKmsIntegration::parse_key_id("not-a-key-id").is_err());
    }

    #[test]
    #[serial_test::serial]
    fn removing_the_age_key_reports_aws_reencryption_failure() {
        let _env = EnvVarGuard::unset(AwsKmsIntegration::private_key_env_var_name());
        let _file = EnvVarGuard::set(
            AwsKmsIntegration::private_key_file_path_override_env_var_name(),
            "/no/such/aws-keys",
        );
        let mut metadata = RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock();
        let age_key_id = <AgeIntegration as Integration>::KeyId::mock();
        assert!(metadata.remove_integration_key::<AgeIntegration>(&age_key_id).is_err());
    }
}
