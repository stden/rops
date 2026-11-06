use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct IntegrationMetadata {
    #[cfg(feature = "aws-kms")]
    // Naming inconsistency inherited from SOPS, should ideally be named `aws_kms`
    // (a serde(alias = "kms") could be kept to supporting migrations.)
    #[serde(skip_serializing_if = "IntegrationMetadataUnits::is_empty", default)]
    pub kms: IntegrationMetadataUnits<AwsKmsIntegration>,
    #[cfg(feature = "age")]
    #[serde(skip_serializing_if = "IntegrationMetadataUnits::is_empty", default)]
    pub age: IntegrationMetadataUnits<AgeIntegration>,
}

impl IntegrationMetadata {
    pub fn add_keys<I: Integration>(&mut self, key_ids: impl IntoIterator<Item = I::KeyId>, data_key: &DataKey) -> IntegrationResult<()>
    where
        I::KeyId: Clone,
    {
        key_ids
            .into_iter()
            .map(|key_id| I::Config::new(key_id))
            .map(|integration_config| IntegrationMetadataUnit::<I>::new(integration_config, data_key))
            .try_for_each(|integration_metadata_unit_result| {
                I::select_metadata_units(self).insert(integration_metadata_unit_result?);
                Ok(())
            })
    }

    pub fn decrypt_data_key(&self) -> IntegrationResult<Option<DataKey>> {
        // In order of what is assumed to be quickest:

        // IMPROVEMENT: generialize if access to unit by simple reference becomes common.
        #[cfg(feature = "age")]
        if let Some(decrypt_result) = self.age.values().find_map(|age_metadata| {
            AgeIntegration::decrypt_data_key(&age_metadata.config.key_id, &age_metadata.encrypted_data_key).transpose()
        }) {
            return decrypt_result.map(Some);
        }

        #[cfg(feature = "aws-kms")]
        if let Some(decrypt_result) = self.kms.values().find_map(|aws_kms_metadata| {
            AwsKmsIntegration::decrypt_data_key(&aws_kms_metadata.config.key_id, &aws_kms_metadata.encrypted_data_key).transpose()
        }) {
            return decrypt_result.map(Some);
        }

        Ok(None)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for IntegrationMetadata {
        fn mock() -> Self {
            Self {
                #[cfg(feature = "aws-kms")]
                kms: MockTestUtil::mock(),
                #[cfg(feature = "age")]
                age: MockTestUtil::mock(),
            }
        }
    }
}

// Using age keys rather than stub integration to avoid setting adding test fields in
// `IntegrationMetadata`.
#[cfg(all(test, feature = "age"))]
mod tests {
    use super::*;

    #[test]
    fn adds_keys() {
        let mut integration_metadata = IntegrationMetadata::default();
        assert!(integration_metadata.age.is_empty());

        integration_metadata
            .add_keys::<AgeIntegration>(Some(<AgeIntegration as Integration>::KeyId::mock()), &DataKey::mock())
            .unwrap();

        assert!(!integration_metadata.age.is_empty())
    }

    #[test]
    #[serial_test::serial]
    fn decrypts_nothing_without_integration_units() {
        assert!(IntegrationMetadata::default().decrypt_data_key().unwrap().is_none());
    }

    #[test]
    #[serial_test::serial]
    fn age_and_aws_decryption_errors_propagate() {
        let _age = EnvVarGuard::set(
            AgeIntegration::private_key_env_var_name(),
            AgeIntegration::mock_private_key_str().as_ref(),
        );
        let _age_file = EnvVarGuard::set(AgeIntegration::private_key_file_path_override_env_var_name(), "/no/such/age-keys");

        let mut age_metadata = IntegrationMetadata::default();
        let mut age_unit = IntegrationMetadataUnit::<AgeIntegration>::mock();
        age_unit.encrypted_data_key = "not armor".to_string();
        age_metadata.age.insert(age_unit);
        assert!(age_metadata.decrypt_data_key().is_err());

        let mut aws_metadata = IntegrationMetadata::default();
        let mut aws_unit = IntegrationMetadataUnit::<AwsKmsIntegration>::mock();
        aws_unit.encrypted_data_key = "%%%".to_string();
        aws_metadata.kms.insert(aws_unit);
        assert!(aws_metadata.decrypt_data_key().is_err());
    }
}
