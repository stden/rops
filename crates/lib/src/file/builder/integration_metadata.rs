use std::{fmt::Debug, hash::Hash};

use crate::*;

pub trait AppendIntegrationKey<I: Integration>: Debug + PartialEq + Eq + Hash {
    fn append_to_metadata_builder(self, integration_metadata_builder: &mut IntegrationMetadataBuilder);
}

#[derive(Default)]
pub struct IntegrationMetadataBuilder {
    #[cfg(feature = "age")]
    pub age_key_ids: Vec<<AgeIntegration as Integration>::KeyId>,
    #[cfg(feature = "aws-kms")]
    pub aws_kms_key_ids: Vec<<AwsKmsIntegration as Integration>::KeyId>,
}

#[derive(Debug, thiserror::Error)]
pub enum IntegrationMetadataBuilderError {
    #[error(transparent)]
    Integration(#[from] IntegrationError),
    #[error("no integration keys were set, without them it's impossible to store the private data key")]
    MissingKeys,
}

impl IntegrationMetadataBuilder {
    pub fn into_integration_metadata(self, data_key: &DataKey) -> Result<IntegrationMetadata, IntegrationMetadataBuilderError> {
        if self.missing_keys() {
            return Err(IntegrationMetadataBuilderError::MissingKeys);
        }

        let mut integration_metadata = IntegrationMetadata::default();

        #[cfg(feature = "age")]
        integration_metadata.add_keys::<AgeIntegration>(self.age_key_ids, data_key)?;
        #[cfg(feature = "aws-kms")]
        integration_metadata.add_keys::<AwsKmsIntegration>(self.aws_kms_key_ids, data_key)?;

        Ok(integration_metadata)
    }

    fn missing_keys(&self) -> bool {
        #[cfg(feature = "age")]
        if !self.age_key_ids.is_empty() {
            return false;
        }

        #[cfg(feature = "aws-kms")]
        if !self.aws_kms_key_ids.is_empty() {
            return false;
        }

        // Not using any feature flags should also return true
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_disallows_missing_keys() {
        assert!(matches!(
            IntegrationMetadataBuilder::default()
                .into_integration_metadata(&DataKey::mock())
                .unwrap_err(),
            IntegrationMetadataBuilderError::MissingKeys
        ))
    }

    #[test]
    #[cfg(feature = "aws-kms")]
    #[serial_test::serial]
    fn aws_keys_skip_the_missing_key_check_and_still_fail_closed() {
        let _env = EnvVarGuard::unset(AwsKmsIntegration::private_key_env_var_name());
        let _file = EnvVarGuard::set(
            AwsKmsIntegration::private_key_file_path_override_env_var_name(),
            "/no/such/aws-keys",
        );
        let mut builder = IntegrationMetadataBuilder::default();
        builder.aws_kms_key_ids.push(AwsKeyId::mock());
        assert!(builder.into_integration_metadata(&DataKey::mock()).is_err());
    }
}
