use std::{env::VarError, fmt::Debug, path::PathBuf};

use crate::*;

const ROPS_APPLICATION_NAME: &str = "rops";

pub trait Integration: Sized {
    const NAME: &'static str;
    type KeyId: AppendIntegrationKey<Self>;
    type PrivateKey;
    type Config: IntegrationConfig<Self>;

    fn private_key_env_var_name() -> String {
        format!("ROPS_{}", Self::NAME.to_uppercase())
    }

    fn private_key_file_path_override_env_var_name() -> String {
        format!("ROPS_{}_KEY_FILE", Self::NAME.to_uppercase())
    }

    fn private_keys_from_env() -> IntegrationResult<Vec<Self::PrivateKey>> {
        match std::env::var(Self::private_key_env_var_name()) {
            Ok(found_string) => found_string.split(',').map(Self::parse_private_key).collect(),
            Err(env_var_error) => match env_var_error {
                VarError::NotPresent => Ok(Vec::default()),
                VarError::NotUnicode(os_str) => Err(IntegrationError::EnvVarNotUnicode(os_str)),
            },
        }
    }

    fn private_keys_from_default_key_file() -> IntegrationResult<Vec<Self::PrivateKey>> {
        let integration_key_file = match std::env::var_os(Self::private_key_file_path_override_env_var_name()) {
            Some(os_string) => PathBuf::from(os_string),
            None => directories::BaseDirs::new()
                .expect("the process home directory is set")
                .config_local_dir()
                .join(ROPS_APPLICATION_NAME)
                .join(format!("{}_keys", Self::NAME)),
        };

        match integration_key_file.exists() {
            true => std::fs::read_to_string(integration_key_file)?
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .map(Self::parse_private_key)
                .collect(),
            false => Ok(Vec::new()),
        }
    }

    fn retrieve_private_keys() -> IntegrationResult<Vec<Self::PrivateKey>> {
        let mut private_key_strings = Vec::<Self::PrivateKey>::new();

        private_key_strings.append(&mut Self::private_keys_from_env()?);
        private_key_strings.append(&mut Self::private_keys_from_default_key_file()?);

        Ok(private_key_strings)
    }

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId>;

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey>;

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String>;

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>>;

    fn select_metadata_units(integration_metadata: &mut IntegrationMetadata) -> &mut IntegrationMetadataUnits<Self>;
}

pub trait IntegrationConfig<I: Integration>: Debug + PartialEq {
    const INCLUDE_DATA_KEY_CREATED_AT: bool;

    fn new(key_id: I::KeyId) -> Self;

    fn key_id(&self) -> &I::KeyId;
}

#[cfg(test)]
use stub_integration::StubIntegration;
#[cfg(test)]
mod stub_integration {
    use super::*;

    pub struct StubIntegration;

    impl Integration for StubIntegration {
        const NAME: &'static str = "stub";
        type KeyId = String;
        type PrivateKey = String;
        type Config = StubIntegrationConfig;

        fn parse_key_id(_key_id_str: &str) -> IntegrationResult<Self::KeyId> {
            unimplemented!()
        }

        fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
            Ok(private_key_str.as_ref().to_string())
        }

        fn encrypt_data_key(_key_id: &Self::KeyId, _data_key: &DataKey) -> IntegrationResult<String> {
            unimplemented!()
        }

        fn decrypt_data_key(_key_id: &Self::KeyId, _encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
            unimplemented!()
        }

        fn select_metadata_units(_integration_metadata: &mut IntegrationMetadata) -> &mut IntegrationMetadataUnits<Self> {
            unimplemented!()
        }
    }

    impl AppendIntegrationKey<StubIntegration> for String {
        fn append_to_metadata_builder(self, _integration_metadata_builder: &mut IntegrationMetadataBuilder) {
            unimplemented!()
        }
    }

    #[derive(Debug, PartialEq, Eq, Hash)]
    pub struct StubIntegrationConfig(String);

    impl IntegrationConfig<StubIntegration> for StubIntegrationConfig {
        const INCLUDE_DATA_KEY_CREATED_AT: bool = false;

        fn new(key_id: <StubIntegration as Integration>::KeyId) -> Self {
            Self(key_id)
        }

        fn key_id(&self) -> &<StubIntegration as Integration>::KeyId {
            &self.0
        }
    }

    #[cfg(test)]
    mod coverage {
        use super::*;

        #[test]
        #[should_panic]
        fn parse_key_id_is_unimplemented() {
            let _ = StubIntegration::parse_key_id("id");
        }

        #[test]
        #[should_panic]
        fn encrypt_data_key_is_unimplemented() {
            let _ = StubIntegration::encrypt_data_key(&String::new(), &DataKey::empty());
        }

        #[test]
        #[serial_test::serial]
        #[should_panic]
        fn decrypt_data_key_is_unimplemented() {
            let _ = StubIntegration::decrypt_data_key(&String::new(), "");
        }

        #[test]
        #[should_panic]
        fn select_metadata_units_is_unimplemented() {
            let _ = StubIntegration::select_metadata_units(&mut IntegrationMetadata::default());
        }

        #[test]
        #[should_panic]
        fn append_to_metadata_builder_is_unimplemented() {
            String::new().append_to_metadata_builder(&mut IntegrationMetadataBuilder::default());
        }

        #[test]
        fn config_stores_its_key_id() {
            let config = StubIntegrationConfig::new("id".to_string());
            assert_eq!("id", config.key_id());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STUB_KEYS: &[&str] = &["key1", "key2"];

    #[test]
    #[serial_test::serial]
    fn gets_private_key_env_var_name() {
        assert_eq!("ROPS_STUB", StubIntegration::private_key_env_var_name())
    }

    #[test]
    #[serial_test::serial]
    fn gets_private_key_file_path_override_env_var_name() {
        assert_eq!("ROPS_STUB_KEY_FILE", StubIntegration::private_key_file_path_override_env_var_name())
    }

    #[test]
    #[serial_test::serial]
    fn gets_private_key_from_env() {
        let var_name = StubIntegration::private_key_env_var_name();
        std::env::set_var(&var_name, "key1,key2");

        assert_eq!(STUB_KEYS, StubIntegration::private_keys_from_env().unwrap().as_slice());

        std::env::remove_var(&var_name);
    }

    const STUB_KEY_FILE_CONTENTS: &str = "
        key1
        key2
    ";

    fn read_default_stub_keys() {
        let rops_config_dir = directories::BaseDirs::new().unwrap().config_local_dir().join(ROPS_APPLICATION_NAME);

        let created_config_dir = match rops_config_dir.is_dir() {
            true => false,
            false => {
                std::fs::create_dir_all(&rops_config_dir).unwrap();
                true
            }
        };

        let stub_keys_path = rops_config_dir.join(format!("{}_keys", StubIntegration::NAME));

        std::fs::write(&stub_keys_path, STUB_KEY_FILE_CONTENTS).unwrap();

        assert_eq!(STUB_KEYS, StubIntegration::private_keys_from_default_key_file().unwrap().as_slice());

        match created_config_dir {
            true => std::fs::remove_dir_all(rops_config_dir).unwrap(),
            false => std::fs::remove_file(stub_keys_path).unwrap(),
        }
    }

    struct ConfigBackup {
        original: std::path::PathBuf,
        backup: std::path::PathBuf,
    }

    impl Drop for ConfigBackup {
        fn drop(&mut self) {
            if self.backup.is_dir() {
                let _ = std::fs::remove_dir_all(&self.original);
                let _ = std::fs::rename(&self.backup, &self.original);
            }
        }
    }

    fn hide_config_dir(existed: bool, dir: &std::path::Path, backup: &std::path::Path) {
        if existed {
            std::fs::rename(dir, backup).unwrap();
        }
    }

    fn restore_config_dir(existed: bool, dir: &std::path::Path, backup: &std::path::Path) {
        if existed {
            let _ = std::fs::remove_dir_all(dir);
            let _ = std::fs::rename(backup, dir);
        } else {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    fn restore_env(name: &str, previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    fn create_if_missing(missing: bool, dir: &std::path::Path) {
        if missing {
            std::fs::create_dir_all(dir).unwrap();
        }
    }

    fn remove_if_missing(missing: bool, dir: &std::path::Path) {
        if missing {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn config_backup_drop_restores_a_directory() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let backup = temp.path().join("backup");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("kept"), b"yes").unwrap();
        std::fs::rename(&original, &backup).unwrap();
        drop(ConfigBackup {
            original: original.clone(),
            backup,
        });
        assert_eq!(b"yes", std::fs::read(original.join("kept")).unwrap().as_slice());
    }

    #[test]
    fn reports_a_missing_home_directory() {
        assert_eq!(
            "unable to retrieve any home directory from the operating system",
            IntegrationError::NoHomeDir.to_string()
        );
    }

    #[test]
    #[serial_test::serial]
    fn gets_private_key_from_default_key_file() {
        let rops_config_dir = directories::BaseDirs::new().unwrap().config_local_dir().join(ROPS_APPLICATION_NAME);
        let backup = rops_config_dir.with_file_name("rops-coverage-backup");
        let missing = !rops_config_dir.is_dir();
        let scratch = tempfile::tempdir().unwrap();
        let scratch_dir = scratch.path().join("created");
        create_if_missing(missing, &rops_config_dir);
        create_if_missing(!missing, &scratch_dir);
        hide_config_dir(false, &rops_config_dir, &backup);
        hide_config_dir(true, &rops_config_dir, &backup);
        let _restore = ConfigBackup {
            original: rops_config_dir.clone(),
            backup: backup.clone(),
        };

        let override_name = StubIntegration::private_key_file_path_override_env_var_name();
        let previous_override = std::env::var_os(&override_name);
        std::env::remove_var(&override_name);
        assert!(StubIntegration::private_keys_from_default_key_file().unwrap().is_empty());

        let env_name = StubIntegration::private_key_env_var_name();
        let previous_env = std::env::var_os(&env_name);
        std::env::set_var(&env_name, "from-env");
        assert_eq!(vec!["from-env".to_string()], StubIntegration::retrieve_private_keys().unwrap());
        restore_env(&env_name, previous_env);

        read_default_stub_keys();
        std::fs::create_dir_all(&rops_config_dir).unwrap();
        read_default_stub_keys();
        std::fs::remove_dir_all(&rops_config_dir).unwrap();

        std::fs::create_dir_all(&rops_config_dir).unwrap();
        read_default_stub_keys();
        let moved = rops_config_dir.with_file_name("rops-coverage-moved");
        std::fs::rename(&rops_config_dir, &moved).unwrap();
        read_default_stub_keys();
        std::fs::rename(&moved, &rops_config_dir).unwrap();

        restore_env(&override_name, previous_override);
        restore_config_dir(false, &rops_config_dir, &backup);
        restore_config_dir(true, &rops_config_dir, &backup);
        remove_if_missing(missing, &rops_config_dir);
        remove_if_missing(!missing, &scratch_dir);
    }

    #[test]
    #[serial_test::serial]
    fn gets_private_key_from_default_key_file_with_location_override() {
        let temp_dir = tempfile::tempdir().unwrap();

        let key_file_override_path = temp_dir.path().join("keys_override");

        std::fs::write(&key_file_override_path, STUB_KEY_FILE_CONTENTS).unwrap();

        let override_var_name = StubIntegration::private_key_file_path_override_env_var_name();
        std::env::set_var(&override_var_name, key_file_override_path.as_os_str());

        assert_eq!(STUB_KEYS, StubIntegration::private_keys_from_default_key_file().unwrap());

        std::env::remove_var(override_var_name)
    }

    #[test]
    #[serial_test::serial]
    fn private_keys_from_env_when_unset_or_not_unicode() {
        let name = StubIntegration::private_key_env_var_name();
        let original = std::env::var_os(&name);
        let invalid = <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(vec![0xff]);

        for preset in [Some("preset"), None] {
            match preset {
                Some(value) => std::env::set_var(&name, value),
                None => std::env::remove_var(&name),
            }
            let previous = std::env::var_os(&name);
            std::env::remove_var(&name);
            assert!(StubIntegration::private_keys_from_env().unwrap().is_empty());
            std::env::set_var(&name, &invalid);
            assert!(matches!(
                StubIntegration::private_keys_from_env().unwrap_err(),
                IntegrationError::EnvVarNotUnicode(_)
            ));
            assert!(StubIntegration::retrieve_private_keys().is_err());
            restore_env(&name, previous);
        }

        restore_env(&name, Some("kept".into()));
        restore_env(&name, None);
        restore_env(&name, original);
    }

    #[test]
    #[serial_test::serial]
    fn private_key_file_read_errors_fail_retrieval() {
        let directory = tempfile::tempdir().unwrap();
        let name = StubIntegration::private_key_file_path_override_env_var_name();
        let original = std::env::var_os(&name);

        std::env::set_var(&name, "preset");
        let previous = std::env::var_os(&name);
        std::env::set_var(&name, directory.path());
        assert!(StubIntegration::private_keys_from_default_key_file().is_err());
        assert!(StubIntegration::retrieve_private_keys().is_err());
        restore_env(&name, previous);

        std::env::remove_var(&name);
        let previous = std::env::var_os(&name);
        std::env::set_var(&name, directory.path());
        assert!(StubIntegration::private_keys_from_default_key_file().is_err());
        restore_env(&name, previous);
        restore_env(&name, original);
    }

    #[test]
    #[serial_test::serial]
    fn default_key_file_keeps_a_preexisting_config_directory() {
        let rops_config_dir = directories::BaseDirs::new().unwrap().config_local_dir().join(ROPS_APPLICATION_NAME);
        std::fs::create_dir_all(&rops_config_dir).unwrap();
        let stub_keys_path = rops_config_dir.join(format!("{}_keys", StubIntegration::NAME));
        std::fs::write(&stub_keys_path, STUB_KEY_FILE_CONTENTS).unwrap();

        assert_eq!(STUB_KEYS, StubIntegration::private_keys_from_default_key_file().unwrap().as_slice());

        std::fs::remove_file(stub_keys_path).unwrap();
    }
}
