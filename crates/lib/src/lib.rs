// TEMP: https://github.com/rust-lang/rust/issues/43781
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod cryptography;
pub(crate) use cryptography::*;

pub mod file;
pub(crate) use file::*;

pub mod integration;
pub(crate) use integration::*;

mod base64utils;
pub(crate) use base64utils::*;

#[cfg(feature = "test-utils")]
pub mod test_utils;
#[cfg(feature = "test-utils")]
pub(crate) use test_utils::*;

#[cfg(test)]
mod env_guard {
    pub(crate) struct EnvVarGuard {
        name: String,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        pub(crate) fn set(name: impl Into<String>, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let name = name.into();
            let previous = std::env::var_os(&name);
            std::env::set_var(&name, value);
            Self { name, previous }
        }

        pub(crate) fn unset(name: impl Into<String>) -> Self {
            let name = name.into();
            let previous = std::env::var_os(&name);
            std::env::remove_var(&name);
            Self { name, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(&self.name, value),
                None => std::env::remove_var(&self.name),
            }
        }
    }
}

#[cfg(test)]
pub(crate) use env_guard::EnvVarGuard;

#[cfg(all(test, feature = "yaml"))]
mod sops_reference_normalize {
    include!("../sops_reference_normalize.rs");

    mod tests {
        use std::path::Path;

        use serde::Serialize;
        use tempfile::tempdir;

        use super::{normalize_sops_references, to_sops_yaml, with_trailing_newline};

        /// Runs `action` while writes to `path` fail. Permission bits stop regular users
        /// (CI runners); root ignores them, so it also needs the immutable attribute.
        fn while_unwritable<T>(path: &Path, action: impl FnOnce() -> T) -> T {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
            let needs_immutable = std::fs::OpenOptions::new().write(true).open(path).is_ok();
            if needs_immutable {
                chattr(path, "+i");
            }
            let result = action();
            if needs_immutable {
                chattr(path, "-i");
            }
            result
        }

        fn chattr(path: &Path, flag: &str) {
            let status = std::process::Command::new("chattr").arg(flag).arg(path).status().unwrap();
            assert!(status.success(), "chattr {flag} is required to force a write error as root");
        }

        #[test]
        fn leaves_a_current_cache_untouched() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 100\n").unwrap();
            std::fs::write(directory.path().join("sample.yaml"), "key: value\n").unwrap();

            normalize_sops_references(directory.path(), &cache_path).unwrap();

            let cache = std::fs::read_to_string(cache_path).unwrap();
            assert!(cache.contains("previous_files_in_directory: 100"));
        }

        #[test]
        fn rewrites_stale_yaml_and_json_references() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            std::fs::write(directory.path().join("sample.yaml"), "key: value\n").unwrap();
            std::fs::write(directory.path().join("sample.json"), "{\"key\":true}\n").unwrap();
            std::fs::create_dir(directory.path().join("nested")).unwrap();

            normalize_sops_references(directory.path(), &cache_path).unwrap();

            let cache = std::fs::read_to_string(&cache_path).unwrap();
            assert!(cache.contains("previous_files_in_directory:"));
            assert!(std::fs::read_to_string(directory.path().join("sample.yaml"))
                .unwrap()
                .ends_with('\n'));
        }

        #[test]
        fn reports_a_missing_cache() {
            let directory = tempdir().unwrap();
            assert!(normalize_sops_references(directory.path(), Path::new("/no/such/rops-cache.yaml")).is_err());
        }

        #[test]
        fn reports_an_unreadable_cache() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: [\n").unwrap();
            assert!(normalize_sops_references(directory.path(), &cache_path).is_err());
        }

        #[test]
        fn reports_invalid_reference_documents() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            std::fs::write(directory.path().join("broken.yaml"), "[\n").unwrap();
            assert!(normalize_sops_references(directory.path(), &cache_path).is_err());

            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            std::fs::remove_file(directory.path().join("broken.yaml")).unwrap();
            std::fs::write(directory.path().join("broken.json"), "{\n").unwrap();
            assert!(normalize_sops_references(directory.path(), &cache_path).is_err());
        }

        #[test]
        #[should_panic]
        fn rejects_an_unknown_extension() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            std::fs::write(directory.path().join("notes.txt"), "plain\n").unwrap();
            normalize_sops_references(directory.path(), &cache_path).unwrap();
        }

        #[test]
        fn reports_a_reference_write_failure() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            let reference = directory.path().join("sample.yaml");
            std::fs::write(&reference, "key: value\n").unwrap();

            let rewritten = while_unwritable(&reference, || normalize_sops_references(directory.path(), &cache_path));
            assert!(rewritten.is_err());
        }

        #[test]
        fn reports_an_unreadable_reference() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            // Not valid UTF-8, so reading the reference as a string fails for every user.
            std::fs::write(directory.path().join("blocked.yaml"), [0xff, 0xfe]).unwrap();

            assert!(normalize_sops_references(directory.path(), &cache_path).is_err());
        }

        #[test]
        fn reports_a_cache_write_failure() {
            let directory = tempdir().unwrap();
            let cache_directory = tempdir().unwrap();
            let cache_path = cache_directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            std::fs::write(directory.path().join("sample.yaml"), "key: value\n").unwrap();

            let written = while_unwritable(&cache_path, || normalize_sops_references(directory.path(), &cache_path));
            assert!(written.is_err());
        }

        #[test]
        fn adds_a_trailing_newline_when_missing() {
            assert_eq!("value\n", with_trailing_newline("value".to_string()));
            assert_eq!("value\n", with_trailing_newline("value\n".to_string()));
        }

        #[test]
        fn serializes_yaml_and_reports_serializer_errors() {
            assert!(to_sops_yaml(&"hello").unwrap().ends_with('\n'));

            struct Boom;
            impl Serialize for Boom {
                fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                    Err(serde::ser::Error::custom("boom"))
                }
            }
            assert!(to_sops_yaml(&Boom).is_err());

            struct Toggle(std::cell::Cell<bool>);
            impl Serialize for Toggle {
                fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    if self.0.replace(false) {
                        return Err(serde::ser::Error::custom("toggle"));
                    }
                    serializer.serialize_str("ok")
                }
            }
            let toggle = Toggle(std::cell::Cell::new(true));
            assert!(to_sops_yaml(&toggle).is_err());
            assert!(to_sops_yaml(&toggle).unwrap().ends_with('\n'));
        }
    }
}
