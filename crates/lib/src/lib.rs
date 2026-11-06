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
            let status = std::process::Command::new("chattr")
                .args(["+i", reference.to_str().unwrap()])
                .status()
                .unwrap();
            assert!(status.success(), "chattr +i is required to force the write error");

            let rewritten = normalize_sops_references(directory.path(), &cache_path);
            let cleanup = std::process::Command::new("chattr")
                .args(["-i", reference.to_str().unwrap()])
                .status()
                .unwrap();
            assert!(cleanup.success());
            assert!(rewritten.is_err());
        }

        #[test]
        fn reports_an_unreadable_reference() {
            let directory = tempdir().unwrap();
            let cache_path = directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            let reference = directory.path().join("blocked.yaml");
            std::fs::write(&reference, "key: value\n").unwrap();
            let status = std::process::Command::new("mount")
                .args(["--bind", "/proc/sysrq-trigger", reference.to_str().unwrap()])
                .status()
                .unwrap();
            assert!(status.success(), "bind mount is required to force the read error");

            let read = normalize_sops_references(directory.path(), &cache_path);
            let cleanup = std::process::Command::new("umount").arg(&reference).status().unwrap();
            assert!(cleanup.success());
            assert!(read.is_err());
        }

        #[test]
        fn reports_a_cache_write_failure() {
            let directory = tempdir().unwrap();
            let cache_directory = tempdir().unwrap();
            let cache_path = cache_directory.path().join("cache.yaml");
            std::fs::write(&cache_path, "previous_files_in_directory: 0\n").unwrap();
            std::fs::write(directory.path().join("sample.yaml"), "key: value\n").unwrap();
            let status = std::process::Command::new("chattr")
                .args(["+i", cache_path.to_str().unwrap()])
                .status()
                .unwrap();
            assert!(status.success(), "chattr +i is required to force the cache write error");

            let written = normalize_sops_references(directory.path(), &cache_path);
            let cleanup = std::process::Command::new("chattr")
                .args(["-i", cache_path.to_str().unwrap()])
                .status()
                .unwrap();
            assert!(cleanup.success());
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
