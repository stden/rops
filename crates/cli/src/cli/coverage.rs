use std::{io::IsTerminal, os::unix::ffi::OsStringExt, path::Path};

use rops::{
    file::{builder::RopsFileBuilder, format::*, metadata::PartialEncryptionConfig},
    integration::{AgeIntegration, AwsKmsIntegration, Integration, IntegrationTestUtils},
    test_utils::{MockOtherTestUtil, MockTestUtil},
};
use tempfile::NamedTempFile;

use super::test_fd::{close_raw, Alarm, Pty, SavedFd};
use crate::*;

fn require_terminal_stdin() {
    assert!(std::io::stdin().is_terminal(), "run file-input tests under script");
}

struct EnvGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }

    fn unset(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::remove_var(name);
        Self { name, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

fn age_env() -> EnvGuard {
    let key = AgeIntegration::mock_private_key_str();
    EnvGuard::set("ROPS_AGE", key.as_ref())
}

fn age_recipient() -> <AgeIntegration as Integration>::KeyId {
    <AgeIntegration as Integration>::KeyId::mock()
}

fn only_age() -> IntegrationKeys {
    IntegrationKeys {
        age: vec![age_recipient()],
        aws_kms: vec![],
    }
}

fn write_temp(contents: &str) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    std::fs::write(file.path(), contents).unwrap();
    file
}

fn seal(plaintext: &str, partial: Option<PartialEncryptionConfig>, mac_only: bool) -> String {
    let mut builder = RopsFileBuilder::<YamlFileFormat>::new(plaintext)
        .unwrap()
        .add_integration_key::<AgeIntegration>(age_recipient());
    if let Some(partial) = partial {
        builder = builder.with_partial_encryption(partial);
    }
    if mac_only {
        builder = builder.mac_only_encrypted();
    }
    builder.encrypt::<DefaultCipher, DefaultHasher>().unwrap().to_string()
}

fn input(path: &Path, format: Format) -> InputArgs {
    InputArgs {
        config: None,
        format: Some(format),
        file: Some(path.to_path_buf()),
    }
}

fn encrypted_yaml() -> (EnvGuard, NamedTempFile) {
    let env = age_env();
    let file = write_temp(&seal("hello: world\n", None, false));
    (env, file)
}

/// Changes a path's mode until dropped, then restores the original mode.
struct ModeGuard {
    path: std::path::PathBuf,
    original: std::fs::Permissions,
}

impl ModeGuard {
    /// Applies `mode` to `path`. Returns `None` when `denied` still succeeds, because root ignores mode bits.
    fn if_enforced(path: &Path, mode: u32, denied: fn(&Path) -> bool) -> Option<Self> {
        let guard = Self {
            path: path.to_path_buf(),
            original: std::fs::metadata(path).unwrap().permissions(),
        };
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
        if denied(path) {
            return Some(guard);
        }
        eprintln!(
            "skipped: {} is still accessible with mode {mode:o}, permissions are not enforced for this user",
            path.display()
        );
        None
    }
}

impl Drop for ModeGuard {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.path, self.original.clone());
    }
}

fn write_denied(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_err()
}

fn create_denied(directory: &Path) -> bool {
    tempfile::tempfile_in(directory).is_err()
}

fn write_script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("editor.sh");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    (directory, path)
}

fn executable_named(directory: &Path, name: &str) {
    let path = directory.join(name);
    std::fs::write(&path, "#!/bin/sh\nprintf 'hello: world\\n' > \"$1\"\n").unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

#[test]
#[serial_test::serial(config_retrieval)]
fn format_arms_reject_garbage() {
    require_terminal_stdin();
    let _editor = EnvGuard::set("EDITOR", "/no/such/editor");
    for format in [Format::Yaml, Format::Json, Format::Toml] {
        let file = write_temp("this is not a rops file\n");
        assert!(Cli::decrypt(DecryptArgs {
            input_args: input(file.path(), format),
            in_place: None,
        })
        .is_err());
        assert!(Cli::encrypt(EncryptArgs {
            integration_keys: IntegrationKeys::default(),
            partial_encryption_args: None,
            mac_only_encrypted: None,
            input_args: input(file.path(), format),
            in_place: None,
        })
        .is_err());
        assert!(Cli::edit(input(file.path(), format)).is_err());
        let keys = KeyInputArgs {
            integration_keys: IntegrationKeys::default(),
            format: Some(format),
            file: file.path().to_path_buf(),
        };
        assert!(Cli::keys(KeysSubcommand::Add(keys)).is_err());
        let keys = KeyInputArgs {
            integration_keys: IntegrationKeys::default(),
            format: Some(format),
            file: file.path().to_path_buf(),
        };
        assert!(Cli::keys(KeysSubcommand::Remove(keys)).is_err());
        assert!(Cli::refresh(RefreshArgs {
            input_args: input(file.path(), format),
            in_place: None,
        })
        .is_err());
    }
}

#[test]
#[serial_test::serial(config_retrieval)]
fn encrypts_with_partial_encryption_and_reports_failures() {
    require_terminal_stdin();
    let _age = age_env();
    let plaintext = write_temp("hello: world\n");

    assert!(Cli::encrypt(EncryptArgs {
        integration_keys: only_age(),
        partial_encryption_args: Some(PartialEncryptionConfig::UnencryptedSuffix("public".to_string()).into()),
        mac_only_encrypted: Some(true),
        input_args: input(plaintext.path(), Format::Yaml),
        in_place: None,
    })
    .is_ok());

    assert!(Cli::encrypt(EncryptArgs {
        integration_keys: IntegrationKeys::default(),
        partial_encryption_args: None,
        mac_only_encrypted: Some(false),
        input_args: input(plaintext.path(), Format::Yaml),
        in_place: None,
    })
    .is_err());

    let Some(_read_only) = ModeGuard::if_enforced(plaintext.path(), 0o444, write_denied) else {
        return;
    };
    assert!(Cli::encrypt(EncryptArgs {
        integration_keys: only_age(),
        partial_encryption_args: None,
        mac_only_encrypted: None,
        input_args: input(plaintext.path(), Format::Yaml),
        in_place: Some(true),
    })
    .is_err());
}

#[test]
#[serial_test::serial(config_retrieval)]
fn decrypts_and_reports_key_and_write_failures() {
    require_terminal_stdin();
    let (_age, file) = encrypted_yaml();

    assert!(Cli::decrypt(DecryptArgs {
        input_args: input(file.path(), Format::Yaml),
        in_place: None,
    })
    .is_ok());

    let copy = write_temp(&std::fs::read_to_string(file.path()).unwrap());
    assert!(Cli::decrypt(DecryptArgs {
        input_args: input(copy.path(), Format::Yaml),
        in_place: Some(true),
    })
    .is_ok());

    std::env::remove_var("ROPS_AGE");
    assert!(Cli::decrypt(DecryptArgs {
        input_args: input(file.path(), Format::Yaml),
        in_place: None,
    })
    .is_err());

    let (_restored, writable) = encrypted_yaml();
    let Some(_read_only) = ModeGuard::if_enforced(writable.path(), 0o444, write_denied) else {
        return;
    };
    assert!(Cli::decrypt(DecryptArgs {
        input_args: input(writable.path(), Format::Yaml),
        in_place: Some(true),
    })
    .is_err());
}

#[test]
#[serial_test::serial(config_retrieval)]
fn adds_and_removes_keys_and_reports_failures() {
    require_terminal_stdin();
    let _age = age_env();
    let _aws_env = EnvGuard::unset("ROPS_AWS_KMS");
    let _aws_file = EnvGuard::set("ROPS_AWS_KMS_KEY_FILE", "/no/such/aws-keys");
    let file = write_temp(&seal("hello: world\n", None, false));

    let added = write_temp(&std::fs::read_to_string(file.path()).unwrap());
    assert!(Cli::keys(KeysSubcommand::Add(KeyInputArgs {
        integration_keys: IntegrationKeys {
            age: vec![<AgeIntegration as Integration>::KeyId::mock_other()],
            aws_kms: vec![],
        },
        format: Some(Format::Yaml),
        file: added.path().to_path_buf(),
    }))
    .is_ok());

    let removable = write_temp(&std::fs::read_to_string(added.path()).unwrap());
    assert!(Cli::keys(KeysSubcommand::Remove(KeyInputArgs {
        integration_keys: IntegrationKeys {
            age: vec![<AgeIntegration as Integration>::KeyId::mock_other()],
            aws_kms: vec![],
        },
        format: Some(Format::Yaml),
        file: removable.path().to_path_buf(),
    }))
    .is_ok());

    assert!(Cli::keys(KeysSubcommand::Add(KeyInputArgs {
        integration_keys: only_age(),
        format: Some(Format::Yaml),
        file: std::path::PathBuf::from("/no/such/rops-add.yaml"),
    }))
    .is_err());
    assert!(Cli::keys(KeysSubcommand::Remove(KeyInputArgs {
        integration_keys: only_age(),
        format: Some(Format::Yaml),
        file: std::path::PathBuf::from("/no/such/rops-remove.yaml"),
    }))
    .is_err());

    std::env::remove_var("ROPS_AGE");
    assert!(Cli::keys(KeysSubcommand::Add(KeyInputArgs {
        integration_keys: only_age(),
        format: Some(Format::Yaml),
        file: file.path().to_path_buf(),
    }))
    .is_err());

    let _age = age_env();
    assert!(Cli::keys(KeysSubcommand::Add(KeyInputArgs {
        integration_keys: IntegrationKeys {
            age: vec![],
            aws_kms: vec![<AwsKmsIntegration as Integration>::KeyId::mock()],
        },
        format: Some(Format::Yaml),
        file: file.path().to_path_buf(),
    }))
    .is_err());

    let unwritable = write_temp(&std::fs::read_to_string(file.path()).unwrap());
    let Some(_read_only) = ModeGuard::if_enforced(unwritable.path(), 0o444, write_denied) else {
        return;
    };
    assert!(Cli::keys(KeysSubcommand::Add(KeyInputArgs {
        integration_keys: only_age(),
        format: Some(Format::Yaml),
        file: unwritable.path().to_path_buf(),
    }))
    .is_err());
    drop(_read_only);

    assert!(Cli::keys(KeysSubcommand::Remove(KeyInputArgs {
        integration_keys: only_age(),
        format: Some(Format::Yaml),
        file: file.path().to_path_buf(),
    }))
    .is_err());

    std::env::remove_var("ROPS_AGE");
    assert!(Cli::keys(KeysSubcommand::Remove(KeyInputArgs {
        integration_keys: only_age(),
        format: Some(Format::Yaml),
        file: added.path().to_path_buf(),
    }))
    .is_err());

    let _age = age_env();
    let rewrite = write_temp(&std::fs::read_to_string(added.path()).unwrap());
    let Some(_read_only) = ModeGuard::if_enforced(rewrite.path(), 0o444, write_denied) else {
        return;
    };
    assert!(Cli::keys(KeysSubcommand::Remove(KeyInputArgs {
        integration_keys: IntegrationKeys {
            age: vec![<AgeIntegration as Integration>::KeyId::mock_other()],
            aws_kms: vec![],
        },
        format: Some(Format::Yaml),
        file: rewrite.path().to_path_buf(),
    }))
    .is_err());
}

fn config_with(rule_keys: IntegrationKeys, partial: Option<PartialEncryptionConfig>, mac: Option<bool>, regex: &str) -> Config {
    Config {
        creation_rules: vec![CreationRule {
            path_regex: regex::Regex::new(regex).unwrap(),
            mac_only_encrypted: mac,
            partial_encryption: partial,
            integration_keys: rule_keys,
        }],
    }
}

fn store_config(config: &Config) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    let text = TomlFileFormat::serialize_to_string(config).unwrap();
    std::fs::write(file.path(), text).unwrap();
    file
}

#[test]
#[serial_test::serial(config_retrieval)]
fn refreshes_matching_rules_and_reports_failures() {
    require_terminal_stdin();
    let _age = age_env();
    let _aws_env = EnvGuard::unset("ROPS_AWS_KMS");
    let _aws_file = EnvGuard::set("ROPS_AWS_KMS_KEY_FILE", "/no/such/aws-keys");
    let source = seal("hello: world\n", None, false);
    let file = write_temp(&source);

    let config = store_config(&config_with(
        only_age(),
        Some(PartialEncryptionConfig::UnencryptedSuffix("public".to_string())),
        Some(true),
        ".*",
    ));
    assert!(Cli::refresh(RefreshArgs {
        input_args: InputArgs {
            config: Some(config.path().to_path_buf()),
            format: Some(Format::Yaml),
            file: Some(file.path().to_path_buf()),
        },
        in_place: None,
    })
    .is_ok());

    let skipped = write_temp(&seal(
        "hello: world\n",
        Some(PartialEncryptionConfig::UnencryptedSuffix("public".to_string())),
        true,
    ));
    let config = store_config(&config_with(
        only_age(),
        Some(PartialEncryptionConfig::UnencryptedSuffix("public".to_string())),
        Some(true),
        ".*",
    ));
    assert!(Cli::refresh(RefreshArgs {
        input_args: InputArgs {
            config: Some(config.path().to_path_buf()),
            format: Some(Format::Yaml),
            file: Some(skipped.path().to_path_buf()),
        },
        in_place: None,
    })
    .is_ok());

    let untouched = write_temp(&source);
    let config = store_config(&config_with(IntegrationKeys::default(), None, None, "^does-not-match$"));
    assert!(Cli::refresh(RefreshArgs {
        input_args: InputArgs {
            config: Some(config.path().to_path_buf()),
            format: Some(Format::Yaml),
            file: Some(untouched.path().to_path_buf()),
        },
        in_place: None,
    })
    .is_ok());

    let directory = tempfile::tempdir().unwrap();
    assert!(Cli::refresh(RefreshArgs {
        input_args: InputArgs {
            config: Some(directory.path().to_path_buf()),
            format: Some(Format::Yaml),
            file: Some(file.path().to_path_buf()),
        },
        in_place: None,
    })
    .is_err());

    std::env::remove_var("ROPS_AGE");
    let config = store_config(&config_with(only_age(), None, Some(true), ".*"));
    assert!(Cli::refresh(RefreshArgs {
        input_args: InputArgs {
            config: Some(config.path().to_path_buf()),
            format: Some(Format::Yaml),
            file: Some(file.path().to_path_buf()),
        },
        in_place: None,
    })
    .is_err());

    let _age = age_env();
    let config = store_config(&config_with(IntegrationKeys::default(), None, None, ".*"));
    assert!(Cli::refresh(RefreshArgs {
        input_args: InputArgs {
            config: Some(config.path().to_path_buf()),
            format: Some(Format::Yaml),
            file: Some(file.path().to_path_buf()),
        },
        in_place: None,
    })
    .is_err());

    let rewrite = write_temp(&source);
    let Some(_read_only) = ModeGuard::if_enforced(rewrite.path(), 0o444, write_denied) else {
        return;
    };
    let config = store_config(&config_with(only_age(), None, None, ".*"));
    assert!(Cli::refresh(RefreshArgs {
        input_args: InputArgs {
            config: Some(config.path().to_path_buf()),
            format: Some(Format::Yaml),
            file: Some(rewrite.path().to_path_buf()),
        },
        in_place: Some(true),
    })
    .is_err());
}

#[test]
#[serial_test::serial(config_retrieval)]
fn edit_reports_a_missing_file() {
    require_terminal_stdin();
    assert!(Cli::edit(input(Path::new("/no/such/rops-edit.yaml"), Format::Yaml)).is_err());
}

fn edit_file(editor: &Path, file: &Path) -> anyhow::Result<()> {
    let _alarm = Alarm::seconds(15);
    let _editor = EnvGuard::set("EDITOR", editor);
    Cli::edit(input(file, Format::Yaml))
}

#[test]
#[serial_test::serial(config_retrieval)]
fn edits_a_file_and_stdin() {
    require_terminal_stdin();
    let (_age, file) = encrypted_yaml();
    let (_dir, editor) = write_script("printf 'hello: world\\n' > \"$1\"");
    assert!(edit_file(&editor, file.path()).is_ok());

    let stored = write_temp(&std::fs::read_to_string(file.path()).unwrap());
    let input_file = std::fs::File::open(stored.path()).unwrap();
    let _stdin = SavedFd::redirect_to(0, &input_file);
    let _alarm = Alarm::seconds(15);
    let _editor = EnvGuard::set("EDITOR", &editor);
    assert!(Cli::edit(InputArgs {
        config: None,
        format: Some(Format::Yaml),
        file: None,
    })
    .is_ok());
}

#[test]
#[serial_test::serial(config_retrieval)]
fn edit_reports_map_encryption_and_editor_failures() {
    require_terminal_stdin();
    let (_age, file) = encrypted_yaml();
    let (_dir, editor) = write_script("printf 'n: 18446744073709551615\\n' > \"$1\"");
    assert!(edit_file(&editor, file.path()).is_err());

    let (_dir, editor) = write_script("echo boom >&2\nexit 1");
    assert!(edit_file(&editor, file.path()).is_err());

    let (_dir, editor) = write_script("printf '\\377' >&2\nexit 1");
    assert!(edit_file(&editor, file.path()).is_err());

    let (_dir, editor) = write_script("rm -f \"$1\"");
    assert!(edit_file(&editor, file.path()).is_err());

    let _editor = EnvGuard::set("EDITOR", "/no/such/editor");
    let _alarm = Alarm::seconds(15);
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_err());

    let _editor = EnvGuard::set("EDITOR", "\"");
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_err());

    let invalid = std::ffi::OsString::from_vec(vec![0xff]);
    let _editor = EnvGuard::set("EDITOR", invalid);
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_err());
}

#[test]
#[serial_test::serial(config_retrieval)]
fn edit_retries_when_stdout_is_not_a_terminal() {
    require_terminal_stdin();
    let (_age, file) = encrypted_yaml();
    let body = "if [ ! -f \"$1.tried\" ]; then touch \"$1.tried\"; printf '[\\n' > \"$1\"; exit 0; fi\nrm -f \"$1.tried\"\nprintf 'hello: world\\n' > \"$1\"";
    let (_dir, editor) = write_script(body);
    let _stdout = SavedFd::stdout_to_pipe();
    assert!(edit_file(&editor, file.path()).is_ok());
}

#[test]
#[serial_test::serial(config_retrieval)]
fn edit_falls_back_through_vim_nano_and_vi() {
    require_terminal_stdin();
    let (_age, file) = encrypted_yaml();
    let _alarm = Alarm::seconds(15);
    let _editor = EnvGuard::unset("EDITOR");

    let vim_dir = tempfile::tempdir().unwrap();
    executable_named(vim_dir.path(), "vim");
    let _path = EnvGuard::set("PATH", vim_dir.path());
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_ok());
    drop(_path);

    let nano_dir = tempfile::tempdir().unwrap();
    executable_named(nano_dir.path(), "nano");
    let _path = EnvGuard::set("PATH", nano_dir.path());
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_ok());
    drop(_path);

    let vi_dir = tempfile::tempdir().unwrap();
    executable_named(vi_dir.path(), "vi");
    let _path = EnvGuard::set("PATH", vi_dir.path());
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_ok());
    drop(_path);

    let empty = tempfile::tempdir().unwrap();
    let _path = EnvGuard::set("PATH", empty.path());
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_err());
}

fn without_extension(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret");
    std::fs::write(&path, contents).unwrap();
    (directory, path)
}

fn plain_input(path: &Path) -> InputArgs {
    InputArgs {
        config: None,
        format: None,
        file: Some(path.to_path_buf()),
    }
}

#[test]
#[serial_test::serial(config_retrieval)]
fn rejects_input_whose_format_cannot_be_inferred() {
    let (_directory, path) = without_extension("hello: world\n");
    assert!(Cli::decrypt(DecryptArgs {
        input_args: plain_input(&path),
        in_place: None,
    })
    .is_err());
    assert!(Cli::encrypt(EncryptArgs {
        integration_keys: IntegrationKeys::default(),
        partial_encryption_args: None,
        mac_only_encrypted: None,
        input_args: plain_input(&path),
        in_place: None,
    })
    .is_err());
    assert!(Cli::edit(plain_input(&path)).is_err());
    assert!(Cli::refresh(RefreshArgs {
        input_args: plain_input(&path),
        in_place: None,
    })
    .is_err());

    let keys = KeyInputArgs {
        integration_keys: IntegrationKeys::default(),
        format: None,
        file: path.clone(),
    };
    assert!(Cli::keys(KeysSubcommand::Add(keys)).is_err());
    let keys = KeyInputArgs {
        integration_keys: IntegrationKeys::default(),
        format: None,
        file: path,
    };
    assert!(Cli::keys(KeysSubcommand::Remove(keys)).is_err());
}

struct CwdGuard(std::path::PathBuf);

impl CwdGuard {
    fn enter(path: &Path) -> Self {
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        Self(previous)
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

#[test]
#[serial_test::serial(config_retrieval)]
fn edit_reports_decrypt_tempfile_and_write_failures() {
    require_terminal_stdin();
    let (_age, file) = encrypted_yaml();
    std::env::remove_var("ROPS_AGE");
    let _no_key_file = EnvGuard::set("ROPS_AGE_KEY_FILE", "/no/such/age-keys");
    let _editor = EnvGuard::set("EDITOR", "/no/such/editor");
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_err());
    drop(_no_key_file);
    drop(_editor);

    let (_age, file) = encrypted_yaml();
    let (_dir, editor) = write_script("printf 'hello: world\\n' > \"$1\"");
    let Some(_read_only) = ModeGuard::if_enforced(file.path(), 0o444, write_denied) else {
        return;
    };
    assert!(edit_file(&editor, file.path()).is_err());
    drop(_read_only);

    let directory = tempfile::tempdir().unwrap();
    let _cwd = CwdGuard::enter(directory.path());
    let Some(_read_only_directory) = ModeGuard::if_enforced(directory.path(), 0o555, create_denied) else {
        return;
    };
    assert!(edit_file(&editor, file.path()).is_err());
    drop(_read_only_directory);
    drop(_cwd);

    // A full filesystem can only be forced with a mount, which needs root. A process-wide
    // RLIMIT_FSIZE would also fail writes in the parallel tests, so this write error is skipped.
    eprintln!("skipped: a full filesystem needs a mount (root), so the temp-file write error in `edit` is not exercised");
}

#[test]
#[serial_test::serial(config_retrieval)]
fn edit_cancel_and_read_errors_come_from_the_terminal() {
    let _age = age_env();
    let file = write_temp(&seal("hello: world\n", None, false));
    let (_dir, editor) = write_script("printf '[\\n' > \"$1\"");
    let _alarm = Alarm::seconds(3);

    let pty = Pty::open();
    pty.make_raw();
    pty.write_master(&[0x03]);
    let (_stdin, _stdout) = pty.attach_stdio();
    let _editor = EnvGuard::set("EDITOR", &editor);
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_ok());
    drop(_editor);
    drop(_stdout);
    drop(_stdin);
    drop(pty);

    let pty = Pty::open();
    pty.make_raw();
    let master = pty.take_master();
    let (_stdin, _stdout) = pty.attach_stdio();
    let closer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        close_raw(master);
    });
    let _editor = EnvGuard::set("EDITOR", &editor);
    assert!(Cli::edit(input(file.path(), Format::Yaml)).is_err());
    closer.join().unwrap();
}

fn with_kms(encrypted: &str, entries: &[(&str, &str)]) -> String {
    let mut body = String::from("  kms:\n");
    for (profile, arn) in entries {
        body.push_str(&format!("  - aws_profile: {profile}\n    arn: {arn}\n    enc: YQ==\n"));
    }
    encrypted.replacen("sops:\n", &format!("sops:\n{body}"), 1)
}

#[test]
#[serial_test::serial(config_retrieval)]
fn remove_reports_reencryption_failures() {
    require_terminal_stdin();
    let _age = age_env();
    let _aws_env = EnvGuard::unset("ROPS_AWS_KMS");
    let _aws_file = EnvGuard::set("ROPS_AWS_KMS_KEY_FILE", "/no/such/aws-keys");
    let sealed = seal("hello: world\n", None, false);
    let mock_key = <AwsKmsIntegration as Integration>::KeyId::mock();
    let mock_display = mock_key.to_string();
    let (profile, arn) = mock_display.split_once('.').unwrap();
    let second_arn = "arn:aws:kms:eu-north-1:822284028627:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    let age_file = write_temp(&with_kms(&sealed, &[(profile, arn)]));
    assert!(Cli::keys(KeysSubcommand::Remove(KeyInputArgs {
        integration_keys: only_age(),
        format: Some(Format::Yaml),
        file: age_file.path().to_path_buf(),
    }))
    .is_err());

    let second: <AwsKmsIntegration as Integration>::KeyId = format!("other.{second_arn}").parse().unwrap();
    let aws_file = write_temp(&with_kms(&sealed, &[(profile, arn), ("other", second_arn)]));
    assert!(Cli::keys(KeysSubcommand::Remove(KeyInputArgs {
        integration_keys: IntegrationKeys {
            age: vec![],
            aws_kms: vec![second],
        },
        format: Some(Format::Yaml),
        file: aws_file.path().to_path_buf(),
    }))
    .is_err());
}
