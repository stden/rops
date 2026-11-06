use std::{
    io::{IsTerminal, Read},
    path::Path,
};

use anyhow::bail;
use clap::ValueEnum;

use crate::*;

impl Cli {
    pub fn get_input_string(file_path: Option<&Path>, in_place: Option<bool>) -> anyhow::Result<String> {
        let mut stdin_guard = std::io::stdin().lock();

        let input_string = match in_place.unwrap_or_default() {
            true => read_from_path(file_path.expect(IN_PLACE_PANIC), stdin_guard)?,
            false => match &file_path {
                Some(plaintext_path) => read_from_path(plaintext_path, stdin_guard)?,
                None => {
                    if stdin_guard.is_terminal() {
                        bail!(RopsCliError::MissingInput)
                    }
                    let mut stdin_string = String::new();
                    stdin_guard.read_to_string(&mut stdin_string)?;
                    stdin_string
                }
            },
        };

        return Ok(input_string);

        fn read_from_path(path: &Path, stdin_guard: std::io::StdinLock<'_>) -> anyhow::Result<String> {
            if !stdin_guard.is_terminal() {
                bail!(RopsCliError::MultipleInputs)
            }
            drop(stdin_guard);

            std::fs::read_to_string(path).map_err(Into::into)
        }
    }

    pub fn get_format(explicit_file_path: Option<&Path>, explicit_format: Option<Format>) -> Result<Format, RopsCliError> {
        match explicit_format {
            Some(format) => Ok(format),
            None => match explicit_file_path {
                Some(file_path) => file_path
                    .extension()
                    .and_then(|file_extension| {
                        <Format as ValueEnum>::from_str(file_extension.to_str().expect("invalid unicode"), true).ok()
                    })
                    .ok_or_else(|| UndeterminedFormatError::NoFileExtension(file_path.to_path_buf()).into()),
                None => Err(UndeterminedFormatError::FoundNeither.into()),
            },
        }
    }

    pub fn write_or_print(in_place: Option<bool>, explicit_file_path: Option<&Path>, output_str: &str) -> std::io::Result<()> {
        match in_place.unwrap_or_default() {
            true => {
                // TODO: improve error message
                std::fs::write(explicit_file_path.expect(IN_PLACE_PANIC), output_str)?;
            }
            false => {
                println!("{output_str}");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::IsTerminal;

    use super::*;

    #[test]
    fn infers_format_by_extension() {
        assert_eq!(Format::Yaml, Cli::get_format(Some(Path::new("test.yaml")), None).unwrap())
    }

    #[test]
    fn infers_format_by_extension_alias() {
        assert_eq!(Format::Yaml, Cli::get_format(Some(Path::new("test.yml")), None).unwrap())
    }

    #[test]
    fn both_missing_is_undetermined_format() {
        assert_eq!(
            RopsCliError::UndeterminedFormat(UndeterminedFormatError::FoundNeither),
            Cli::get_format(None, None).unwrap_err()
        )
    }

    #[test]
    fn errors_on_missing_file_extension() {
        assert!(matches!(
            Cli::get_format(Some(Path::new("test")), None).unwrap_err(),
            RopsCliError::UndeterminedFormat(UndeterminedFormatError::NoFileExtension(_))
        ))
    }

    #[test]
    fn honors_an_explicit_format() {
        assert_eq!(Format::Json, Cli::get_format(None, Some(Format::Json)).unwrap());
        assert_eq!(Format::Toml, Cli::get_format(None, Some(Format::Toml)).unwrap());
    }

    #[test]
    fn in_place_write_errors_are_reported() {
        assert!(Cli::write_or_print(Some(true), Some(Path::new("/dev/full")), "rops").is_err());
    }

    #[test]
    fn rejects_an_unknown_extension() {
        assert!(matches!(
            Cli::get_format(Some(Path::new("file.txt")), None).unwrap_err(),
            RopsCliError::UndeterminedFormat(UndeterminedFormatError::NoFileExtension(_))
        ))
    }

    #[test]
    fn prints_when_not_in_place() {
        assert!(Cli::write_or_print(None, None, "rops").is_ok());
        assert!(Cli::write_or_print(Some(false), None, "rops").is_ok());
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn stdin_read_errors_are_reported() {
        let directory = std::fs::File::open("/").unwrap();
        let _saved = super::super::test_fd::SavedFd::redirect_to(0, &directory);
        assert!(Cli::get_input_string(None, None).is_err());
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn reads_piped_stdin() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "piped").unwrap();
        let input = std::fs::File::open(file.path()).unwrap();
        let _saved = super::super::test_fd::SavedFd::redirect_to(0, &input);
        assert_eq!("piped", Cli::get_input_string(None, None).unwrap());
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn file_and_piped_stdin_are_multiple_inputs() {
        let devnull = std::fs::File::open("/dev/null").unwrap();
        let _saved = super::super::test_fd::SavedFd::redirect_to(0, &devnull);
        let error = Cli::get_input_string(Some(Path::new("anything")), None).unwrap_err();
        assert_eq!(Some(&RopsCliError::MultipleInputs), error.downcast_ref());
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn missing_input_on_a_terminal() {
        assert!(std::io::stdin().is_terminal(), "run file-input tests under script");
        let error = Cli::get_input_string(None, None).unwrap_err();
        assert_eq!(Some(&RopsCliError::MissingInput), error.downcast_ref());
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn reads_a_file_from_both_in_place_arms() {
        assert!(std::io::stdin().is_terminal(), "run file-input tests under script");
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "inplace").unwrap();
        assert_eq!("inplace", Cli::get_input_string(Some(file.path()), Some(true)).unwrap());
        assert_eq!("inplace", Cli::get_input_string(Some(file.path()), None).unwrap());
        assert_eq!("inplace", Cli::get_input_string(Some(file.path()), Some(false)).unwrap());
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn in_place_read_errors_are_reported() {
        assert!(std::io::stdin().is_terminal(), "run file-input tests under script");
        let error = Cli::get_input_string(Some(Path::new("/no/such/rops-input")), Some(true)).unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_some());
    }
}
