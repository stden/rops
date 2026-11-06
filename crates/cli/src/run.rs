use clap::Parser;

use crate::*;

pub fn run() -> anyhow::Result<()> {
    dispatch(CliArgs::parse())
}

fn dispatch(mut args: CliArgs) -> anyhow::Result<()> {
    args.merge_config(Config::retrieve(args.config_path())?);

    match args.cmd {
        CliSubcommand::Encrypt(encrypt_args) => Cli::encrypt(encrypt_args),
        CliSubcommand::Decrypt(decrypt_args) => Cli::decrypt(decrypt_args),
        CliSubcommand::Edit(input_args) => Cli::edit(input_args),
        CliSubcommand::Keys(key_command) => Cli::keys(key_command),
        CliSubcommand::Refresh(refresh_args) => Cli::refresh(refresh_args),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn parse(args: &[&str]) -> CliArgs {
        CliArgs::try_parse_from(args).unwrap()
    }

    #[test]
    fn reports_a_bad_config_path() {
        let directory = tempfile::tempdir().unwrap();
        let args = parse(&[
            "rops",
            "decrypt",
            "--config",
            directory.path().to_str().unwrap(),
            "--format",
            "yaml",
        ]);
        assert!(dispatch(args).is_err());
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn dispatches_each_subcommand() {
        let missing = "/no/such/rops-coverage-file";
        let invocations: &[&[&str]] = &[
            &["rops", "encrypt", "--format", "yaml", missing],
            &["rops", "decrypt", "--format", "json", missing],
            &["rops", "edit", "--format", "toml", missing],
            &["rops", "keys", "add", "--format", "json", missing],
            &["rops", "keys", "remove", "--format", "toml", missing],
            &["rops", "refresh", "--format", "yaml", missing],
        ];

        for invocation in invocations {
            assert!(dispatch(parse(invocation)).is_err());
        }
    }
}
