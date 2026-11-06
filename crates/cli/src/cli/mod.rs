pub struct Cli;

mod common;
mod decrypt;
mod edit;
mod encrypt;
mod keys;
mod refresh;

#[cfg(test)]
mod coverage;
#[cfg(test)]
mod test_fd;
