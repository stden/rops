#![feature(coverage_attribute)]

const REFERENCES_DIR: &str = "tests/sops_references";

// WORKAROUND: cargo:rerun-if-changed=REFERENCES_DIR would always be triggered
// Naive approach that works well enough.
const CACHE_PATH: &str = "tests/sops_references/cache.yaml";

// Covered by the library tests of this file. The build script runs only while the cache is current.
#[coverage(off)]
mod normalize {
    include!("sops_reference_normalize.rs");
}

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(coverage)");
    println!("cargo::rustc-check-cfg=cfg(coverage_nightly)");
    println!("cargo:rerun-if-changed={CACHE_PATH}");
    normalize::normalize_sops_references(std::path::Path::new(REFERENCES_DIR), std::path::Path::new(CACHE_PATH))
}
