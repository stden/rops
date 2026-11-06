use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Cache {
    previous_files_in_directory: usize,
}

pub fn normalize_sops_references(references_dir: &Path, cache_path: &Path) -> anyhow::Result<()> {
    let cache = serde_yaml::from_str::<Cache>(&std::fs::read_to_string(cache_path)?)?;

    let entries_count = walkdir::WalkDir::new(references_dir).into_iter().count();

    if cache.previous_files_in_directory < entries_count {
        for file_path in walkdir::WalkDir::new(references_dir).into_iter().filter_map(|entry| match entry {
            Ok(entry) if entry.file_type().is_file() => Some(entry.into_path()),
            _ => None,
        }) {
            let content = std::fs::read_to_string(&file_path)?;
            let normalized_content = match file_path.extension().and_then(|extension| extension.to_str()) {
                Some("yaml") => {
                    let value = serde_yaml::from_str::<serde_yaml::Value>(&content)?;
                    to_sops_yaml(&value).expect("yaml values serialize")
                }
                Some("json") => {
                    let value = serde_json::from_str::<serde_json::Value>(&content)?;
                    serde_json::to_string(&value).expect("json values serialize")
                }
                _ => unimplemented!(),
            };
            std::fs::write(file_path, normalized_content)?;
        }

        std::fs::write(
            cache_path,
            to_sops_yaml(&Cache {
                previous_files_in_directory: entries_count,
            })
            .expect("the reference cache serializes"),
        )?
    }

    Ok(())
}

/// Same layout as `YamlFileFormat::serialize_to_string`: indentless block sequences.
pub fn to_sops_yaml<T: Serialize>(value: &T) -> Result<String, serde_yaml::Error> {
    let config = noyalib::SerializerConfig::new()
        .compact_list_indent(true)
        .prefer_single_quotes(true);
    let yaml = noyalib::to_string_with_config(value, &config).map_err(serde_yaml::Error::from)?;
    Ok(with_trailing_newline(yaml))
}

pub fn with_trailing_newline(mut yaml: String) -> String {
    if !yaml.ends_with('\n') {
        yaml.push('\n');
    }
    yaml
}
