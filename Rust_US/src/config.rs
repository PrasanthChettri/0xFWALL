use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub kernel_path: String,
    pub rules_path: String,
    pub log_path: String,
    pub interface: String,
}

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, i32> {
        let content = fs::read_to_string(path).map_err(|_| -1)?;
        serde_yaml::from_str(&content).map_err(|_| -1)
    }
}
