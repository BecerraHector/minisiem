//! Adapter: loads Sigma rules from a directory tree.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::detection::sigma::{RuleSet, parse_documents};

#[derive(Debug)]
pub struct LoadError {
    pub path: PathBuf,
    pub message: String,
}

impl LoadError {
    fn new(path: &Path, message: impl ToString) -> Self {
        Self {
            path: path.to_path_buf(),
            message: message.to_string(),
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for LoadError {}

/// Loads every `*.yml` / `*.yaml` file under `dir`, in path order, and links
/// correlations to the rules they reference (which may live in other files).
/// The first invalid rule aborts loading: a rule that silently fails to load
/// is a detection gap nobody knows about.
pub fn load_dir(dir: &Path) -> Result<RuleSet, LoadError> {
    let mut files = Vec::new();
    collect_rule_files(dir, &mut files)?;
    files.sort();

    let mut documents = Vec::new();
    for path in &files {
        let yaml = fs::read_to_string(path).map_err(|e| LoadError::new(path, e))?;
        documents.extend(parse_documents(&yaml).map_err(|e| LoadError::new(path, e))?);
    }
    // Cross-file problems (unknown references, cycles) belong to the directory.
    RuleSet::new(documents).map_err(|e| LoadError::new(dir, e))
}

/// Recurses into real directories only: symlinked directories are skipped so
/// a link loop cannot hang startup.
fn collect_rule_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    for entry in fs::read_dir(dir).map_err(|e| LoadError::new(dir, e))? {
        let entry = entry.map_err(|e| LoadError::new(dir, e))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| LoadError::new(&path, e))?;

        if file_type.is_dir() {
            collect_rule_files(&path, files)?;
        } else if is_rule_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
}
