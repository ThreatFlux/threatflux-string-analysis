use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn internal_markdown_links_resolve() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut documents = root_markdown_files(&manifest_dir);
    collect_markdown_files(&manifest_dir.join("docs"), &mut documents);
    documents.sort();

    let links = Regex::new(r#"(?m)(?P<image>!)?\[[^\]\n]*\]\((?P<destination>[^)\n]+)\)"#).unwrap();
    let mut checked = 0usize;

    for document in documents {
        let contents = fs::read_to_string(&document).unwrap();
        for captures in links.captures_iter(&contents) {
            if captures.name("image").is_some() {
                continue;
            }
            let Some(destination) = captures.name("destination") else {
                continue;
            };
            let target = destination.as_str().trim();
            let target = target
                .strip_prefix('<')
                .and_then(|target| target.strip_suffix('>'))
                .unwrap_or(target);
            let target = target.split_ascii_whitespace().next().unwrap_or_default();
            if target.is_empty()
                || target.starts_with('#')
                || target.contains("://")
                || target.starts_with("mailto:")
                || target.starts_with("data:")
            {
                continue;
            }

            let path = target.split_once('#').map_or(target, |(path, _)| path);
            let path = path.split_once('?').map_or(path, |(path, _)| path);
            if path.is_empty() {
                continue;
            }
            let resolved = document.parent().unwrap().join(path);
            assert!(
                resolved.exists(),
                "{} links to missing path {target:?} (resolved as {})",
                document.display(),
                resolved.display()
            );
            checked = checked.saturating_add(1);
        }
    }

    assert!(
        checked > 10,
        "link parser did not exercise the documentation set"
    );
}

fn root_markdown_files(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "md"))
        .collect()
}

fn collect_markdown_files(directory: &Path, documents: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_markdown_files(&path, documents);
        } else if path.extension().is_some_and(|extension| extension == "md") {
            documents.push(path);
        }
    }
}
