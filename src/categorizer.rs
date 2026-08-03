//! String categorization functionality.

use crate::types::{
    AnalysisError, AnalysisResult, MAX_DESCRIPTION_BYTES, compact_string, validate_identifier,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::LazyLock;

const MAX_CATEGORY_RULES: usize = 4_096;

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .expect("the built-in email regex must compile")
});

/// Thread-safe predicate used by a [`CategoryRule`].
pub type CategoryMatcher = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// A named category that can be assigned to a string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringCategory {
    /// Stable category name.
    pub name: String,
    /// Optional parent category name.
    pub parent: Option<String>,
    /// Human-readable category description.
    pub description: String,
}

impl StringCategory {
    pub(crate) fn compact(mut self) -> Self {
        self.name = compact_string(self.name);
        self.parent = self.parent.map(compact_string);
        self.description = compact_string(self.description);
        self
    }
}

/// Rule for categorizing strings.
pub struct CategoryRule {
    /// Unique rule name.
    pub name: String,
    /// Predicate that determines whether a string matches.
    pub matcher: CategoryMatcher,
    /// Category assigned on a match.
    pub category: StringCategory,
    /// Priority; larger values are evaluated first.
    pub priority: i32,
}

impl CategoryRule {
    fn validate(&self) -> AnalysisResult<()> {
        validate_identifier("category rule", &self.name)?;
        validate_category(&self.category)
    }
}

/// Interface for deterministic, thread-safe string categorizers.
pub trait Categorizer: Send + Sync {
    /// Categorize a string in deterministic rule order.
    fn categorize(&self, value: &str) -> Vec<StringCategory>;

    /// Validate and add a uniquely named rule.
    fn add_rule(&mut self, rule: CategoryRule) -> AnalysisResult<()>;

    /// Remove an existing rule by name.
    fn remove_rule(&mut self, name: &str) -> AnalysisResult<()>;

    /// Return distinct categories in deterministic rule order.
    fn get_categories(&self) -> Vec<StringCategory>;
}

/// Default heuristic categorizer.
pub struct DefaultCategorizer {
    rules: Vec<CategoryRule>,
}

impl DefaultCategorizer {
    /// Create a categorizer with the built-in informational rules.
    pub fn new() -> Self {
        let mut categorizer = Self::empty();
        categorizer.add_default_rules();
        categorizer
    }

    /// Create a categorizer without built-in rules.
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    fn add_default_rules(&mut self) {
        self.rules = vec![
            rule(
                "url",
                "url",
                "network",
                "URL or web address",
                100,
                |value| {
                    [
                        "http://",
                        "https://",
                        "ftp://",
                        "ssh://",
                        "telnet://",
                        "rdp://",
                    ]
                    .iter()
                    .any(|scheme| starts_with_ascii_case(value, scheme))
                },
            ),
            rule(
                "registry",
                "registry",
                "windows",
                "Windows registry key",
                95,
                |value| {
                    starts_with_ascii_case(value, "HKEY_")
                        || contains_ascii_case(value, "\\SOFTWARE\\")
                },
            ),
            rule(
                "ip_address",
                "ip_address",
                "network",
                "Syntactically valid IPv4 or IPv6 address",
                95,
                |value| value.parse::<IpAddr>().is_ok(),
            ),
            rule(
                "path",
                "path",
                "filesystem",
                "Absolute or drive-qualified file-system path",
                90,
                |value| {
                    value.starts_with('/')
                        || value.starts_with('\\')
                        || (value.len() >= 3
                            && value.as_bytes()[1] == b':'
                            && matches!(value.as_bytes()[2], b'\\' | b'/'))
                },
            ),
            rule(
                "api_call",
                "api_call",
                "system",
                "Known system API function name",
                90,
                is_known_api_call,
            ),
            rule(
                "library",
                "library",
                "binary",
                "Shared library or DLL name",
                85,
                |value| {
                    ends_with_ascii_case(value, ".dll")
                        || ends_with_ascii_case(value, ".so")
                        || ends_with_ascii_case(value, ".dylib")
                        || contains_ascii_case(value, ".so.")
                },
            ),
            rule(
                "email",
                "email",
                "contact",
                "Email-address-shaped string",
                85,
                |value| EMAIL_REGEX.is_match(value),
            ),
            rule(
                "command",
                "command",
                "execution",
                "Command or shell interpreter reference",
                80,
                is_command_reference,
            ),
        ];
        sort_rules(&mut self.rules);
    }
}

impl Categorizer for DefaultCategorizer {
    fn categorize(&self, value: &str) -> Vec<StringCategory> {
        let mut seen = BTreeSet::new();
        let mut categories = Vec::new();
        for rule in &self.rules {
            if (rule.matcher)(value) && seen.insert(rule.category.name.clone()) {
                categories.push(rule.category.clone());
            }
        }

        if categories.is_empty() {
            categories.push(StringCategory {
                name: "generic".to_string(),
                parent: None,
                description: "Generic string".to_string(),
            });
        }
        categories
    }

    fn add_rule(&mut self, mut rule: CategoryRule) -> AnalysisResult<()> {
        rule.validate()?;
        if self.rules.len() >= MAX_CATEGORY_RULES {
            return Err(AnalysisError::CapacityExceeded {
                resource: "category rules",
                limit: MAX_CATEGORY_RULES,
            });
        }
        if self.rules.iter().any(|existing| existing.name == rule.name) {
            return Err(AnalysisError::DuplicateName {
                kind: "category rule",
                name: rule.name.to_string(),
            });
        }
        rule.name = compact_string(rule.name);
        rule.category = rule.category.compact();
        self.rules.push(rule);
        sort_rules(&mut self.rules);
        Ok(())
    }

    fn remove_rule(&mut self, name: &str) -> AnalysisResult<()> {
        validate_identifier("category rule", name)?;
        let Some(index) = self.rules.iter().position(|rule| rule.name == name) else {
            return Err(AnalysisError::NotFound {
                kind: "category rule",
                name: name.to_string(),
            });
        };
        self.rules.remove(index);
        Ok(())
    }

    fn get_categories(&self) -> Vec<StringCategory> {
        let mut seen = BTreeSet::new();
        self.rules
            .iter()
            .filter(|rule| seen.insert(rule.category.name.clone()))
            .map(|rule| rule.category.clone())
            .collect()
    }
}

impl Default for DefaultCategorizer {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn validate_category(category: &StringCategory) -> AnalysisResult<()> {
    validate_identifier("category", &category.name)?;
    if let Some(parent) = &category.parent {
        validate_identifier("parent category", parent)?;
    }
    if category.description.len() > MAX_DESCRIPTION_BYTES {
        return Err(AnalysisError::InputTooLarge {
            field: "category.description",
            actual: category.description.len(),
            limit: MAX_DESCRIPTION_BYTES,
        });
    }
    if category.description.trim().is_empty() {
        return Err(AnalysisError::InvalidIdentifier {
            kind: "category description",
            name: category.description.clone(),
            reason: "must not be empty or whitespace-only",
        });
    }
    if category.description.chars().any(char::is_control) {
        return Err(AnalysisError::InvalidIdentifier {
            kind: "category description",
            name: category.description.to_string(),
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn sort_rules(rules: &mut [CategoryRule]) {
    rules.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.name.cmp(&right.name))
    });
}

fn rule(
    rule_name: &str,
    category_name: &str,
    parent: &str,
    description: &str,
    priority: i32,
    matcher: impl Fn(&str) -> bool + Send + Sync + 'static,
) -> CategoryRule {
    CategoryRule {
        name: rule_name.to_string(),
        matcher: Box::new(matcher),
        category: StringCategory {
            name: category_name.to_string(),
            parent: Some(parent.to_string()),
            description: description.to_string(),
        },
        priority,
    }
}

fn is_command_reference(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '.')
        .any(|token| {
            [
                "cmd",
                "cmd.exe",
                "powershell",
                "powershell.exe",
                "pwsh",
                "pwsh.exe",
                "bash",
                "dash",
                "zsh",
                "ksh",
                "sh",
            ]
            .iter()
            .any(|command| token.eq_ignore_ascii_case(command))
        })
}

fn starts_with_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn ends_with_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .as_bytes()
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix.as_bytes()))
}

fn contains_ascii_case(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(needle.as_bytes()))
}

fn is_known_api_call(value: &str) -> bool {
    matches!(
        value,
        "CreateProcess"
            | "CreateProcessA"
            | "CreateProcessW"
            | "VirtualAlloc"
            | "VirtualAllocEx"
            | "WriteProcessMemory"
            | "GetProcAddress"
            | "LoadLibrary"
            | "LoadLibraryA"
            | "LoadLibraryW"
            | "OpenProcess"
            | "CreateRemoteThread"
            | "malloc"
            | "calloc"
            | "realloc"
            | "free"
            | "fork"
            | "exec"
            | "open"
            | "read"
            | "write"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_rules_compact_owned_metadata() {
        let mut name = String::with_capacity(1_000_000);
        name.push_str("compact_rule");
        let mut category_name = String::with_capacity(1_000_000);
        category_name.push_str("compact_category");
        let mut parent = String::with_capacity(1_000_000);
        parent.push_str("parent");
        let mut description = String::with_capacity(1_000_000);
        description.push_str("Category compaction regression");
        let mut categorizer = DefaultCategorizer::empty();
        categorizer
            .add_rule(CategoryRule {
                name,
                matcher: Box::new(|_| true),
                category: StringCategory {
                    name: category_name,
                    parent: Some(parent),
                    description,
                },
                priority: 0,
            })
            .unwrap();

        let rule = &categorizer.rules[0];
        assert_eq!(rule.name.capacity(), rule.name.len());
        assert_eq!(rule.category.name.capacity(), rule.category.name.len());
        assert_eq!(
            rule.category.parent.as_ref().unwrap().capacity(),
            rule.category.parent.as_ref().unwrap().len()
        );
        assert_eq!(
            rule.category.description.capacity(),
            rule.category.description.len()
        );
    }
}
