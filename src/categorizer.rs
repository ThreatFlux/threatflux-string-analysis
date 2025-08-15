//! String categorization functionality

use crate::types::AnalysisResult;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

// Type aliases to reduce complexity
type MatcherFn = Box<dyn Fn(&str) -> bool + Send + Sync>;

// Pre-compiled regex patterns for performance
static IPV4_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());

static IPV6_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$|^::1$|^::$").unwrap());

static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

/// Represents a category that strings can belong to
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StringCategory {
    /// Name of the category
    pub name: String,
    /// Parent category (for hierarchical categorization)
    pub parent: Option<String>,
    /// Description of what this category represents
    pub description: String,
}

/// Rule for categorizing strings
pub struct CategoryRule {
    /// Name of the rule
    pub name: String,
    /// Function that determines if a string matches this rule
    pub matcher: MatcherFn,
    /// Category to assign if the rule matches
    pub category: StringCategory,
    /// Priority (higher priority rules are evaluated first)
    pub priority: i32,
}

/// Trait for categorizing strings
pub trait Categorizer: Send + Sync {
    /// Categorize a string
    fn categorize(&self, value: &str) -> Vec<StringCategory>;

    /// Add a categorization rule
    fn add_rule(&mut self, rule: CategoryRule) -> AnalysisResult<()>;

    /// Remove a rule by name
    fn remove_rule(&mut self, name: &str) -> AnalysisResult<()>;

    /// Get all categories
    fn get_categories(&self) -> Vec<StringCategory>;
}

/// Default categorizer implementation
pub struct DefaultCategorizer {
    rules: Vec<CategoryRule>,
}

impl DefaultCategorizer {
    /// Create a new categorizer with default rules
    pub fn new() -> Self {
        let mut categorizer = Self { rules: Vec::new() };

        // Add default rules
        categorizer.add_default_rules();

        categorizer
    }

    /// Create an empty categorizer
    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    fn add_default_rules(&mut self) {
        // URL categorization
        self.rules.push(CategoryRule {
            name: "url_rule".to_string(),
            matcher: Box::new(|s| {
                s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
            }),
            category: StringCategory {
                name: "url".to_string(),
                parent: Some("network".to_string()),
                description: "URL or web address".to_string(),
            },
            priority: 100,
        });

        // File path categorization
        self.rules.push(CategoryRule {
            name: "path_rule".to_string(),
            matcher: Box::new(|s| {
                (s.contains('/') || s.contains('\\'))
                    && (s.starts_with("/") || s.starts_with("\\") || s.contains(":\\"))
            }),
            category: StringCategory {
                name: "path".to_string(),
                parent: Some("filesystem".to_string()),
                description: "File system path".to_string(),
            },
            priority: 90,
        });

        // Registry key categorization
        self.rules.push(CategoryRule {
            name: "registry_rule".to_string(),
            matcher: Box::new(|s| s.starts_with("HKEY_") || s.contains("\\SOFTWARE\\")),
            category: StringCategory {
                name: "registry".to_string(),
                parent: Some("windows".to_string()),
                description: "Windows registry key".to_string(),
            },
            priority: 95,
        });

        // Library/DLL categorization
        self.rules.push(CategoryRule {
            name: "library_rule".to_string(),
            matcher: Box::new(|s| {
                s.ends_with(".dll") || s.ends_with(".so") || s.ends_with(".dylib") ||
                s.contains(".so.") || // versioned shared libraries like libc.so.6
                (s.ends_with(".dll") || s.contains("kernel32") || s.contains("ntdll"))
            }),
            category: StringCategory {
                name: "library".to_string(),
                parent: Some("binary".to_string()),
                description: "Shared library or DLL".to_string(),
            },
            priority: 85,
        });

        // Command categorization
        self.rules.push(CategoryRule {
            name: "command_rule".to_string(),
            matcher: Box::new(|s| {
                s.contains("cmd")
                    || s.contains("powershell")
                    || s.contains("bash")
                    || s.contains("/bin/")
            }),
            category: StringCategory {
                name: "command".to_string(),
                parent: Some("execution".to_string()),
                description: "Command or shell-related string".to_string(),
            },
            priority: 80,
        });

        // IP address categorization (IPv4 and IPv6)
        self.rules.push(CategoryRule {
            name: "ip_rule".to_string(),
            matcher: Box::new(|s| IPV4_REGEX.is_match(s) || IPV6_REGEX.is_match(s)),
            category: StringCategory {
                name: "ip_address".to_string(),
                parent: Some("network".to_string()),
                description: "IP address (IPv4 or IPv6)".to_string(),
            },
            priority: 95,
        });

        // Email categorization
        self.rules.push(CategoryRule {
            name: "email_rule".to_string(),
            matcher: Box::new(|s| s.contains('@') && s.contains('.') && EMAIL_REGEX.is_match(s)),
            category: StringCategory {
                name: "email".to_string(),
                parent: Some("contact".to_string()),
                description: "Email address".to_string(),
            },
            priority: 85,
        });

        // API call categorization
        self.rules.push(CategoryRule {
            name: "api_call_rule".to_string(),
            matcher: Box::new(|s| {
                // Common Windows API calls
                s.contains("CreateProcess") || s.contains("VirtualAlloc") || s.contains("WriteProcessMemory") ||
                s.contains("GetProcAddress") || s.contains("LoadLibrary") || s.contains("OpenProcess") ||
                // Unix/Linux API calls
                s == "malloc" || s == "calloc" || s == "realloc" || s == "free" ||
                s == "fork" || s == "exec" || s == "open" || s == "read" || s == "write" ||
                // Common API patterns
                s.ends_with("A") && s.len() > 5 && s.chars().any(|c| c.is_uppercase()) // Windows API naming pattern
            }),
            category: StringCategory {
                name: "api_call".to_string(),
                parent: Some("system".to_string()),
                description: "System API call".to_string(),
            },
            priority: 90,
        });

        // Sort rules by priority (descending)
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
}

impl Categorizer for DefaultCategorizer {
    fn categorize(&self, value: &str) -> Vec<StringCategory> {
        let mut categories = Vec::new();

        for rule in &self.rules {
            if (rule.matcher)(value) {
                categories.push(rule.category.clone());
            }
        }

        // If no specific category matched, return generic
        if categories.is_empty() {
            categories.push(StringCategory {
                name: "generic".to_string(),
                parent: None,
                description: "Generic string".to_string(),
            });
        }

        categories
    }

    fn add_rule(&mut self, rule: CategoryRule) -> AnalysisResult<()> {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    fn remove_rule(&mut self, name: &str) -> AnalysisResult<()> {
        self.rules.retain(|r| r.name != name);
        Ok(())
    }

    fn get_categories(&self) -> Vec<StringCategory> {
        let mut categories = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for rule in &self.rules {
            if seen.insert(rule.category.name.clone()) {
                categories.push(rule.category.clone());
            }
        }

        categories
    }
}

impl Default for DefaultCategorizer {
    fn default() -> Self {
        Self::new()
    }
}
