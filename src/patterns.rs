//! Pattern matching and pattern provider functionality

use crate::types::AnalysisResult;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Represents a pattern used for string matching and categorization
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Unique name for the pattern
    pub name: String,
    /// Regular expression
    pub regex: Regex,
    /// Category this pattern belongs to
    pub category: String,
    /// Description of what this pattern matches
    pub description: String,
    /// Whether matches are considered suspicious
    pub is_suspicious: bool,
    /// Severity level (0-10) if suspicious
    pub severity: u8,
}

/// Serializable pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDef {
    pub name: String,
    pub regex: String,
    pub category: String,
    pub description: String,
    pub is_suspicious: bool,
    pub severity: u8,
}

impl PatternDef {
    /// Convert to a compiled Pattern
    pub fn compile(self) -> AnalysisResult<Pattern> {
        Ok(Pattern {
            name: self.name,
            regex: Regex::new(&self.regex)?,
            category: self.category,
            description: self.description,
            is_suspicious: self.is_suspicious,
            severity: self.severity,
        })
    }
}

/// Trait for providing patterns
pub trait PatternProvider: Send + Sync {
    /// Get all patterns
    fn get_patterns(&self) -> Vec<Pattern>;

    /// Add a new pattern
    fn add_pattern(&mut self, pattern: PatternDef) -> AnalysisResult<()>;

    /// Remove a pattern by name
    fn remove_pattern(&mut self, name: &str) -> AnalysisResult<()>;

    /// Update an existing pattern
    fn update_pattern(&mut self, pattern: PatternDef) -> AnalysisResult<()>;
}

/// Default pattern provider with built-in security patterns
pub struct DefaultPatternProvider {
    patterns: Vec<Pattern>,
}

impl DefaultPatternProvider {
    /// Create a new provider with default security patterns
    pub fn new() -> AnalysisResult<Self> {
        let mut provider = Self {
            patterns: Vec::new(),
        };

        // Network indicators
        provider.add_pattern(PatternDef {
            name: "url_pattern".to_string(),
            regex: r"(?i)(https?|ftp|ssh|telnet|rdp)://".to_string(),
            category: "network".to_string(),
            description: "URL or network protocol".to_string(),
            is_suspicious: true,
            severity: 3,
        })?;

        provider.add_pattern(PatternDef {
            name: "ip_address".to_string(),
            regex: r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b".to_string(),
            category: "network".to_string(),
            description: "IP address pattern".to_string(),
            is_suspicious: true,
            severity: 4,
        })?;

        // Command execution
        provider.add_pattern(PatternDef {
            name: "shell_command".to_string(),
            regex: r"(?i)(cmd\.exe|powershell|bash|sh)".to_string(),
            category: "command".to_string(),
            description: "Shell command interpreter".to_string(),
            is_suspicious: true,
            severity: 6,
        })?;

        provider.add_pattern(PatternDef {
            name: "code_execution".to_string(),
            regex: r"(?i)(eval|exec|system|shell)".to_string(),
            category: "execution".to_string(),
            description: "Code execution function".to_string(),
            is_suspicious: true,
            severity: 7,
        })?;

        // Crypto/encoding
        provider.add_pattern(PatternDef {
            name: "crypto_algorithm".to_string(),
            regex: r"(?i)(base64|rot13|xor|aes|des|rsa)".to_string(),
            category: "crypto".to_string(),
            description: "Cryptographic or encoding algorithm".to_string(),
            is_suspicious: true,
            severity: 5,
        })?;

        provider.add_pattern(PatternDef {
            name: "base64_string".to_string(),
            regex: r"^[A-Za-z0-9+/]{20,}={0,2}$".to_string(),
            category: "encoding".to_string(),
            description: "Potential Base64 encoded string".to_string(),
            is_suspicious: true,
            severity: 4,
        })?;

        // File paths
        provider.add_pattern(PatternDef {
            name: "suspicious_path".to_string(),
            regex: r"(?i)(\\temp\\|\/tmp\/|\\windows\\system32)".to_string(),
            category: "path".to_string(),
            description: "Suspicious file path".to_string(),
            is_suspicious: true,
            severity: 5,
        })?;

        // Credentials
        provider.add_pattern(PatternDef {
            name: "credential_keyword".to_string(),
            regex: r"(?i)(passwords?|credential|secret|token|api[_-]?key)".to_string(),
            category: "credential".to_string(),
            description: "Credential-related keyword".to_string(),
            is_suspicious: true,
            severity: 8,
        })?;

        // Registry
        provider.add_pattern(PatternDef {
            name: "registry_key".to_string(),
            regex: r"(?i)(HKEY_|SOFTWARE\\Microsoft\\Windows)".to_string(),
            category: "registry".to_string(),
            description: "Windows registry key".to_string(),
            is_suspicious: true,
            severity: 5,
        })?;

        // Malware indicators
        provider.add_pattern(PatternDef {
            name: "malware_keyword".to_string(),
            regex: r"(?i)(dropper|payload|inject|hook|rootkit)".to_string(),
            category: "malware".to_string(),
            description: "Common malware terminology".to_string(),
            is_suspicious: true,
            severity: 9,
        })?;

        provider.add_pattern(PatternDef {
            name: "surveillance_keyword".to_string(),
            regex: r"(?i)(keylog|screenshot|webcam|microphone)".to_string(),
            category: "surveillance".to_string(),
            description: "Surveillance/spyware functionality".to_string(),
            is_suspicious: true,
            severity: 8,
        })?;

        Ok(provider)
    }

    /// Create an empty provider
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }
}

impl PatternProvider for DefaultPatternProvider {
    fn get_patterns(&self) -> Vec<Pattern> {
        self.patterns.clone()
    }

    fn add_pattern(&mut self, pattern_def: PatternDef) -> AnalysisResult<()> {
        let pattern = pattern_def.compile()?;
        self.patterns.push(pattern);
        Ok(())
    }

    fn remove_pattern(&mut self, name: &str) -> AnalysisResult<()> {
        self.patterns.retain(|p| p.name != name);
        Ok(())
    }

    fn update_pattern(&mut self, pattern_def: PatternDef) -> AnalysisResult<()> {
        self.remove_pattern(&pattern_def.name)?;
        self.add_pattern(pattern_def)?;
        Ok(())
    }
}

impl Default for DefaultPatternProvider {
    fn default() -> Self {
        Self::new().expect("Failed to create default pattern provider")
    }
}
