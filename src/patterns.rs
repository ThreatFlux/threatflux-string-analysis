//! Pattern matching and pattern provider functionality.

use crate::types::{
    AnalysisError, AnalysisResult, MAX_DESCRIPTION_BYTES, MAX_REGEX_BYTES, compact_string,
    regex_error_reason, validate_identifier,
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

const REGEX_COMPILED_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const REGEX_DFA_SIZE_LIMIT: usize = 4 * 1024 * 1024;
pub(crate) const MAX_PATTERNS: usize = 4_096;

/// A validated, compiled pattern used for analysis and categorization.
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Unique name for the pattern.
    pub name: String,
    /// Compiled regular expression.
    pub regex: Regex,
    /// Category assigned when the pattern matches.
    pub category: String,
    /// Human-readable explanation of the match.
    pub description: String,
    /// Whether a match contributes a suspicious indicator.
    pub is_suspicious: bool,
    /// Severity from 0 through 10 when the match is suspicious.
    pub severity: u8,
}

impl Pattern {
    pub(crate) fn validate(&self) -> AnalysisResult<()> {
        validate_pattern_fields(&self.name, &self.category, &self.description, self.severity)?;
        validate_regex_source(self.regex.as_str())
    }

    pub(crate) fn compact(mut self) -> Self {
        self.name = compact_string(self.name);
        self.category = compact_string(self.category);
        self.description = compact_string(self.description);
        self
    }
}

/// Serializable pattern definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternDef {
    /// Unique identifier for the pattern.
    pub name: String,
    /// Regular expression source.
    pub regex: String,
    /// Category assigned when the pattern matches.
    pub category: String,
    /// Human-readable explanation of the match.
    pub description: String,
    /// Whether a match contributes a suspicious indicator.
    pub is_suspicious: bool,
    /// Severity from 0 through 10 when suspicious.
    pub severity: u8,
}

impl PatternDef {
    /// Validate and compile this definition.
    pub fn compile(self) -> AnalysisResult<Pattern> {
        validate_pattern_fields(&self.name, &self.category, &self.description, self.severity)?;
        validate_regex_source(&self.regex)?;

        let regex = RegexBuilder::new(&self.regex)
            .size_limit(REGEX_COMPILED_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .map_err(|error| AnalysisError::InvalidRegex {
                context: "pattern definition",
                reason: regex_error_reason(&error),
            })?;

        Ok(Pattern {
            name: compact_string(self.name),
            regex,
            category: compact_string(self.category),
            description: compact_string(self.description),
            is_suspicious: self.is_suspicious,
            severity: self.severity,
        })
    }
}

fn validate_regex_source(source: &str) -> AnalysisResult<()> {
    if source.len() > MAX_REGEX_BYTES {
        Err(AnalysisError::InputTooLarge {
            field: "pattern.regex",
            actual: source.len(),
            limit: MAX_REGEX_BYTES,
        })
    } else {
        Ok(())
    }
}

fn validate_pattern_fields(
    name: &str,
    category: &str,
    description: &str,
    severity: u8,
) -> AnalysisResult<()> {
    validate_identifier("pattern", name)?;
    validate_identifier("category", category)?;
    if description.len() > MAX_DESCRIPTION_BYTES {
        return Err(AnalysisError::InputTooLarge {
            field: "pattern.description",
            actual: description.len(),
            limit: MAX_DESCRIPTION_BYTES,
        });
    }
    if description.trim().is_empty() {
        return Err(AnalysisError::InvalidIdentifier {
            kind: "pattern description",
            name: description.to_string(),
            reason: "must not be empty or whitespace-only",
        });
    }
    if description.chars().any(char::is_control) {
        return Err(AnalysisError::InvalidIdentifier {
            kind: "pattern description",
            name: description.to_string(),
            reason: "must not contain control characters",
        });
    }
    if severity > 10 {
        return Err(AnalysisError::InvalidSeverity { severity });
    }
    Ok(())
}

/// Provider interface for validated analysis patterns.
pub trait PatternProvider: Send + Sync {
    /// Return a snapshot of all patterns in evaluation order.
    fn get_patterns(&self) -> Vec<Pattern>;

    /// Validate and add a uniquely named pattern.
    fn add_pattern(&mut self, pattern: PatternDef) -> AnalysisResult<()>;

    /// Remove an existing pattern by name.
    fn remove_pattern(&mut self, name: &str) -> AnalysisResult<()>;

    /// Atomically validate and replace an existing pattern by name.
    fn update_pattern(&mut self, pattern: PatternDef) -> AnalysisResult<()>;
}

/// Built-in pattern provider.
///
/// Generic artifacts such as URLs, IP addresses, paths, registry keys, and
/// algorithm names are informational categories. Only higher-signal patterns
/// contribute suspicious indicators.
pub struct DefaultPatternProvider {
    patterns: Vec<Pattern>,
}

impl DefaultPatternProvider {
    /// Build the validated built-in pattern set.
    pub fn new() -> AnalysisResult<Self> {
        let mut provider = Self::empty();
        for definition in builtin_pattern_definitions() {
            provider.add_pattern(definition)?;
        }
        Ok(provider)
    }

    /// Create a provider without built-in patterns.
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
        if self
            .patterns
            .iter()
            .any(|pattern| pattern.name == pattern_def.name)
        {
            return Err(AnalysisError::DuplicateName {
                kind: "pattern",
                name: pattern_def.name.to_string(),
            });
        }
        if self.patterns.len() >= MAX_PATTERNS {
            return Err(AnalysisError::CapacityExceeded {
                resource: "pattern provider patterns",
                limit: MAX_PATTERNS,
            });
        }
        self.patterns.push(pattern_def.compile()?);
        Ok(())
    }

    fn remove_pattern(&mut self, name: &str) -> AnalysisResult<()> {
        validate_identifier("pattern", name)?;
        let Some(index) = self
            .patterns
            .iter()
            .position(|pattern| pattern.name == name)
        else {
            return Err(AnalysisError::NotFound {
                kind: "pattern",
                name: name.to_string(),
            });
        };
        self.patterns.remove(index);
        Ok(())
    }

    fn update_pattern(&mut self, pattern_def: PatternDef) -> AnalysisResult<()> {
        validate_identifier("pattern", &pattern_def.name)?;
        let Some(index) = self
            .patterns
            .iter()
            .position(|pattern| pattern.name == pattern_def.name)
        else {
            return Err(AnalysisError::NotFound {
                kind: "pattern",
                name: pattern_def.name.to_string(),
            });
        };

        // Compile before mutating so a failed replacement preserves the old pattern.
        let replacement = pattern_def.compile()?;
        self.patterns[index] = replacement;
        Ok(())
    }
}

impl Default for DefaultPatternProvider {
    fn default() -> Self {
        match Self::new() {
            Ok(provider) => provider,
            Err(error) => panic!("built-in pattern definitions must be valid: {error}"),
        }
    }
}

fn builtin_pattern_definitions() -> Vec<PatternDef> {
    vec![
        informational(
            "url",
            r"(?i)\b(?:https?|ftp|ssh|telnet|rdp)://[^\s]+",
            "network",
            "URL or network-protocol reference",
        ),
        informational(
            "ipv4_address",
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b",
            "network",
            "Syntactically valid IPv4 address",
        ),
        informational(
            "crypto_algorithm",
            r"(?i)\b(?:base64|rot13|xor|aes|des|rsa)\b",
            "crypto",
            "Cryptographic or encoding algorithm name",
        ),
        informational(
            "base64_candidate",
            r"^(?:(?:[A-Za-z0-9+/]{4}){8,}|(?:[A-Za-z0-9+/]{4}){7,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))$",
            "encoding",
            "String shaped like Base64 data",
        ),
        informational(
            "temporary_or_system_path",
            r"(?i)(?:\\temp\\|/tmp/|\\windows\\system32(?:\\|$))",
            "path",
            "Temporary or operating-system path",
        ),
        informational(
            "registry_key",
            r"(?i)(?:\bHKEY_[A-Z_]+|SOFTWARE\\Microsoft\\Windows)",
            "registry",
            "Windows registry-key reference",
        ),
        suspicious(
            "shell_interpreter",
            r#"(?ix)(?:(?:^|[^A-Za-z0-9_])(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)(?:$|[^A-Za-z0-9_])|(?:^|[\s"'`])(?:/bin/)?(?:ba|da|z|k)?sh\s+-c(?:\s|$))"#,
            "command",
            "Command-shell interpreter token",
            6,
        ),
        suspicious(
            "dynamic_execution_call",
            r"(?i)\b(?:eval|exec|system|shell)\s*\(",
            "execution",
            "Dynamic code or command execution call",
            7,
        ),
        suspicious(
            "credential_assignment",
            r"(?i)\b(?:password|credential|secret|token|api[_-]?key)\b\s*[:=]",
            "credential",
            "Credential-related value assignment",
            8,
        ),
        suspicious(
            "malware_behavior_term",
            r"(?i)\b(?:dropper|payload|rootkit|process[ _-]?inject(?:ion|or)?|keylog(?:ger|ging)?)\b",
            "malware",
            "High-signal malware behavior term",
            9,
        ),
        suspicious(
            "surveillance_behavior_term",
            r"(?i)\b(?:screen[ _-]?capture|webcam[ _-]?capture|microphone[ _-]?recording)\b",
            "surveillance",
            "High-signal surveillance behavior term",
            8,
        ),
    ]
}

fn informational(name: &str, regex: &str, category: &str, description: &str) -> PatternDef {
    PatternDef {
        name: name.to_string(),
        regex: regex.to_string(),
        category: category.to_string(),
        description: description.to_string(),
        is_suspicious: false,
        severity: 0,
    }
}

fn suspicious(
    name: &str,
    regex: &str,
    category: &str,
    description: &str,
    severity: u8,
) -> PatternDef {
    PatternDef {
        name: name.to_string(),
        regex: regex.to_string(),
        category: category.to_string(),
        description: description.to_string(),
        is_suspicious: true,
        severity,
    }
}
