use threatflux_string_analysis::{
    AnalysisConfig, AnalysisResult, DefaultCategorizer, DefaultPatternProvider,
    DefaultStringAnalyzer, PatternDef, PatternProvider, StringContext, StringTracker,
};

fn main() -> AnalysisResult<()> {
    let mut provider = DefaultPatternProvider::empty();
    provider.add_pattern(PatternDef {
        name: "example_domain_assignment".to_string(),
        regex: r"(?i)\bcallback_domain\s*[:=]".to_string(),
        category: "configuration".to_string(),
        description: "Callback-domain configuration assignment".to_string(),
        is_suspicious: true,
        severity: 7,
    })?;

    let config = AnalysisConfig {
        min_suspicious_entropy: 4.8,
        ..AnalysisConfig::default()
    };
    let analyzer = DefaultStringAnalyzer::new()
        .with_entropy_threshold(config.min_suspicious_entropy)?
        .with_patterns(provider.get_patterns())?;
    let tracker = StringTracker::with_components_and_config(
        Box::new(analyzer),
        Box::new(DefaultCategorizer::new()),
        config,
    )?;

    tracker.track_string(
        "callback_domain = example.invalid",
        "/samples/config.txt",
        "sha256:example",
        "config-parser",
        StringContext::Metadata {
            field: "configuration".to_string(),
        },
    )?;

    let entry = tracker
        .get_string_details("callback_domain = example.invalid")
        .expect("the value was just tracked");
    println!("categories: {:?}", entry.categories);
    println!("evidence: {:?}", entry.suspicious_indicators);
    Ok(())
}
