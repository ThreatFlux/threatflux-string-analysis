use std::collections::{BTreeMap, BTreeSet};
use threatflux_string_analysis::{
    AnalysisConfig, StringAnalysis, StringContext, StringStatistics, SuspiciousIndicator,
};

#[test]
fn serde_round_trips_preserve_deterministic_collection_order() {
    let analysis = StringAnalysis {
        entropy: 3.5,
        categories: BTreeSet::from(["zeta".to_string(), "alpha".to_string()]),
        suspicious_indicators: vec![SuspiciousIndicator {
            pattern_name: "example".to_string(),
            description: "Serialization regression".to_string(),
            severity: 4,
            matched_text: Some("match".to_string()),
            matched_text_truncated: false,
        }],
        indicators_truncated: false,
        is_suspicious: true,
    };
    let encoded = serde_json::to_string(&analysis).unwrap();
    assert!(encoded.contains(r#""categories":["alpha","zeta"]"#));
    let decoded: StringAnalysis = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, analysis);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);

    let statistics = StringStatistics {
        total_unique_strings: 0,
        total_occurrences: 0,
        total_files_analyzed: 0,
        most_common: Vec::new(),
        total_suspicious_strings: 0,
        suspicious_strings: Vec::new(),
        total_high_entropy_strings: 0,
        high_entropy_strings: Vec::new(),
        category_distribution: BTreeMap::from([("zeta".to_string(), 2), ("alpha".to_string(), 1)]),
        length_distribution: BTreeMap::new(),
    };
    let encoded = serde_json::to_string(&statistics).unwrap();
    assert!(encoded.contains(r#""category_distribution":{"alpha":1,"zeta":2}"#));
    let decoded: StringStatistics = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, statistics);

    let config = AnalysisConfig::default();
    let encoded = serde_json::to_string(&config).unwrap();
    assert_eq!(
        serde_json::from_str::<AnalysisConfig>(&encoded).unwrap(),
        config
    );
}

#[test]
fn string_context_rejects_unknown_variant_fields() {
    let encoded = r#"{"FileString":{"offset":1,"unexpected":true}}"#;
    assert!(serde_json::from_str::<StringContext>(encoded).is_err());
}
