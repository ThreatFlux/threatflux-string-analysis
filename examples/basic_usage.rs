use threatflux_string_analysis::{AnalysisResult, StringContext, StringFilter, StringTracker};

fn main() -> AnalysisResult<()> {
    let tracker = StringTracker::new();

    tracker.track_string(
        "https://example.com/docs",
        "/samples/benign.txt",
        "sha256:benign",
        "example-scanner",
        StringContext::Url {
            protocol: Some("https".to_string()),
        },
    )?;
    tracker.track_string(
        "powershell -EncodedCommand Zg==",
        "/samples/suspicious.bin",
        "sha256:suspicious",
        "example-scanner",
        StringContext::Command {
            command_type: "powershell".to_string(),
        },
    )?;

    let statistics = tracker.get_statistics(None)?;
    println!("distinct values: {}", statistics.total_unique_strings);
    println!(
        "suspicious signals: {}",
        statistics.total_suspicious_strings
    );

    let suspicious = tracker.get_statistics(Some(&StringFilter {
        suspicious_only: Some(true),
        ..StringFilter::default()
    }))?;
    for value in suspicious.suspicious_strings {
        if let Some(entry) = tracker.get_string_details(&value) {
            println!("{value}: {:?}", entry.suspicious_indicators);
        }
    }

    Ok(())
}
