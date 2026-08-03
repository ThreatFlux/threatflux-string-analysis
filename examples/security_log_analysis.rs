use chrono::{TimeZone, Utc};
use threatflux_string_analysis::{
    AnalysisResult, StringContext, StringFilter, StringOccurrence, StringTracker,
};

fn main() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    let event_time = Utc
        .with_ymd_and_hms(2026, 7, 15, 10, 30, 0)
        .single()
        .expect("example timestamp is valid");

    tracker.track_occurrence(
        "powershell -EncodedCommand Zg==",
        StringOccurrence::new(
            "/var/log/security.log",
            "sha256:log-snapshot",
            "log-parser",
            event_time,
            StringContext::Command {
                command_type: "powershell".to_string(),
            },
        ),
    )?;

    let matches = tracker.get_statistics(Some(&StringFilter {
        file_hashes: Some(vec!["sha256:log-snapshot".to_string()]),
        suspicious_only: Some(true),
        date_range: Some((event_time, event_time)),
        ..StringFilter::default()
    }))?;

    for value in matches.suspicious_strings {
        println!("heuristic signal: {value}");
    }
    Ok(())
}
