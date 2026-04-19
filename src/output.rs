use colored::Colorize;
use serde_json::{json, Value};

use crate::types::{Confidence, Finding, OutputFormat};

pub fn print_banner(mode: &str) {
    println!(
        "\n  {} {}  {}\n",
        "secox".bold().cyan(),
        env!("CARGO_PKG_VERSION").dimmed(),
        mode.dimmed(),
    );
}

fn confidence_color(c: &Confidence) -> colored::ColoredString {
    match c {
        Confidence::High => " HIGH ".on_red().white().bold(),
        Confidence::Medium => " MED  ".on_yellow().black().bold(),
        Confidence::Low => " LOW  ".on_bright_black().white(),
    }
}

pub fn print_findings(findings: &[Finding], format: OutputFormat) {
    match format {
        OutputFormat::Text => print_findings_text(findings),
        OutputFormat::Json => print_json(findings),
        OutputFormat::Sarif => print_sarif(findings),
    }
}

fn print_findings_text(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", "  No secrets found.".green().bold());
        return;
    }

    println!();
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            println!();
        }

        print!("  {} ", confidence_color(&f.confidence));
        println!(
            "  {}  {}",
            f.rule_name.bold(),
            format!("({})", f.rule_id).dimmed()
        );

        let file_str = f.file.display().to_string();
        println!(
            "     {} {}",
            "File:".dimmed(),
            format!("{}:{}", file_str, f.line_number).cyan()
        );

        println!(
            "     {} {}",
            "Secret:".dimmed(),
            f.secret_preview.yellow()
        );

        let line_display = if f.line.len() > 120 {
            format!("{}…", &f.line[..120])
        } else {
            f.line.clone()
        };
        println!("     {} {}", "Line:".dimmed(), line_display);

        if let Some(ref commit) = f.commit {
            let short = &commit[..commit.len().min(8)];
            let msg = f.commit_message.as_deref().unwrap_or("");
            println!(
                "     {} {} {}",
                "Commit:".dimmed(),
                short.magenta(),
                msg.dimmed()
            );
        }

        match f.verified {
            Some(true)  => println!("     {} {}", "Status:".dimmed(), "✓ verified active".green().bold()),
            Some(false) => println!("     {} {}", "Status:".dimmed(), "✗ invalid / rotated".red().bold()),
            None        => {}
        }
    }
    println!();
}

fn print_json(findings: &[Finding]) {
    let arr: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "confidence": match f.confidence {
                    Confidence::High => "HIGH",
                    Confidence::Medium => "MEDIUM",
                    Confidence::Low => "LOW",
                },
                "file": f.file.display().to_string(),
                "line_number": f.line_number,
                "line": f.line,
                "secret_preview": f.secret_preview,
                "commit": f.commit,
                "commit_message": f.commit_message,
                "verified": f.verified,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&arr).unwrap());
}

fn print_sarif(findings: &[Finding]) {
    use crate::rules::RULES;

    let rules_sarif: Vec<Value> = RULES
        .iter()
        .map(|r| {
            json!({
                "id": r.meta.id,
                "name": r.meta.name,
                "shortDescription": { "text": r.meta.description },
                "defaultConfiguration": {
                    "level": match r.meta.confidence {
                        Confidence::High => "error",
                        Confidence::Medium => "warning",
                        Confidence::Low => "note",
                    }
                }
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": match f.confidence {
                    Confidence::High => "error",
                    Confidence::Medium => "warning",
                    Confidence::Low => "note",
                },
                "message": {
                    "text": format!("{} detected: {}", f.rule_name, f.secret_preview)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file.display().to_string(),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": f.line_number,
                            "snippet": { "text": f.line }
                        }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secox",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules_sarif
                }
            },
            "results": results
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
}

pub fn print_summary(findings: &[Finding], format: OutputFormat) {
    if format != OutputFormat::Text {
        return;
    }

    let high = findings.iter().filter(|f| f.confidence == Confidence::High).count();
    let med = findings.iter().filter(|f| f.confidence == Confidence::Medium).count();
    let low = findings.iter().filter(|f| f.confidence == Confidence::Low).count();
    let files_affected: std::collections::HashSet<_> = findings.iter().map(|f| &f.file).collect();

    println!("{}", "─".repeat(60).dimmed());

    if findings.is_empty() {
        println!("  {} No secrets found.", "✓".green().bold());
    } else {
        println!(
            "  {} Found {} secret(s) in {} file(s):",
            "✗".red().bold(),
            findings.len().to_string().red().bold(),
            files_affected.len()
        );
        if high > 0 { println!("    {} high confidence", high.to_string().red()); }
        if med > 0  { println!("    {} medium confidence", med.to_string().yellow()); }
        if low > 0  { println!("    {} low confidence", low.to_string().dimmed()); }

        let active  = findings.iter().filter(|f| f.verified == Some(true)).count();
        let invalid = findings.iter().filter(|f| f.verified == Some(false)).count();
        if active > 0  { println!("    {} verified active",          active.to_string().green()); }
        if invalid > 0 { println!("    {} invalid / rotated",        invalid.to_string().dimmed()); }
    }
    println!();
}
