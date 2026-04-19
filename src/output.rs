use colored::Colorize;

use crate::types::{Confidence, Finding};

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

pub fn print_findings_text(findings: &[Finding]) {
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
    }
    println!();
}

pub fn print_summary(findings: &[Finding]) {
    let high = findings.iter().filter(|f| f.confidence == Confidence::High).count();
    let med = findings.iter().filter(|f| f.confidence == Confidence::Medium).count();
    let low = findings.iter().filter(|f| f.confidence == Confidence::Low).count();

    let files_affected: std::collections::HashSet<_> = findings.iter().map(|f| &f.file).collect();

    println!("{}", "─".repeat(60).dimmed());

    if findings.is_empty() {
        println!(
            "  {} No secrets found.",
            "✓".green().bold(),
        );
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
    }

    println!();
}
