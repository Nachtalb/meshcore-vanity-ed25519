use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vanity_ed25519::{
    KeyResult, MeshCoreKeypair, calculate_estimated_attempts, get_num_cpus,
    initialize_shared_state, is_prefix_valid, parse_prefix_target, perform_parallel_search,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Prefix to search for (in hex)
    #[arg(short, long)]
    prefix: String,

    /// Output file to save the key pair (optional)
    #[arg(short, long)]
    output: Option<String>,

    /// Print only the JSON output to stdout
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Silent execution (suppress progress bar and logs)
    #[arg(short = 'q', long, default_value_t = false)]
    quiet: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let prefix = args.prefix.clone();

    validate_prefix(&prefix)?;

    // Quiet mode only suppresses logs (stderr), NOT the result (stdout)
    let quiet = args.quiet;

    if !quiet {
        print_banner();
        eprintln!(
            "{} {}",
            "🔍 Searching for Ed25519 key with prefix:".bold().blue(),
            prefix.yellow().bold()
        );
        eprintln!(
            "{} {}",
            "🖥️  Using CPU cores:".bold().blue(),
            get_num_cpus().to_string().yellow()
        );
    }

    let estimated_attempts = calculate_estimated_attempts(prefix.len());

    if !quiet {
        eprintln!(
            "{} {}",
            "📊 Estimated attempts needed:".bold().blue(),
            format!("~{}", format_number(estimated_attempts)).yellow()
        );
        if estimated_attempts > u64::MAX as u128 {
            eprintln!(
                "{}",
                "🍺 If you find this key, I will personally fly out to you and give you a free drink!"
                    .red()
                    .bold()
            );
        }
        eprintln!("{}", "⏱️  Starting search...\n".bold().green());
    }

    let (found, attempts) = initialize_shared_state();

    // Prepare optimized target for fast comparison
    let target = parse_prefix_target(&prefix);

    // Only set up progress bar if not in quiet mode
    let pb = if !quiet {
        Some(setup_progress_bar(
            if estimated_attempts > u64::MAX as u128 {
                0
            } else {
                estimated_attempts as u64
            },
        ))
    } else {
        None
    };

    let start_time = Instant::now();
    let monitor_handle = spawn_progress_monitor(
        pb.clone(),
        attempts.clone(),
        found.clone(),
        estimated_attempts,
    );

    let result = perform_parallel_search(&target, &attempts, &found);

    found.store(true, Ordering::Relaxed);
    monitor_handle.join().unwrap();

    if let Some(bar) = pb {
        // Kept visible as requested
        bar.abandon();
    }

    let elapsed = start_time.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);

    match result {
        Some(key_result) => handle_success(key_result, &args, &prefix, total_attempts, elapsed),
        None => {
            if !quiet {
                eprintln!("\n{}", "❌ Search was interrupted".red().bold());
            }
            Err("Search interrupted".into())
        }
    }
}

// --- Helper Functions ---

pub fn validate_prefix(prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_prefix_valid(prefix) {
        eprintln!(
            "{}",
            "❌ Prefix must contain only hexadecimal characters (0-9, a-f)"
                .red()
                .bold()
        );
        return Err(format!("Invalid prefix: {}", prefix).into());
    }
    Ok(())
}

fn print_banner() {
    eprintln!(
        "{}",
        "=============================================".bright_purple()
    );
    eprintln!(
        "{}",
        "       Vanity Ed25519 Key Generator          "
            .bright_purple()
            .bold()
    );
    eprintln!(
        "{}\n",
        "=============================================".bright_purple()
    );
}

fn setup_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.yellow/white}] {pos}/{len} ({percent}%) | {per_sec} | ETA: {eta}"
            )
            .unwrap()
            .progress_chars(" 𜱭∙")

    );
    // indicatif defaults to stderr, which is what we want
    pb
}

fn spawn_progress_monitor(
    pb: Option<ProgressBar>,
    attempts: Arc<AtomicU64>,
    found: Arc<AtomicBool>,
    initial_estimate: u128,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut current_total = if initial_estimate > u64::MAX as u128 {
            0
        } else {
            initial_estimate as u64
        };
        let mut first_change = true;

        while !found.load(Ordering::Relaxed) {
            let current = attempts.load(Ordering::Relaxed);

            if let Some(ref bar) = pb {
                // Update total if we exceed initial estimate
                if current_total != 0 && current > current_total {
                    current_total = current; // Add 10% buffer
                    bar.set_length(current_total);
                    if first_change {
                        bar.set_style(bar.style().progress_chars("= "));
                        first_change = false;
                    }
                }

                bar.set_position(current);
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    })
}

fn handle_success(
    result: KeyResult,
    args: &Args,
    _prefix: &str,
    total_attempts: u64,
    elapsed: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.json {
        let keypair = MeshCoreKeypair {
            public_key: result.public_key_hex.to_uppercase(),
            private_key: result.private_key_hex.to_uppercase(),
        };
        let json_output = serde_json::to_string_pretty(&keypair)?;
        // JSON output always to stdout
        println!("{}", json_output);
    } else {
        // Human readable output
        println!(
            "{}",
            "=============================================".bright_black()
        );
        println!("{}:", "Public Key".cyan().bold());
        println!("{}", result.public_key_hex.to_uppercase().white());

        println!("\n{}:", "Private Key".cyan().bold());
        println!("{}", result.private_key_hex.to_uppercase().white());
        println!(
            "{}",
            "=============================================".bright_black()
        );
    }

    // Print Stats and Validation to stderr, unless quiet
    if !args.quiet {
        eprintln!("\n{}", "✓ Key Generated Successfully!".bold().green());

        eprintln!("\n{}", "Validation Status:".yellow().bold());
        eprintln!(
            "{}",
            "✓ RFC 8032 Ed25519 compliant - Proper SHA-512 expansion, scalar clamping, and key consistency verified".green()
        );

        let attempts_str = format_number(total_attempts as u128);
        let time_str = format!("{:.1}s", elapsed.as_secs_f64());
        let keys_per_sec = format_number((total_attempts as f64 / elapsed.as_secs_f64()) as u128);

        eprintln!(
            "{} {} {} {} {} {}",
            "Attempts".bold(),
            attempts_str.yellow(),
            "Time".bold(),
            time_str.yellow(),
            "Keys/sec".bold(),
            keys_per_sec.green()
        );
    }

    // Save to file only if output arg is present
    if let Some(output_filename) = &args.output {
        match save_keypair_json(
            output_filename,
            &result.public_key_hex.to_uppercase(),
            &result.private_key_hex.to_uppercase(),
        ) {
            Ok(_) => {
                if !args.quiet {
                    eprintln!(
                        "\n{} {}",
                        "💾 Key pair saved to:".bold(),
                        output_filename.green()
                    )
                }
            }
            Err(e) => {
                eprintln!("\n{} {}", "⚠️  Failed to save key pair:".red().bold(), e);
                return Err("Failed to save key pair".into());
            }
        }
    }
    Ok(())
}

fn format_number(n: u128) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn save_keypair_json(filename: &str, public_key: &str, private_key: &str) -> std::io::Result<()> {
    let keypair = MeshCoreKeypair {
        public_key: public_key.to_string(),
        private_key: private_key.to_string(),
    };

    let json_data = serde_json::to_string_pretty(&keypair).map_err(Error::other)?;

    fs::write(filename, json_data)?;
    Ok(())
}
