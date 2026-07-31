//! CLI surface for `renpyex`.
//!
//! Subcommands:
//! - `info`: enumerate a game's files (with magic-byte classification)
//! - `extract`: copy files byte-perfect to `--out`
//! - `verify`: read a `SHA256SUMS.txt` and re-hash every referenced file
//! - `convert`: re-emit decode-able images as PNG or JPEG

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::archive::{
    self, GameWalker, RpycDecompileOptions, decompile_rpyc_to, extract_rpa, list_rpa,
};
use crate::convert::{ConvertTarget, FormatQuality, convert_to_jpeg, convert_to_png};
use crate::output;
use crate::verify::{self, magic::Magic};
use crate::{doctor, sdk};

/// Top-level CLI argument parser.
#[derive(Debug, Parser)]
#[command(
    name = "renpyex",
    about = "Byte-perfect Ren'Py archive extractor and integrity verifier",
    version
)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// All CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Enumerate files in a game directory and classify by magic bytes.
    Info {
        /// Game directory (the one containing `game/`, or `game/` itself).
        #[arg(value_name = "DIR")]
        dir: PathBuf,
    },
    /// Walk a game directory and copy files byte-perfect to `--out`.
    Extract {
        /// Game directory.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// Output directory.
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        /// Allow writing into an existing non-empty output directory.
        #[arg(long = "overwrite")]
        overwrite: bool,
        /// Also extract contents of every `.rpa` archive into a subdirectory.
        #[arg(long = "rpa")]
        rpa: bool,
        /// Try to decompile `.rpyc` files via Python `unrpyc`.
        #[arg(long = "rpyc")]
        rpyc: bool,
        /// Optional XOR key (8-char hex) for `.rpa` archives.
        #[arg(long = "key")]
        key: Option<String>,
        /// Python interpreter for optional `.rpyc` decompilation.
        #[arg(long)]
        python: Option<String>,
        /// `unrpyc` script or executable for optional decompilation.
        #[arg(long)]
        unrpyc: Option<String>,
    },
    /// Re-hash every file in `--sums` against the actual contents.
    Verify {
        /// Root directory containing the files referenced by `--sums`.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// Path to `SHA256SUMS.txt`. Defaults to `<dir>/SHA256SUMS.txt`.
        #[arg(short = 's', long = "sums")]
        sums: Option<PathBuf>,
    },
    /// Re-emit images as PNG or JPEG into `--out` directory.
    Convert {
        /// Source directory containing decode-able images.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// Output directory (created if missing).
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        /// Target format.
        #[arg(short = 't', long = "to", default_value = "png")]
        to: String,
        /// JPEG quality, 1..=100 (only used with `to=jpeg`).
        #[arg(short = 'q', long = "quality", default_value_t = 90)]
        quality: u8,
        /// Allow writing into an existing non-empty output directory.
        #[arg(long = "overwrite")]
        overwrite: bool,
    },
    /// Inspect a project without modifying it.
    Doctor {
        /// Project root, game directory, or flat directory.
        dir: PathBuf,
        /// Emit JSON instead of human text.
        #[arg(long)]
        json: bool,
    },
    /// Execute an official Ren'Py SDK command.
    Sdk {
        /// Project root.
        project: PathBuf,
        /// SDK directory containing `renpy.py`.
        #[arg(long)]
        sdk: PathBuf,
        /// Maximum duration in seconds.
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        /// SDK action.
        #[command(subcommand)]
        command: SdkCommand,
    },
}

/// Official SDK actions.
#[derive(Debug, Subcommand)]
#[allow(missing_docs)]
pub enum SdkCommand {
    /// Run lint.
    Lint {
        #[arg(long)]
        all_problems: bool,
    },
    /// Compile scripts.
    Compile {
        #[arg(long)]
        keep_orphan_rpyc: bool,
    },
    /// Run testcases.
    Test {
        suite: Option<String>,
        #[arg(long)]
        enable_all: bool,
        #[arg(long)]
        report_detailed: bool,
    },
    /// Generate translations.
    Translate {
        language: String,
        #[arg(long)]
        count: bool,
        #[arg(long)]
        strings_only: bool,
    },
    /// Export dialogue.
    Dialogue {
        language: String,
        #[arg(long)]
        strings: bool,
        #[arg(long)]
        text: bool,
    },
    /// Build distribution.
    Distribute {
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        no_archive: bool,
        #[arg(long)]
        no_update: bool,
    },
}

#[derive(Debug)]
struct ExtractOptions {
    overwrite: bool,
    rpa: bool,
    rpyc: bool,
    key: Option<String>,
    python: Option<String>,
    unrpyc: Option<String>,
}

impl Command {
    /// Dispatch to the matching concrete routine.
    pub fn run(self) -> crate::Result<()> {
        match self {
            Command::Info { dir } => cmd_info(&dir),
            Command::Extract {
                dir,
                out,
                overwrite,
                rpa,
                rpyc,
                key,
                python,
                unrpyc,
            } => cmd_extract(
                &dir,
                &out,
                ExtractOptions {
                    overwrite,
                    rpa,
                    rpyc,
                    key,
                    python,
                    unrpyc,
                },
            ),
            Command::Verify { dir, sums } => cmd_verify(&dir, sums.as_deref().map(Path::new)),
            Command::Convert {
                dir,
                out,
                to,
                quality,
                overwrite,
            } => cmd_convert(&dir, &out, &to, quality, overwrite),
            Command::Doctor { dir, json } => cmd_doctor(&dir, json),
            Command::Sdk {
                project,
                sdk,
                timeout,
                command,
            } => cmd_sdk(&project, &sdk, timeout, command),
        }
    }
}

fn cmd_doctor(dir: &Path, as_json: bool) -> crate::Result<()> {
    let report = doctor::inspect(dir)?;
    if as_json {
        println!("{}", doctor::json(&report)?);
    } else {
        print!("{}", doctor::text(&report));
    }
    if report.has_errors() {
        Err(crate::RenpyExError::Integrity {
            message: format!("doctor found {} errors", report.summary.errors),
        })
    } else {
        Ok(())
    }
}

fn cmd_sdk(project: &Path, sdk_dir: &Path, timeout: u64, command: SdkCommand) -> crate::Result<()> {
    let action = match command {
        SdkCommand::Lint { all_problems } => sdk::Action::Lint { all_problems },
        SdkCommand::Compile { keep_orphan_rpyc } => sdk::Action::Compile { keep_orphan_rpyc },
        SdkCommand::Test {
            suite,
            enable_all,
            report_detailed,
        } => sdk::Action::Test {
            suite,
            enable_all,
            report_detailed,
        },
        SdkCommand::Translate {
            language,
            count,
            strings_only,
        } => sdk::Action::Translate {
            language,
            count,
            strings_only,
        },
        SdkCommand::Dialogue {
            language,
            strings,
            text,
        } => sdk::Action::Dialogue {
            language,
            strings,
            text,
        },
        SdkCommand::Distribute {
            destination,
            package,
            no_archive,
            no_update,
        } => sdk::Action::Distribute {
            destination,
            package,
            no_archive,
            no_update,
        },
    };
    let result = sdk::execute(
        &sdk::Spec {
            sdk_dir: sdk_dir.to_path_buf(),
            timeout: std::time::Duration::from_secs(timeout),
        },
        project,
        &action,
    )?;
    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    Ok(())
}

fn cmd_info(dir: &Path) -> crate::Result<()> {
    let game_dir = archive::walker::resolve_game_dir(dir);
    let inv = GameWalker::new(game_dir.clone()).walk()?;
    println!("Game directory: {}", game_dir.display());
    println!("Files: {}", inv.files.len());
    println!("Total bytes: {}", inv.total_bytes);
    let mut by_magic: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for f in &inv.files {
        *by_magic.entry(f.magic.label().to_string()).or_insert(0) += 1;
    }
    println!("By classified magic:");
    for (label, count) in by_magic {
        println!("  {label:<30} {count}");
    }
    if game_dir.is_dir() {
        let mut rpa_found = 0usize;
        for file in &inv.files {
            if file
                .rel
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("rpa"))
            {
                rpa_found += 1;
                println!("Archive detected: {}", file.rel.display());
                if let Ok(listed) = list_rpa(&file.abs, None) {
                    println!(
                        "  {} version, {} entries, {} bytes uncompressed",
                        listed.version,
                        listed.entries.len(),
                        listed.total_uncompressed
                    );
                }
            }
        }
        if rpa_found > 0 {
            println!("Pass --rpa with `extract` to write archive contents.");
        }
    }
    Ok(())
}

fn cmd_extract(dir: &Path, out: &Path, options: ExtractOptions) -> crate::Result<()> {
    let game_dir = archive::walker::resolve_game_dir(dir);
    output::reject_output_within_source(&game_dir, out)?;
    output::prepare_output(out, options.overwrite)?;
    let inv = GameWalker::new(game_dir.clone()).walk()?;
    println!(
        "Walking {} ({} files)…",
        game_dir.display(),
        inv.files.len()
    );

    let mut failures: Vec<String> = Vec::new();
    let total = inv.files.len();
    for (i, file) in inv.files.iter().enumerate() {
        let is_archive = matches!(file.magic, Magic::Rpa3)
            || file
                .rel
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("rpa"));
        if is_archive && !options.rpa {
            continue;
        }
        let dest = match safe_join(out, &file.rel.to_string_lossy()) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{}: {e}", file.rel.display()));
                continue;
            }
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|err| crate::RenpyExError::io(parent, err))?;
        }
        match output::copy_atomic(&file.abs, &dest) {
            Ok(()) => {
                if (i + 1) % 250 == 0 {
                    eprintln!("  [{}/{}] extracted {}", i + 1, total, file.rel.display());
                }
            }
            Err(e) => failures.push(format!("{}: {e}", file.rel.display())),
        }
    }

    if options.rpa {
        let parsed_key = parse_user_key(options.key.as_deref())?;
        for file in &inv.files {
            if file
                .rel
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("rpa"))
            {
                let dest = out.join("rpa").join(&file.rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|err| crate::RenpyExError::io(parent, err))?;
                }
                match extract_rpa(&file.abs, &dest, parsed_key) {
                    Ok(listed) => println!(
                        "Extracted {:?} ({} entries, {} bytes uncompressed) → {}",
                        file.rel,
                        listed.entries.len(),
                        listed.total_uncompressed,
                        dest.display()
                    ),
                    Err(e) => failures.push(format!("rpa {}: {e}", file.rel.display())),
                }
            }
        }
    }

    if options.rpyc {
        let opts = RpycDecompileOptions {
            python: options.python,
            unrpyc: options.unrpyc,
            overwrite_rpyc: options.overwrite,
        };
        for file in &inv.files {
            if file.rel.extension().and_then(|s| s.to_str()) != Some("rpyc") {
                continue;
            }
            let dest = safe_join(out, &file.rel.to_string_lossy())?;
            match decompile_rpyc_to(&file.abs, &dest, &opts) {
                Ok(Some(rpy)) => {
                    println!("Decompiled: {} → {}", file.rel.display(), rpy.display())
                }
                Ok(None) => eprintln!("Skipped (no unrpyc): {}", file.rel.display()),
                Err(e) => failures.push(format!("{}: {e}", file.rel.display())),
            }
        }
    }

    if failures.is_empty() {
        println!("Done. Wrote {total} files.");
        Ok(())
    } else {
        eprintln!("Done with {} failures.", failures.len());
        for f in &failures {
            eprintln!("  {f}");
        }
        Err(crate::RenpyExError::Integrity {
            message: format!("{} files failed to extract", failures.len()),
        })
    }
}

fn cmd_verify(dir: &Path, sums: Option<&Path>) -> crate::Result<()> {
    let sums_path = sums
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| dir.join("SHA256SUMS.txt"));
    let (ok, bad) = verify::verify_all(dir, &sums_path)?;
    let total = ok + bad.len() as u64;
    println!("Verified {} / {} files in {}", ok, total, dir.display());
    for issue in &bad {
        match issue {
            verify::VerifyOutcome::Ok { .. } => {}
            verify::VerifyOutcome::HashMismatch {
                path,
                expected,
                actual,
            } => eprintln!(
                "  MISMATCH {}\n    expected: {}\n    actual:   {}",
                path.display(),
                expected,
                actual
            ),
            verify::VerifyOutcome::Missing { path } => {
                eprintln!("  MISSING {}", path.display())
            }
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(crate::RenpyExError::Integrity {
            message: format!("{} failures", bad.len()),
        })
    }
}

fn cmd_convert(
    dir: &Path,
    out: &Path,
    to: &str,
    quality: u8,
    overwrite: bool,
) -> crate::Result<()> {
    let target = ConvertTarget::parse(to)
        .ok_or_else(|| crate::RenpyExError::Invalid(format!("invalid --to value: {to}")))?;
    if !(1..=100).contains(&quality) {
        return Err(crate::RenpyExError::Invalid(format!(
            "quality must be in 1..=100, got {quality}"
        )));
    }
    let game_dir = archive::walker::resolve_game_dir(dir);
    output::reject_output_within_source(&game_dir, out)?;
    output::prepare_output(out, overwrite)?;

    let inv = GameWalker::new(game_dir).walk()?;
    let mut converted = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for file in &inv.files {
        let is_image_payload = matches!(
            file.magic,
            Magic::Png | Magic::Jpeg | Magic::Gif | Magic::WebP | Magic::Bmp
        );
        if !is_image_payload {
            skipped += 1;
            continue;
        }
        let dest_rel = file.rel.with_extension(match target {
            ConvertTarget::Png => "png",
            ConvertTarget::Jpeg => "jpg",
        });
        let dest = safe_join_redir(out, &dest_rel.to_string_lossy())?;
        let res = match target {
            ConvertTarget::Png => convert_to_png(&file.abs),
            ConvertTarget::Jpeg => convert_to_jpeg(&file.abs, FormatQuality(quality)),
        };
        let owned = match res {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  convert fail {}: {e}", file.rel.display());
                failed += 1;
                continue;
            }
        };
        if let Err(e) = output::write_atomic(&dest, &owned) {
            eprintln!("  write fail {}: {e}", dest.display());
            failed += 1;
            continue;
        }
        converted += 1;
        if converted.is_multiple_of(50) {
            eprintln!("  [{converted}] converted {}", file.rel.display());
        }
    }
    println!(
        "Converted: {}, skipped (non-image): {}, failed: {}",
        converted, skipped, failed
    );
    if failed > 0 {
        Err(crate::RenpyExError::Integrity {
            message: format!("{failed} files failed"),
        })
    } else {
        Ok(())
    }
}

fn parse_user_key(s: Option<&str>) -> crate::Result<Option<u32>> {
    let raw = match s {
        Some(s) => s,
        None => return Ok(None),
    };
    let raw = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() {
        return Ok(None);
    }
    let v = u64::from_str_radix(raw, 16)
        .map_err(|e| crate::RenpyExError::Invalid(format!("--key must be hex: {e}")))?;
    u32::try_from(v)
        .map(Some)
        .map_err(|_| crate::RenpyExError::Invalid("--key must fit in u32".into()))
}

/// Sanitize and join `out_root` + `rel`, rejecting `..` traversal.
fn safe_join(out_root: &Path, rel: &str) -> crate::Result<PathBuf> {
    safe_join_redir(out_root, rel)
}

fn safe_join_redir(out_root: &Path, rel: &str) -> crate::Result<PathBuf> {
    let mut joined = out_root.to_path_buf();
    let normalised = rel.replace('\\', "/");
    if normalised.starts_with('/') || normalised.starts_with("//") {
        return Err(crate::RenpyExError::PathTraversal {
            archive: out_root.to_path_buf(),
            entry: rel.into(),
        });
    }
    for piece in normalised.split('/').filter(|s| !s.is_empty()) {
        match piece {
            "." => continue,
            ".." => {
                return Err(crate::RenpyExError::PathTraversal {
                    archive: out_root.to_path_buf(),
                    entry: rel.into(),
                });
            }
            _ => {
                for c in piece.chars() {
                    if matches!(c, '\0' | '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                        return Err(crate::RenpyExError::Invalid(format!(
                            "forbidden character {c:?} in {piece:?}"
                        )));
                    }
                }
                joined.push(piece);
            }
        }
    }
    Ok(joined)
}
