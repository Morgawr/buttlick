use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use rayon::prelude::*;

use buttlick::bench::run_benchmarks;
use buttlick::engine::aggregate::AggregateQuery;
use buttlick::engine::regex_compile::GrepMode;
use buttlick::error::{ButtlickError, Result};
use buttlick::format::MappedArchive;
use buttlick::grammar::GrammarDag;

const BINARY_MEDIA_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "mp3", "ogg", "wav", "flac", "mp4", "mkv",
    "avi", "mov", "zip", "gz", "xz", "zst", "7z", "rar", "tar", "iso", "bin",
];

fn should_include_file(path: &Path, text_only: bool, exclude_exts: &[String]) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if exclude_exts.iter().any(|x| x.eq_ignore_ascii_case(&ext)) {
        return false;
    }
    if text_only && BINARY_MEDIA_EXTS.contains(&ext.as_str()) {
        return false;
    }
    true
}

/// Recursively collects `(archive_doc_name, file_path, file_size)` tuples for files and directories.
fn collect_input_files(
    inputs: &[PathBuf],
    text_only: bool,
    exclude_exts: &[String],
) -> Result<Vec<(String, PathBuf, u64)>> {
    let mut out = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let base = input.parent().unwrap_or_else(|| Path::new(""));
            collect_dir_recursive(base, input, text_only, exclude_exts, &mut out)?;
        } else if should_include_file(input, text_only, exclude_exts) {
            let meta = fs::metadata(input)?;
            let name = input
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| input.to_string_lossy().into_owned());
            out.push((name, input.clone(), meta.len()));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn collect_dir_recursive(
    base: &Path,
    dir: &Path,
    text_only: bool,
    exclude_exts: &[String],
    out: &mut Vec<(String, PathBuf, u64)>,
) -> Result<()> {
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        entries.push(entry.path());
    }
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_dir_recursive(base, &path, text_only, exclude_exts, out)?;
        } else if path.is_file() && should_include_file(&path, text_only, exclude_exts) {
            let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let rel = path.strip_prefix(base).unwrap_or(&path);
            let name = rel.to_string_lossy().replace('\\', "/");
            out.push((name, path, len));
        }
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(
    name = "buttlick",
    version,
    about = "Buttlick: Grammar-Homomorphic Zero-Decompression Storage & Compute Engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Compress one or more files or directories into a .btlk grammar archive
    Compress {
        /// Input file(s) or directory(ies) to compress into the shared grammar DAG
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Output .btlk archive path
        #[arg(short, long)]
        output: PathBuf,
        /// Skip pre-compressed binary media/archive files (e.g. .png, .jpg, .zip, .mp4)
        #[arg(long)]
        text_only: bool,
        /// Comma-separated list of file extensions to exclude (e.g. "png,jpg,bin")
        #[arg(long, value_delimiter = ',')]
        exclude_ext: Vec<String>,
        /// Print compression progress and statistics
        #[arg(long)]
        stats: bool,
    },

    /// Decompress a .btlk archive (single document or entire directory tree) back to raw bytes
    Decompress {
        /// Input .btlk archive path
        input: PathBuf,
        /// Optional output file path for a single document (writes to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Optional output directory to extract all documents in the archive
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Optional document name inside the archive (defaults to first document)
        #[arg(long)]
        doc: Option<String>,
    },

    /// Inspect DAG structure, compression ratio, tree depth, and rule statistics
    Inspect {
        /// Input .btlk archive path
        input: PathBuf,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },

    /// O(log N) random-access byte slice extraction without decompressing the file
    Slice {
        /// Input .btlk archive path
        input: PathBuf,
        /// Starting byte offset (0-indexed)
        #[arg(long)]
        start: u64,
        /// Number of bytes to extract
        #[arg(long)]
        len: u64,
        /// Optional document name
        #[arg(long)]
        doc: Option<String>,
    },

    /// O(log N) substring equality check between two arbitrary byte ranges
    Eq {
        /// Input .btlk archive path
        input: PathBuf,
        /// First byte offset
        #[arg(long)]
        pos1: u64,
        /// Second byte offset
        #[arg(long)]
        pos2: u64,
        /// Substring byte length to compare
        #[arg(long)]
        len: u64,
        /// Optional document name
        #[arg(long)]
        doc: Option<String>,
    },

    /// Zero-decompression exact substring search (count + optional byte offsets)
    Count {
        /// Input .btlk archive path
        input: PathBuf,
        /// Exact literal pattern to search for
        pattern: String,
        /// Also extract and print 64-bit byte offsets of matches
        #[arg(long)]
        offsets: bool,
        /// Maximum number of byte offsets to extract when --offsets is set
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Optional document name
        #[arg(long)]
        doc: Option<String>,
        /// Query across all documents in the archive in a single shared-DAG pass
        #[arg(long)]
        all: bool,
    },

    /// Zero-decompression regular expression search & line extraction (`grep -E` / `grep -E -c`)
    Slurp {
        /// Input .btlk archive path
        input: PathBuf,
        /// Regular expression or literal pattern
        regex: String,
        /// Print actual matching lines instead of just counts (`grep -E` output)
        #[arg(short = 'n', long)]
        lines: bool,
        /// Maximum number of matching lines to print when `--lines` (`-n`) is set (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// Count matching lines (`grep -E -c` semantics, default when `--lines` is not set)
        #[arg(short = 'c', long)]
        line_count: bool,
        /// Count total non-overlapping regex matches across the stream
        #[arg(long)]
        match_count: bool,
        /// Optional document name
        #[arg(long)]
        doc: Option<String>,
        /// Query across all documents in the archive in a single shared-DAG pass
        #[arg(short = 'a', long)]
        all: bool,
        /// Colorize matched strings and filenames (`auto`, `always`, `never`)
        #[arg(
            long,
            value_enum,
            default_value_t = ColorMode::Auto,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "always"
        )]
        color: ColorMode,
    },

    /// Zero-decompression structured analytics (CSV / TSV / Log column aggregations)
    Query {
        /// Input .btlk archive path
        input: PathBuf,
        /// Field delimiter character (e.g. ',', '\t', ' ')
        #[arg(long, default_value = ",")]
        delimiter: String,
        /// Target 0-based column index to aggregate (COUNT, SUM, MIN, MAX, AVG)
        #[arg(long)]
        col: usize,
        /// Optional filter 0-based column index
        #[arg(long)]
        where_col: Option<usize>,
        /// Optional filter equality string for --where-col
        #[arg(long)]
        where_eq: Option<String>,
        /// Optional document name
        #[arg(long)]
        doc: Option<String>,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },

    /// Zero-decompression persistent edits directly on .btlk files
    Edit {
        /// Input .btlk archive path
        input: PathBuf,
        /// Output .btlk archive path
        #[arg(short, long)]
        output: PathBuf,
        /// Optional document name to edit (for insert, delete, replace)
        #[arg(long)]
        doc: Option<String>,
        #[command(subcommand)]
        action: EditAction,
    },

    /// Run built-in benchmark suite comparing Buttlick vs raw uncompressed scans
    Bench {
        /// Uncompressed dataset size in megabytes
        #[arg(long, default_value_t = 64)]
        size_mb: usize,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum EditAction {
    /// Insert literal text at a byte offset in O(log N) time
    Insert {
        #[arg(long)]
        offset: u64,
        #[arg(long)]
        text: String,
    },
    /// Delete a byte range [offset, offset + len) in O(log N) time
    Delete {
        #[arg(long)]
        offset: u64,
        #[arg(long)]
        len: u64,
    },
    /// Replace all non-overlapping occurrences of `pattern` with `with` in O(n * |P|) time
    Replace {
        #[arg(long)]
        pattern: String,
        #[arg(long)]
        with: String,
    },
    /// Concatenate two documents in the archive into a new named document in O(log N) time
    Concat {
        #[arg(long)]
        doc1: String,
        #[arg(long)]
        doc2: String,
        #[arg(long)]
        new_name: String,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

fn write_slurp_line(
    w: &mut impl Write,
    doc_name: Option<&str>,
    line: &str,
    re: Option<&regex::Regex>,
    use_color: bool,
) -> io::Result<()> {
    if let Some(name) = doc_name {
        if use_color {
            write!(w, "\x1b[35m{name}\x1b[0m\x1b[36m:\x1b[0m")?;
        } else {
            write!(w, "{name}:")?;
        }
    }
    if use_color {
        if let Some(re) = re {
            let mut last = 0usize;
            for m in re.find_iter(line) {
                if m.start() > last {
                    w.write_all(&line.as_bytes()[last..m.start()])?;
                }
                if !m.is_empty() {
                    w.write_all(b"\x1b[1;31m")?;
                    w.write_all(m.as_str().as_bytes())?;
                    w.write_all(b"\x1b[0m")?;
                }
                last = m.end();
            }
            if last < line.len() {
                w.write_all(&line.as_bytes()[last..])?;
            }
            w.write_all(b"\n")?;
            return Ok(());
        }
    }
    writeln!(w, "{line}")
}

fn parse_delimiter(s: &str) -> Result<u8> {
    match s {
        "\\t" | "\t" => Ok(b'\t'),
        "space" | " " => Ok(b' '),
        _ if s.len() == 1 => Ok(s.as_bytes()[0]),
        _ => Err(ButtlickError::InvalidQuery(format!(
            "Delimiter must be a single ASCII byte (got '{s}')"
        ))),
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Compress {
            inputs,
            output,
            text_only,
            exclude_ext,
            stats,
        } => {
            let file_list = collect_input_files(&inputs, text_only, &exclude_ext)?;
            let total_files = file_list.len();
            let total_bytes: u64 = file_list.iter().map(|(_, _, sz)| *sz).sum();

            // Process in bounded 64 MB streaming batches so raw file buffers never blow up RAM
            // while saturating all CPU cores via Rayon!
            const STREAM_BATCH_BYTES: u64 = 64 * 1024 * 1024;
            let mut dag = GrammarDag::new();
            if total_bytes > 1024 * 1024 {
                let est_rules = (total_bytes as usize / 16).min(40_000_000);
                dag.rules.reserve(est_rules);
                dag.interner = buttlick::grammar::builder::RuleInterner::with_capacity(
                    est_rules.clamp(65_536, 7_500_000),
                );
            }
            let mut idx = 0usize;
            let mut processed_bytes = 0u64;

            while idx < total_files {
                let batch_start = idx;
                let mut batch_bytes = 0u64;
                while idx < total_files
                    && (batch_bytes < STREAM_BATCH_BYTES || idx == batch_start)
                {
                    batch_bytes += file_list[idx].2;
                    idx += 1;
                }
                // Keep companion files sharing the same 12-byte name prefix in the same batch
                while idx < total_files && batch_bytes < STREAM_BATCH_BYTES + 16 * 1024 * 1024 {
                    let prev_name = file_list[idx - 1].0.as_bytes();
                    let next_name = file_list[idx].0.as_bytes();
                    let p_len = prev_name.len().min(next_name.len()).min(12);
                    if p_len >= 8 && prev_name[..p_len] == next_name[..p_len] {
                        batch_bytes += file_list[idx].2;
                        idx += 1;
                    } else {
                        break;
                    }
                }
                let slice = &file_list[batch_start..idx];

                // Read all files in the current 64 MB batch in parallel across worker threads
                let loaded_batch: Result<Vec<(String, Vec<u8>)>> = slice
                    .par_iter()
                    .map(|(name, path, _)| {
                        let bytes = fs::read(path)?;
                        Ok((name.clone(), bytes))
                    })
                    .collect();
                let loaded_batch = loaded_batch?;

                // Compress all chunks across the batch in parallel across all CPU cores
                dag.add_documents_parallel(&loaded_batch);
                dag.interner.trim_for_next_batch(&dag.rules);
                processed_bytes += batch_bytes;

                if stats && total_files > 1 {
                    eprintln!(
                        "[buttlick] Processed {}/{} files ({:.1} / {:.1} MB, {} rules)...",
                        idx,
                        total_files,
                        processed_bytes as f64 / (1024.0 * 1024.0),
                        total_bytes as f64 / (1024.0 * 1024.0),
                        dag.rules.len()
                    );
                }
            }

            // Free hash-consing tables before streaming .btlk file to disk
            dag.interner.clear_tables();
            dag.save_to_path(&output)?;

            if stats {
                let file_len = fs::metadata(&output).map(|m| m.len()).ok();
                let rep = dag.inspect_report(file_len);
                println!(
                    "Compressed {} document(s) ({} bytes) -> {} ({} bytes, {:.2}x ratio, {} rules, height {})",
                    rep.num_roots,
                    rep.total_uncompressed_bytes,
                    output.display(),
                    rep.archive_bytes,
                    rep.compression_ratio,
                    rep.num_rules,
                    rep.max_height
                );
            }
        }

        Commands::Decompress {
            input,
            output,
            out_dir,
            doc,
        } => {
            let dag = GrammarDag::load_from_path(&input)?;
            if let Some(dir_path) = out_dir {
                for root in &dag.roots {
                    let target = dir_path.join(&root.name);
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let bytes = dag.decompress(Some(&root.name))?;
                    fs::write(target, &bytes)?;
                }
            } else {
                let bytes = dag.decompress(doc.as_deref())?;
                match output {
                    Some(out_path) => fs::write(out_path, &bytes)?,
                    None => {
                        let stdout = io::stdout();
                        let mut handle = stdout.lock();
                        handle.write_all(&bytes)?;
                        handle.flush()?;
                    }
                }
            }
        }

        Commands::Inspect { input, json } => {
            let file_len = fs::metadata(&input)?.len();
            let dag = GrammarDag::load_from_path(&input)?;
            let rep = dag.inspect_report(Some(file_len));
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap());
            } else {
                println!("Buttlick Archive (.btlk v1): {}", input.display());
                println!("  Documents          : {}", rep.num_roots);
                println!("  Total Uncompressed : {} bytes", rep.total_uncompressed_bytes);
                println!("  Archive Size       : {} bytes", rep.archive_bytes);
                println!("  Compression Ratio  : {:.2}x", rep.compression_ratio);
                println!(
                    "  Grammar Rules      : {} (Pair: {}, Run: {})",
                    rep.num_rules, rep.num_pair_rules, rep.num_run_rules
                );
                println!("  Max DAG Height     : {}", rep.max_height);
                for r in &rep.roots {
                    println!(
                        "  - Root '{}' : {} bytes, height {}, hash {}",
                        r.name, r.byte_len, r.height, r.kr_hash_hex
                    );
                }
            }
        }

        Commands::Slice {
            input,
            start,
            len,
            doc,
        } => {
            let dag = GrammarDag::load_from_path(&input)?;
            let slice = dag.extract_slice(doc.as_deref(), start, len)?;
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(&slice)?;
            handle.flush()?;
        }

        Commands::Eq {
            input,
            pos1,
            pos2,
            len,
            doc,
        } => {
            let dag = GrammarDag::load_from_path(&input)?;
            let eq = dag.substring_eq(doc.as_deref(), pos1, pos2, len)?;
            println!("{eq}");
        }

        Commands::Count {
            input,
            pattern,
            offsets,
            limit,
            doc,
            all,
        } => {
            let dag = GrammarDag::load_from_path(&input)?;
            if all {
                let results = dag.count_literal_all_docs(pattern.as_bytes())?;
                let show_zeros = results.len() <= 16;
                let mut total = 0u64;
                for (name, c) in results {
                    if c > 0 || show_zeros {
                        println!("{name}:{c}");
                    }
                    total += c;
                }
                println!("TOTAL:{total}");
            } else if offsets {
                let (count, locs) = dag.locate_literal(doc.as_deref(), pattern.as_bytes(), limit)?;
                println!("{count}");
                for off in locs {
                    println!("{off}");
                }
            } else {
                let count = dag.count_literal(doc.as_deref(), pattern.as_bytes())?;
                println!("{count}");
            }
        }

        Commands::Slurp {
            input,
            regex,
            lines,
            limit,
            line_count: _,
            match_count,
            doc,
            all,
            color,
        } => {
            let archive = MappedArchive::open(&input)?;
            let max_lines = if limit == 0 { usize::MAX } else { limit };
            if lines {
                let use_color = match color {
                    ColorMode::Always => true,
                    ColorMode::Never => false,
                    ColorMode::Auto => io::stdout().is_terminal(),
                };
                let highlight_re = if use_color {
                    regex::RegexBuilder::new(&regex)
                        .multi_line(false)
                        .dot_matches_new_line(false)
                        .build()
                        .ok()
                } else {
                    None
                };
                if all || (doc.is_none() && archive.roots.len() > 1) {
                    let results = archive.grep_lines_all_docs(&regex, max_lines)?;
                    let stdout = io::stdout();
                    let mut handle = io::BufWriter::new(stdout.lock());
                    for (name, matched_lines) in results {
                        for line in matched_lines {
                            write_slurp_line(
                                &mut handle,
                                Some(&name),
                                &line,
                                highlight_re.as_ref(),
                                use_color,
                            )?;
                        }
                    }
                    handle.flush()?;
                } else {
                    let matched_lines = archive.grep_lines(doc.as_deref(), &regex, max_lines)?;
                    let stdout = io::stdout();
                    let mut handle = io::BufWriter::new(stdout.lock());
                    for line in matched_lines {
                        write_slurp_line(
                            &mut handle,
                            None,
                            &line,
                            highlight_re.as_ref(),
                            use_color,
                        )?;
                    }
                    handle.flush()?;
                }
            } else {
                let mode = if match_count {
                    GrepMode::MatchCount
                } else {
                    GrepMode::LineCount
                };
                if all || (doc.is_none() && archive.roots.len() > 1) {
                    let results = archive.grep_all_docs(&regex, mode)?;
                    let show_zeros = results.len() <= 16;
                    let mut total = 0u64;
                    for (name, c) in results {
                        if c > 0 || show_zeros {
                            println!("{name}:{c}");
                        }
                        total += c;
                    }
                    println!("TOTAL:{total}");
                } else {
                    let count = archive.grep(doc.as_deref(), &regex, mode)?;
                    println!("{count}");
                }
            }
        }

        Commands::Query {
            input,
            delimiter,
            col,
            where_col,
            where_eq,
            doc,
            json,
        } => {
            let delim = parse_delimiter(&delimiter)?;
            let filter = match (where_col, where_eq) {
                (Some(c), Some(v)) => Some((c, v.into_bytes())),
                (None, None) => None,
                _ => {
                    return Err(ButtlickError::InvalidQuery(
                        "Both --where-col and --where-eq must be provided together".into(),
                    ))
                }
            };
            let dag = GrammarDag::load_from_path(&input)?;
            let q = AggregateQuery {
                delimiter: delim,
                target_col: col,
                filter,
            };
            let res = dag.aggregate_query(doc.as_deref(), &q)?;
            if json {
                let payload = serde_json::json!({
                    "count": res.count,
                    "sum": res.sum,
                    "min": res.min,
                    "max": res.max,
                    "avg": res.avg(),
                });
                println!("{}", serde_json::to_string_pretty(&payload).unwrap());
            } else {
                println!("COUNT : {}", res.count);
                println!("SUM   : {}", res.sum);
                println!(
                    "MIN   : {}",
                    res.min.map(|v| v.to_string()).unwrap_or_else(|| "NULL".into())
                );
                println!(
                    "MAX   : {}",
                    res.max.map(|v| v.to_string()).unwrap_or_else(|| "NULL".into())
                );
                println!(
                    "AVG   : {}",
                    res.avg()
                        .map(|v| format!("{v:.4}"))
                        .unwrap_or_else(|| "NULL".into())
                );
            }
        }

        Commands::Edit {
            input,
            output,
            doc,
            action,
        } => {
            let mut dag = GrammarDag::load_from_path(&input)?;
            match action {
                EditAction::Insert { offset, text } => {
                    dag.insert(doc.as_deref(), offset, text.as_bytes())?;
                }
                EditAction::Delete { offset, len } => {
                    dag.delete(doc.as_deref(), offset, len)?;
                }
                EditAction::Replace { pattern, with } => {
                    let _ = dag.replace_all(doc.as_deref(), pattern.as_bytes(), with.as_bytes())?;
                }
                EditAction::Concat {
                    doc1,
                    doc2,
                    new_name,
                } => {
                    let _ = dag.concat_documents(&doc1, &doc2, new_name)?;
                }
            }
            dag.save_to_path(&output)?;
        }

        Commands::Bench { size_mb, json } => {
            let rep = run_benchmarks(size_mb);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap());
            } else {
                println!("=========================================================================");
                println!(" Buttlick Zero-Decompression Compute Benchmark ({size_mb} MB Dataset)");
                println!("=========================================================================");
                println!("  Uncompressed Size : {} bytes", rep.uncompressed_bytes);
                println!("  Compressed (.btlk): {} bytes ({:.2}x ratio)", rep.archive_bytes, rep.compression_ratio);
                println!("  Grammar DAG Rules : {} rules (height {})", rep.num_rules, rep.dag_height);
                println!("  LCP Compress Time : {:.2} ms", rep.compress_ms);
                println!("-------------------------------------------------------------------------");
                println!(
                    "  {:<46} | {:>10} | {:>10} | {:>8}",
                    "Operation", "Buttlick", "Raw Scan", "Speedup"
                );
                println!("-------------------------------------------------------------------------");
                for b in &rep.benchmarks {
                    println!(
                        "  {:<46} | {:>7} us | {:>7} us | {:>7.1}x",
                        b.operation, b.buttlick_us, b.raw_scan_us, b.speedup_x
                    );
                }
                println!("=========================================================================");
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
