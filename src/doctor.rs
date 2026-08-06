//! Read-only Ren'Py project health checks.
#![allow(missing_docs)]
#![allow(clippy::possible_missing_else, clippy::collapsible_if)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::Result;
use crate::archive::walker::{FileEntry, GameWalker};
use crate::error::RenpyExError;
use crate::verify::magic::Magic;
use crate::verify::sha::{sha256_file, to_hex};

/// Current JSON schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Input layout detected by Doctor.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    ProjectRoot,
    GameDirectory,
    FlatDirectory,
}

/// Discovered project paths.
#[derive(Debug, Clone)]
pub struct Project {
    pub input: PathBuf,
    pub root: PathBuf,
    pub game: PathBuf,
    pub layout: Layout,
}

/// Complete read-only report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub project: ProjectReport,
    pub summary: Summary,
    pub media: Vec<MediaRecord>,
    pub references: References,
    pub translations: Translations,
    pub duplicates: Vec<DuplicateGroup>,
    pub orphans: Vec<Orphan>,
    pub notes: Notes,
}

impl Report {
    /// Return true for error-level findings.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.summary.errors > 0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectReport {
    pub input: String,
    pub root: String,
    pub game: String,
    pub layout: Layout,
    pub archives: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub files: u64,
    pub total_bytes: u64,
    pub media_files: u64,
    pub media_errors: u64,
    pub static_references: u64,
    pub resolved_references: u64,
    pub missing_references: u64,
    pub unsafe_references: u64,
    pub dynamic_references: u64,
    pub translation_languages: u64,
    pub translation_errors: u64,
    pub duplicate_groups: u64,
    pub orphan_candidates: u64,
    pub errors: u64,
    pub warnings: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MediaRecord {
    pub path: String,
    pub size: u64,
    pub magic: String,
    pub kind: Option<MediaKind>,
    pub status: MediaStatus,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Image,
    Audio,
    Container,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaStatus {
    MagicOk,
    InvalidMagic,
    MagicMismatch,
}

#[derive(Debug, Clone, Serialize)]
pub struct References {
    pub resolved: Vec<Reference>,
    pub missing: Vec<Reference>,
    pub archive_unresolved: Vec<Reference>,
    pub unsafe_paths: Vec<UnsafeReference>,
    pub dynamic: Vec<DynamicReference>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub path: String,
    pub locations: Vec<Location>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub file: String,
    pub line: u32,
    pub kind: ReferenceKind,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Image,
    Audio,
    Video,
    Displayable,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnsafeReference {
    pub raw: String,
    pub file: String,
    pub line: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DynamicReference {
    pub file: String,
    pub line: u32,
    pub statement: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Translations {
    pub languages: Vec<Language>,
    pub errors: Vec<TranslationError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Language {
    pub language: String,
    pub files: Vec<String>,
    pub blocks: u64,
    pub old_strings: u64,
    pub new_strings: u64,
    pub missing_new: u64,
    pub unchanged: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranslationError {
    pub language: String,
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DuplicateGroup {
    pub sha256: String,
    pub size: u64,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Orphan {
    pub path: String,
    pub size: u64,
    pub magic: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Notes {
    pub compiled_scripts: Vec<String>,
    pub unreadable_text: Vec<String>,
    pub archives_uninspected: Vec<String>,
    pub limitations: Vec<String>,
}

/// Resolve a project root or a direct game directory.
pub fn discover(input: &Path) -> Result<Project> {
    if !input.is_dir() {
        return Err(RenpyExError::Invalid(format!(
            "not a directory: {}",
            input.display()
        )));
    }
    if input.file_name().and_then(|v| v.to_str()) == Some("game") {
        return Ok(Project {
            input: input.to_path_buf(),
            root: input.parent().unwrap_or(input).to_path_buf(),
            game: input.to_path_buf(),
            layout: Layout::GameDirectory,
        });
    }
    let game = input.join("game");
    if game.is_dir() {
        Ok(Project {
            input: input.to_path_buf(),
            root: input.to_path_buf(),
            game,
            layout: Layout::ProjectRoot,
        })
    } else {
        Ok(Project {
            input: input.to_path_buf(),
            root: input.to_path_buf(),
            game: input.to_path_buf(),
            layout: Layout::FlatDirectory,
        })
    }
}

/// Inspect without writing files, executing Python, or unpacking archives.
pub fn inspect(input: &Path) -> Result<Report> {
    let project = discover(input)?;
    let mut files = GameWalker::new(project.game.clone()).walk()?.files;
    files.sort_by_cached_key(|file| (norm(&file.rel), path(&file.rel)));
    let archives: Vec<String> = files
        .iter()
        .filter(|f| ext(&f.rel, "rpa"))
        .map(|f| path(&f.rel))
        .collect();
    let media = media_report(&files);
    let scan = source_scan(&files, !archives.is_empty());
    let duplicates = duplicate_groups(&files, &media);
    let orphans = orphan_candidates(&files, &media, &scan.used);
    let media_errors = media
        .iter()
        .filter(|m| !matches!(m.status, MediaStatus::MagicOk))
        .count() as u64;
    let errors = media_errors
        + scan.refs.missing.len() as u64
        + scan.refs.unsafe_paths.len() as u64
        + scan.text_errors.len() as u64
        + scan.translations.errors.len() as u64;
    let warnings = scan.refs.archive_unresolved.len() as u64
        + scan.refs.dynamic.len() as u64
        + duplicates.len() as u64
        + orphans.len() as u64;
    let static_count = scan
        .refs
        .resolved
        .iter()
        .chain(&scan.refs.missing)
        .chain(&scan.refs.archive_unresolved)
        .map(|r| r.locations.len() as u64)
        .sum();
    let summary = Summary {
        files: files.len() as u64,
        total_bytes: files.iter().map(|f| f.size).sum(),
        media_files: media.len() as u64,
        media_errors,
        static_references: static_count,
        resolved_references: scan
            .refs
            .resolved
            .iter()
            .map(|r| r.locations.len() as u64)
            .sum(),
        missing_references: scan.refs.missing.len() as u64,
        unsafe_references: scan.refs.unsafe_paths.len() as u64,
        dynamic_references: scan.refs.dynamic.len() as u64,
        translation_languages: scan.translations.languages.len() as u64,
        translation_errors: scan.translations.errors.len() as u64,
        duplicate_groups: duplicates.len() as u64,
        orphan_candidates: orphans.len() as u64,
        errors,
        warnings,
    };
    Ok(Report {
        schema_version: SCHEMA_VERSION,
        project: ProjectReport {
            input: path(&project.input),
            root: path(&project.root),
            game: path(&project.game),
            layout: project.layout,
            archives: archives.clone(),
        },
        summary,
        media,
        references: scan.refs,
        translations: scan.translations,
        duplicates,
        orphans,
        notes: Notes {
            compiled_scripts: files
                .iter()
                .filter(|f| ext(&f.rel, "rpyc") || ext(&f.rel, "rpymc"))
                .map(|f| path(&f.rel))
                .collect(),
            unreadable_text: scan.text_errors,
            archives_uninspected: archives,
            limitations: vec![
                "static references only".into(),
                "media checks use signatures, not full decoders".into(),
                "RPA payloads are reported but not inspected".into(),
            ],
        },
    })
}

/// Render stable pretty JSON.
pub fn json(report: &Report) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(|e| RenpyExError::Invalid(e.to_string()))
}

/// Render concise human output.
pub fn text(report: &Report) -> String {
    let s = &report.summary;
    format!(
        "RenpyEx Doctor\nProject: {}\nGame: {}\nFiles: {}\nMedia: {} ({} errors)\nReferences: {} static, {} resolved, {} missing\nTranslations: {} languages, {} errors\nDuplicates: {}\nOrphans: {}\nErrors: {}\nWarnings: {}\n",
        report.project.root,
        report.project.game,
        s.files,
        s.media_files,
        s.media_errors,
        s.static_references,
        s.resolved_references,
        s.missing_references,
        s.translation_languages,
        s.translation_errors,
        s.duplicate_groups,
        s.orphan_candidates,
        s.errors,
        s.warnings
    )
}

struct Scan {
    refs: References,
    used: BTreeSet<String>,
    text_errors: Vec<String>,
    translations: Translations,
}

fn source_scan(files: &[FileEntry], archives: bool) -> Scan {
    let direct: BTreeMap<String, &FileEntry> = files.iter().map(|f| (norm(&f.rel), f)).collect();
    let mut refs: BTreeMap<String, Vec<Location>> = BTreeMap::new();
    let mut unsafe_paths = Vec::new();
    let mut dynamic = Vec::new();
    let mut used = BTreeSet::new();
    let mut text_errors = Vec::new();
    let mut translation_map: BTreeMap<String, TranslationWork> = BTreeMap::new();
    for file in files
        .iter()
        .filter(|f| ext(&f.rel, "rpy") || ext(&f.rel, "rpym"))
    {
        let name = path(&file.rel);
        let language = tl_language(&file.rel);
        if let Some(lang) = &language {
            translation_map
                .entry(lang.clone())
                .or_default()
                .files
                .insert(name.clone());
        }
        let source = match fs::read_to_string(&file.abs) {
            Ok(v) => v,
            Err(e) => {
                text_errors.push(format!("{name}: {e}"));
                continue;
            }
        };
        for (i, raw) in source.lines().enumerate() {
            let line_no = i as u32 + 1;
            let line = strip_comment(raw);
            scan_translation(
                &mut translation_map,
                language.as_deref(),
                &name,
                line_no,
                &line,
            );
            let literals = quotes(&line);
            let kind = kind(&line);
            let asset_statement = is_ref(&line);
            let fallback_list = line.contains("Frame([") || line.contains("ConditionSwitch(");
            if fallback_list || (literals.is_empty() && asset_statement) {
                dynamic.push(DynamicReference {
                    file: name.clone(),
                    line: line_no,
                    statement: line.trim().into(),
                });
                continue;
            }
            if !asset_statement || literals.is_empty() {
                continue;
            }
            for literal in literals.into_iter().filter(|v| asset(v)) {
                if dynamic_placeholder(&literal) {
                    dynamic.push(DynamicReference {
                        file: name.clone(),
                        line: line_no,
                        statement: line.trim().into(),
                    });
                    continue;
                }
                if !safe(&literal) {
                    unsafe_paths.push(UnsafeReference {
                        raw: literal,
                        file: name.clone(),
                        line: line_no,
                        reason: "absolute, traversal, NUL, or interpolation".into(),
                    });
                    continue;
                }
                refs.entry(normalize_ref(&literal))
                    .or_default()
                    .push(Location {
                        file: name.clone(),
                        line: line_no,
                        kind,
                    });
            }
        }
        if let Some(language) = language.as_deref()
            && let Some(work) = translation_map.get_mut(language)
        {
            work.finish_pending();
        }
    }
    let mut resolved = Vec::new();
    let mut missing = Vec::new();
    let mut archive_unresolved = Vec::new();
    let mut used_paths = BTreeSet::new();
    for (name, locations) in refs {
        let visual_reference = locations.iter().any(|location| {
            matches!(
                location.kind,
                ReferenceKind::Image | ReferenceKind::Displayable
            )
        });
        let target = direct.get(&name).copied().or_else(|| {
            visual_reference
                .then(|| format!("images/{name}"))
                .and_then(|fallback| direct.get(&fallback).copied())
        });
        if let Some(file) = target {
            used_paths.insert(norm(&file.rel));
            resolved.push(Reference {
                path: name,
                locations,
            });
        } else if archives {
            archive_unresolved.push(Reference {
                path: name,
                locations,
            });
        } else {
            missing.push(Reference {
                path: name,
                locations,
            });
        }
    }
    used.extend(used_paths);
    let translations = finish_translations(translation_map);
    Scan {
        refs: References {
            resolved,
            missing,
            archive_unresolved,
            unsafe_paths,
            dynamic,
        },
        used,
        text_errors,
        translations,
    }
}

#[derive(Default)]
struct TranslationWork {
    files: BTreeSet<String>,
    blocks: u64,
    old: u64,
    new: u64,
    missing: u64,
    unchanged: u64,
    pending: Option<(String, u32, String)>,
    errors: Vec<(String, u32, String, String)>,
}

impl TranslationWork {
    fn finish_pending(&mut self) {
        if let Some((file, line, text)) = self.pending.take() {
            self.missing += 1;
            self.errors.push((file, line, text, "missing_new".into()));
        }
    }
}

fn scan_translation(
    all: &mut BTreeMap<String, TranslationWork>,
    lang: Option<&str>,
    file: &str,
    line: u32,
    source: &str,
) {
    let Some(lang) = lang else { return };
    let w = all.entry(lang.into()).or_default();
    let t = source.trim();
    if t.starts_with("translate ") {
        w.blocks += 1
    }
    if let Some(old) = quoted_after(t, "old") {
        w.finish_pending();
        w.old += 1;
        w.pending = Some((file.into(), line, old))
    }
    if let Some(new) = quoted_after(t, "new") {
        w.new += 1;
        if let Some((f, l, old)) = w.pending.take() {
            if new.is_empty() {
                w.missing += 1;
                w.errors.push((f, l, old, "missing_new".into()))
            } else if new == old {
                w.unchanged += 1
            }
        }
    }
}
fn finish_translations(all: BTreeMap<String, TranslationWork>) -> Translations {
    let mut languages = Vec::new();
    let mut errors = Vec::new();
    for (lang, mut w) in all {
        w.finish_pending();
        for (f, l, t, k) in w.errors {
            errors.push(TranslationError {
                language: lang.clone(),
                file: f,
                line: l,
                kind: k,
                text: t,
            })
        }
        languages.push(Language {
            language: lang,
            files: w.files.into_iter().collect(),
            blocks: w.blocks,
            old_strings: w.old,
            new_strings: w.new,
            missing_new: w.missing,
            unchanged: w.unchanged,
        })
    }
    Translations { languages, errors }
}
fn media_report(files: &[FileEntry]) -> Vec<MediaRecord> {
    files
        .iter()
        .filter(|f| magic_kind(f.magic).is_some() || media_ext(&f.rel))
        .map(|f| MediaRecord {
            path: path(&f.rel),
            size: f.size,
            magic: magic_name(f.magic).into(),
            kind: magic_kind(f.magic),
            status: media_status(f),
        })
        .collect()
}
fn duplicate_groups(files: &[FileEntry], media: &[MediaRecord]) -> Vec<DuplicateGroup> {
    let valid: BTreeSet<&str> = media
        .iter()
        .filter(|m| matches!(m.status, MediaStatus::MagicOk))
        .map(|m| m.path.as_str())
        .collect();
    let mut groups: BTreeMap<(u64, String), Vec<String>> = BTreeMap::new();
    for f in files {
        let p = path(&f.rel);
        if valid.contains(p.as_str()) {
            if let Ok(digest) = sha256_file(&f.abs) {
                groups.entry((f.size, to_hex(&digest))).or_default().push(p)
            }
        }
    }
    groups
        .into_iter()
        .filter_map(|((size, sha), mut paths)| {
            if paths.len() < 2 {
                return None;
            }
            paths.sort();
            Some(DuplicateGroup {
                sha256: sha,
                size,
                paths,
            })
        })
        .collect()
}
fn orphan_candidates(
    files: &[FileEntry],
    media: &[MediaRecord],
    used: &BTreeSet<String>,
) -> Vec<Orphan> {
    let valid: BTreeSet<&str> = media
        .iter()
        .filter(|m| matches!(m.status, MediaStatus::MagicOk))
        .map(|m| m.path.as_str())
        .collect();
    files
        .iter()
        .filter_map(|f| {
            let p = path(&f.rel);
            if valid.contains(p.as_str()) && !used.contains(&norm(&f.rel)) {
                Some(Orphan {
                    path: p,
                    size: f.size,
                    magic: magic_name(f.magic).into(),
                })
            } else {
                None
            }
        })
        .collect()
}
fn magic_kind(m: Magic) -> Option<MediaKind> {
    match m {
        Magic::Png | Magic::Jpeg | Magic::Gif | Magic::WebP | Magic::Bmp => Some(MediaKind::Image),
        Magic::Ogg | Magic::Wav | Magic::Flac | Magic::Mp3Id3 | Magic::Mp3Frame => {
            Some(MediaKind::Audio)
        }
        Magic::IsoBmff | Magic::Matroska => Some(MediaKind::Container),
        _ => None,
    }
}
fn media_ext(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        matches!(
            e.to_ascii_lowercase().as_str(),
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "bmp"
                | "ogg"
                | "wav"
                | "mp3"
                | "flac"
                | "mp4"
                | "m4a"
                | "mkv"
                | "webm"
        )
    })
}
fn media_status(f: &FileEntry) -> MediaStatus {
    if !media_ext(&f.rel) {
        return MediaStatus::MagicOk;
    }
    if matches!(f.magic, Magic::Empty | Magic::Unknown) {
        return MediaStatus::InvalidMagic;
    }
    let e = f
        .rel
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ok = match e.as_str() {
        "png" => f.magic == Magic::Png,
        "jpg" | "jpeg" => f.magic == Magic::Jpeg,
        "gif" => f.magic == Magic::Gif,
        "webp" => f.magic == Magic::WebP,
        "bmp" => f.magic == Magic::Bmp,
        "ogg" => f.magic == Magic::Ogg,
        "wav" => f.magic == Magic::Wav,
        "flac" => f.magic == Magic::Flac,
        "mp3" => matches!(f.magic, Magic::Mp3Id3 | Magic::Mp3Frame),
        "mp4" | "m4a" => f.magic == Magic::IsoBmff,
        "mkv" | "webm" => f.magic == Magic::Matroska,
        _ => true,
    };
    if ok {
        MediaStatus::MagicOk
    } else {
        MediaStatus::MagicMismatch
    }
}
fn magic_name(m: Magic) -> &'static str {
    match m {
        Magic::Png => "png",
        Magic::Jpeg => "jpeg",
        Magic::Gif => "gif",
        Magic::WebP => "webp",
        Magic::Bmp => "bmp",
        Magic::Ogg => "ogg",
        Magic::Wav => "wav",
        Magic::IsoBmff => "iso_bmff",
        Magic::Matroska => "matroska",
        Magic::Flac => "flac",
        Magic::Mp3Id3 => "mp3_id3",
        Magic::Mp3Frame => "mp3_frame",
        Magic::Rpyc => "rpyc",
        Magic::Rpa3 => "rpa3",
        Magic::Text => "text",
        Magic::Empty => "empty",
        Magic::Unknown => "unknown",
    }
}
fn path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}
fn norm(p: &Path) -> String {
    path(p).to_ascii_lowercase()
}
fn ext(p: &Path, e: &str) -> bool {
    p.extension()
        .and_then(|v| v.to_str())
        .is_some_and(|v| v.eq_ignore_ascii_case(e))
}
fn tl_language(p: &Path) -> Option<String> {
    let mut tl = false;
    for c in p.components() {
        let v = c.as_os_str().to_string_lossy();
        if tl {
            return Some(v.into());
        }
        tl = v.eq_ignore_ascii_case("tl")
    }
    None
}
fn kind(s: &str) -> ReferenceKind {
    let l = s.to_ascii_lowercase();
    let head = statement_head(s);
    if matches!(head, Some("play" | "queue"))
        && (l.split_ascii_whitespace().nth(1) == Some("movie")
            || l.contains(".mp4")
            || l.contains(".webm"))
    {
        ReferenceKind::Video
    } else if matches!(head, Some("play" | "queue" | "voice")) {
        ReferenceKind::Audio
    } else if matches!(head, Some("image" | "show" | "scene")) {
        ReferenceKind::Image
    } else {
        ReferenceKind::Displayable
    }
}
fn is_ref(s: &str) -> bool {
    matches!(
        statement_head(s),
        Some("image" | "show" | "scene" | "play" | "queue" | "voice")
    )
}
fn statement_head(s: &str) -> Option<&str> {
    let head = s.trim_start().split_ascii_whitespace().next()?;
    match head {
        "image" | "show" | "scene" | "play" | "queue" | "voice" => Some(head),
        _ => None,
    }
}
fn asset(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [
        "images/", "image/", "audio/", "music/", "sound/", "voice/", "gui/", "fonts/", "video/",
        "movies/",
    ]
    .iter()
    .any(|p| l.starts_with(p))
        || media_ext(Path::new(s))
}
fn dynamic_placeholder(s: &str) -> bool {
    s.contains('%') || s.contains('[') || s.contains(']') || s.contains('{') || s.contains('}')
}
fn safe(s: &str) -> bool {
    let n = s.replace('\\', "/");
    !n.starts_with('/')
        && !n.starts_with("//")
        && n.as_bytes().get(1) != Some(&b':')
        && !n.split('/').any(|p| p == "..")
        && !s.contains('\0')
        && !dynamic_placeholder(s)
}
fn normalize_ref(s: &str) -> String {
    s.replace('\\', "/")
        .trim_start_matches("./")
        .to_ascii_lowercase()
}
fn strip_comment(s: &str) -> String {
    let mut q = None;
    let mut esc = false;
    for (i, c) in s.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        if c == '\\' && q.is_some() {
            esc = true;
            continue;
        }
        if c == '"' || c == '\'' {
            q = if q == Some(c) {
                None
            } else if q.is_none() {
                Some(c)
            } else {
                q
            };
            continue;
        }
        if c == '#' && q.is_none() {
            return s[..i].into();
        }
    }
    s.into()
}
fn quotes(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = s.char_indices();
    while let Some((_, q)) = it.next() {
        if q != '"' && q != '\'' {
            continue;
        }
        let mut v = String::new();
        while let Some((_, c)) = it.next() {
            if c == '\\' {
                if let Some((_, e)) = it.next() {
                    v.push(e)
                }
            } else if c == q {
                out.push(v);
                break;
            } else {
                v.push(c)
            }
        }
    }
    out
}
fn quoted_after(s: &str, k: &str) -> Option<String> {
    if s.trim_start().starts_with(k) {
        quotes(s).into_iter().next()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn finds_missing_and_json() {
        let d = tempdir().unwrap();
        fs::write(
            d.path().join("script.rpy"),
            "image x = \"images/missing.png\"\n",
        )
        .unwrap();
        let r = inspect(d.path()).unwrap();
        assert_eq!(r.summary.missing_references, 1);
        assert!(r.has_errors());
        assert!(json(&r).unwrap().contains("schema_version"))
    }
    #[test]
    fn resolves_default_images() {
        let d = tempdir().unwrap();
        fs::create_dir_all(d.path().join("images")).unwrap();
        fs::write(d.path().join("script.rpy"), "image x = \"x.png\"\n").unwrap();
        fs::write(
            d.path().join("images/x.png"),
            [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
        )
        .unwrap();
        let r = inspect(d.path()).unwrap();
        assert_eq!(r.summary.missing_references, 0)
    }

    #[test]
    fn ignores_non_asset_dialogue_literals() {
        let d = tempdir().unwrap();
        fs::write(
            d.path().join("script.rpy"),
            "label start:\n    \"A dialogue line that mentions image.png.\"\n    e \"show images/missing.png\"\n",
        )
        .unwrap();
        let r = inspect(d.path()).unwrap();
        assert_eq!(r.summary.static_references, 0);
        assert_eq!(r.summary.missing_references, 0);
    }

    #[test]
    fn terminal_old_string_increments_missing_count() {
        let d = tempdir().unwrap();
        let translation_dir = d.path().join("tl/french");
        fs::create_dir_all(&translation_dir).unwrap();
        fs::write(translation_dir.join("strings.rpy"), "old \"Hello\"\n").unwrap();

        let report = inspect(d.path()).unwrap();

        assert_eq!(report.translations.languages.len(), 1);
        assert_eq!(report.translations.languages[0].missing_new, 1);
        assert_eq!(report.translations.errors.len(), 1);
        assert_eq!(report.translations.errors[0].kind, "missing_new");
    }

    #[test]
    fn translation_pairs_do_not_cross_file_boundaries() {
        let d = tempdir().unwrap();
        let translation_dir = d.path().join("tl/french");
        fs::create_dir_all(&translation_dir).unwrap();
        fs::write(translation_dir.join("a.rpy"), "old \"from a\"\n").unwrap();
        fs::write(translation_dir.join("b.rpy"), "new \"from b\"\n").unwrap();

        let report = inspect(d.path()).unwrap();

        let french = &report.translations.languages[0];
        assert_eq!(french.old_strings, 1);
        assert_eq!(french.new_strings, 1);
        assert_eq!(french.missing_new, 1);
        assert_eq!(report.translations.errors.len(), 1);
        assert!(report.translations.errors[0].file.ends_with("a.rpy"));
    }

    #[test]
    fn play_movie_is_classified_as_video() {
        assert!(matches!(
            kind("play movie \"video/opening.webm\""),
            ReferenceKind::Video
        ));
    }
}
