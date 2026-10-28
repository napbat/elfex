//! Find the ELF files of the corpus.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The ELF magic (`EI_MAG0` to `EI_MAG3`).
const MAGIC: [u8; 4] = *b"\x7fELF";

/// The number of ELF files below one root path.
pub struct Source {
    /// The path from `ELFEX_CORPUS`.
    pub root: PathBuf,
    /// The number of ELF files below the path that no earlier root contains.
    pub files: usize,
}

/// The ELF files of the corpus.
#[derive(Default)]
pub struct Found {
    /// The ELF files, in path order, each one time.
    pub files: Vec<PathBuf>,
    /// The number of ELF files for each root path.
    pub sources: Vec<Source>,
    /// The number of ELF files that are larger than the limit.
    pub too_large: usize,
    /// The number of files and directories that cannot be read.
    pub unreadable: usize,
}

/// Find the ELF files below `roots`, each one time.
///
/// The function walks directories recursively. It follows a symbolic link to a file, but not a
/// symbolic link to a directory. It skips files larger than `max_bytes` and entries that it
/// cannot read.
pub fn collect(roots: &[PathBuf], max_bytes: u64) -> Found {
    let mut found = Found::default();
    let mut seen = BTreeSet::new();
    for root in roots {
        let mut files = Vec::new();
        let mut walker = Walker {
            max_bytes,
            files: &mut files,
            too_large: 0,
            unreadable: 0,
        };
        match fs::metadata(root) {
            Ok(metadata) if metadata.is_dir() => walker.directory(root),
            Ok(_) => walker.file(root),
            Err(_) => walker.unreadable += 1,
        }
        found.too_large += walker.too_large;
        found.unreadable += walker.unreadable;
        // Check each file one time, also when two roots contain it or symbolic links name it.
        let mut count = 0;
        for file in files {
            let key = fs::canonicalize(&file).unwrap_or_else(|_| file.clone());
            if seen.insert(key) {
                found.files.push(file);
                count += 1;
            }
        }
        found.sources.push(Source {
            root: root.clone(),
            files: count,
        });
    }
    found
}

/// The state of a walk below one root path.
struct Walker<'a> {
    /// The size of the largest file to select.
    max_bytes: u64,
    /// The selected files.
    files: &'a mut Vec<PathBuf>,
    /// The number of ELF files larger than `max_bytes`.
    too_large: usize,
    /// The number of entries that cannot be read.
    unreadable: usize,
}

impl Walker<'_> {
    /// Walk the directory at `path` and its subdirectories, in name order.
    fn directory(&mut self, path: &Path) {
        let Ok(entries) = fs::read_dir(path) else {
            self.unreadable += 1;
            return;
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let Ok(file_type) = entry.file_type() else {
                self.unreadable += 1;
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                self.directory(&path);
            } else if file_type.is_file()
                || (file_type.is_symlink() && fs::metadata(&path).is_ok_and(|meta| meta.is_file()))
            {
                self.file(&path);
            }
        }
    }

    /// Select the file at `path` if it starts with the ELF magic and is not too large.
    fn file(&mut self, path: &Path) {
        let Ok(mut file) = fs::File::open(path) else {
            self.unreadable += 1;
            return;
        };
        let mut magic = [0; 4];
        if file.read_exact(&mut magic).is_err() || magic != MAGIC {
            return;
        }
        match file.metadata() {
            Ok(metadata) if metadata.len() > self.max_bytes => self.too_large += 1,
            Ok(_) => self.files.push(path.to_path_buf()),
            Err(_) => self.unreadable += 1,
        }
    }
}
