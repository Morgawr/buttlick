use thiserror::Error;

#[derive(Debug, Error)]
pub enum ButtlickError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid .btlk magic bytes")]
    InvalidMagic,

    #[error("Unsupported .btlk format version: {0}")]
    UnsupportedVersion(u16),

    #[error("Checksum mismatch in {section}: expected 0x{expected:016x}, got 0x{actual:016x}")]
    ChecksumMismatch {
        section: &'static str,
        expected: u64,
        actual: u64,
    },

    #[error("Corrupted .btlk format: {0}")]
    CorruptedFormat(String),

    #[error("Document '{0}' not found in archive")]
    DocumentNotFound(String),

    #[error("Range out of bounds: offset={offset}, len={len}, total_len={total}")]
    OutOfBounds { offset: u64, len: u64, total: u64 },

    #[error("Invalid regular expression '{pattern}': {message}")]
    InvalidRegex { pattern: String, message: String },

    #[error("Pattern cannot be empty")]
    EmptyPattern,

    #[error("Invalid query specification: {0}")]
    InvalidQuery(String),
}

pub type Result<T> = std::result::Result<T, ButtlickError>;
