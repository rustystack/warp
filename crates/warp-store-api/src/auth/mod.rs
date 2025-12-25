//! Authentication modules

mod s3_sig_v4;

pub use s3_sig_v4::{verify_signature_v4, SignatureV4};
