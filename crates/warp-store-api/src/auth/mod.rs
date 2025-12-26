//! Authentication modules

mod s3_sig_v4;

pub use s3_sig_v4::{verify_signature_v4, SignatureV4};

#[cfg(feature = "iam")]
mod iam_middleware;

#[cfg(feature = "iam")]
pub use iam_middleware::{
    iam_auth_middleware, iam_authz_middleware, IamContext, IamManagers,
};
