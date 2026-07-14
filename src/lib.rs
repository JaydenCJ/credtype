//! credtype — file(1) for secrets.
//!
//! Identify and structurally validate a single leaked token, fully offline.
//! Given one string, credtype answers two questions developers ask constantly:
//! *what key is this?* and *is it real?* — the second by recomputing the
//! token's own embedded checksum where one exists (GitHub CRC-32, payment-card
//! Luhn, OpenSSH magic) and by decoding structure where it does not (AWS
//! account id, JWT claims, UUID version).
//!
//! It is not a repository scanner like gitleaks or trufflehog: it classifies
//! and validates exactly one token. Everything here is built on the standard
//! library alone — offline, deterministic, zero supply chain.
//!
//! The pipeline: [`registry::classify`] runs every [`token::Detector`] over the
//! input, ranks the hits by confidence and checksum verdict, and falls back to
//! an entropy description ([`registry`]) when nothing matches. Results render as
//! text or JSON via [`report`].

pub mod aws;
pub mod card;
pub mod charset;
pub mod checksum;
pub mod cli;
pub mod github;
pub mod json;
pub mod jwt;
pub mod pem;
pub mod registry;
pub mod report;
pub mod token;
pub mod uuid;
pub mod vendors;

/// Crate version, single-sourced from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
