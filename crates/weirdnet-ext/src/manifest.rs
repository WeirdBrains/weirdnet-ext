//! Extension manifests and their signatures.
//!
//! A manifest says what an extension is (id, name, version), who made it (the author's
//! Weirdnet user id and public key), what it needs (host API version, capabilities, site
//! patterns), and every file in the package with its size and BLAKE3 hash. The author's user
//! key (Ed25519) signs the exact `manifest.json` bytes under the domain
//! [`MANIFEST_DOMAIN`].

use crate::error::{Error, Result, invalid};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use libp2p_identity::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};

/// The signature domain of manifests.
pub const MANIFEST_DOMAIN: &[u8] = b"weirdnet-ext/manifest/v1\n";
/// The manifest format this crate writes and reads.
pub const FORMAT: u32 = 1;

/// A capability an extension asks for, optionally limited to patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Capability {
    /// Such as `page.read`, `net.fetch`, `storage`.
    pub name: String,
    /// URL or site patterns (`*` matches any run of characters); empty means unrestricted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
}

impl Capability {
    /// A capability without patterns.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), patterns: Vec::new() }
    }

    /// A capability limited to `patterns`.
    pub fn with_patterns(name: impl Into<String>, patterns: &[&str]) -> Self {
        Self { name: name.into(), patterns: patterns.iter().map(|p| p.to_string()).collect() }
    }
}

/// A native binary for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Native {
    /// `os-arch`, such as `linux-x86_64` or `macos-aarch64` (see [`current_target`]).
    pub target: String,
    /// Path of the binary in the package's files.
    pub path: String,
}

/// A file in the package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path (`/`-separated, no `..`).
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// BLAKE3, hex.
    pub blake3: String,
}

/// An extension manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// [`FORMAT`].
    pub format: u32,
    /// Lowercase id, such as `com.example.reader` (`a-z0-9.-_`, 3 to 128 characters).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// The author's Weirdnet user id (32 hex characters).
    pub author: String,
    /// The author's public key (libp2p protobuf encoding, base64).
    pub author_key: String,
    /// The lowest host API version the extension needs.
    pub api_version: u32,
    /// Capabilities asked for.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Sites the extension works on.
    #[serde(default)]
    pub sites: Vec<String>,
    /// Native binaries per target.
    #[serde(default)]
    pub native: Vec<Native>,
    /// The WebAssembly component, if any (runs where native code can't).
    #[serde(default)]
    pub wasm: Option<String>,
    /// Every file in the package.
    pub files: Vec<FileEntry>,
}

/// The target this build runs on, as used in [`Native::target`].
pub fn current_target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// The Weirdnet user id of a public key: 32 hex characters of the SHA-256 of its protobuf
/// encoding (the same as `weirdnet_net::user::user_id`).
pub fn user_id(key: &PublicKey) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(key.encode_protobuf())[..16])
}

/// Checks a relative package path.
pub fn check_path(p: &str) -> Result<()> {
    let ok = !p.is_empty()
        && p.len() <= 512
        && !p.starts_with('/')
        && !p.contains('\\')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
        && !p.chars().any(|c| c.is_control());
    if ok { Ok(()) } else { Err(invalid(format!("bad path {p:?}"))) }
}

fn check_id(id: &str) -> Result<()> {
    let ok = (3..=128).contains(&id.len())
        && id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
        && !id.starts_with('.')
        && !id.contains("..");
    if ok { Ok(()) } else { Err(invalid(format!("bad extension id {id:?}"))) }
}

impl Manifest {
    /// The author's public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        let b = B64.decode(&self.author_key).map_err(|_| invalid("bad author key"))?;
        PublicKey::try_decode_protobuf(&b).map_err(|_| invalid("bad author key"))
    }

    /// The parsed version.
    pub fn semver(&self) -> Result<semver::Version> {
        semver::Version::parse(&self.version).map_err(|_| invalid(format!("bad version {:?}", self.version)))
    }

    /// The binary for `target`, if the package has one.
    pub fn native_for(&self, target: &str) -> Option<&Native> {
        self.native.iter().find(|n| n.target == target)
    }

    /// Checks the shape: format, id, version, author, paths, and that binaries are listed.
    pub fn check(&self) -> Result<()> {
        if self.format != FORMAT {
            return Err(invalid(format!("manifest format {} (this host reads {FORMAT})", self.format)));
        }
        check_id(&self.id)?;
        self.semver()?;
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err(invalid("bad name"));
        }
        let key = self.public_key()?;
        if user_id(&key) != self.author {
            return Err(Error::Verify("the author id is not the author key's".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for f in &self.files {
            check_path(&f.path)?;
            if f.path == "manifest.json" || f.path == "manifest.sig" {
                return Err(invalid("reserved file name"));
            }
            if !seen.insert(f.path.as_str()) {
                return Err(invalid(format!("{} is listed twice", f.path)));
            }
            if f.blake3.len() != 64 || !f.blake3.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(format!("bad hash for {}", f.path)));
            }
        }
        for n in &self.native {
            if !seen.contains(n.path.as_str()) {
                return Err(invalid(format!("binary {} is not in the files", n.path)));
            }
        }
        if let Some(w) = &self.wasm
            && !seen.contains(w.as_str())
        {
            return Err(invalid(format!("{w} is not in the files")));
        }
        for c in &self.capabilities {
            if c.name.is_empty()
                || c.name.len() > 64
                || !c.name.bytes().all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_' || b.is_ascii_digit())
            {
                return Err(invalid(format!("bad capability {:?}", c.name)));
            }
        }
        Ok(())
    }

    /// Fills in the author from `key`.
    pub fn set_author(&mut self, key: &PublicKey) {
        self.author = user_id(key);
        self.author_key = B64.encode(key.encode_protobuf());
    }
}

/// Signs manifest bytes with the author's user key.
pub fn sign(key: &Keypair, manifest_json: &[u8]) -> Result<Vec<u8>> {
    key.sign(&[MANIFEST_DOMAIN, manifest_json].concat()).map_err(|e| invalid(format!("signing: {e}")))
}

/// Verifies `sig` over `manifest_json`, parses and checks the manifest.
pub fn verify(manifest_json: &[u8], sig: &[u8]) -> Result<Manifest> {
    let m: Manifest = serde_json::from_slice(manifest_json).map_err(|e| invalid(format!("manifest.json: {e}")))?;
    let key = m.public_key()?;
    if !key.verify(&[MANIFEST_DOMAIN, manifest_json].concat(), sig) {
        return Err(Error::Verify("the manifest signature does not check out".into()));
    }
    m.check()?;
    Ok(m)
}
