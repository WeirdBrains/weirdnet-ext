//! Packages: a tar archive with `manifest.json`, `manifest.sig` and the files under `files/`.
//!
//! [`build`] makes one from a directory and the author's key. [`Package::open`] checks it:
//! the signature, the author id, every listed file present with its size and BLAKE3 hash, no
//! unlisted files, regular files only and safe paths. The [`Installer`] keeps extensions in a
//! per-user directory, one read-only directory per version, pins each extension id to its
//! first author, refuses updates by another author or that are not newer, says which
//! capabilities an update adds, and checks every hash again before a launch.

use crate::error::{Error, Result, invalid};
use crate::manifest::{self, Capability, FileEntry, Manifest};
use libp2p_identity::Keypair;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Size limits when opening a package.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest package (sum of file sizes).
    pub total: u64,
    /// Most files.
    pub files: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { total: 512 << 20, files: 10_000 }
    }
}

/// Builds a package from the files under `dir`: fills in `files` (sizes and hashes) and the
/// author, signs, and returns the archive bytes.
pub fn build(dir: &Path, mut m: Manifest, key: &Keypair) -> Result<Vec<u8>> {
    let mut files = BTreeMap::new();
    collect(dir, dir, &mut files)?;
    m.files = files.iter().map(|(p, b)| FileEntry { path: p.clone(), size: b.len() as u64, blake3: blake3::hash(b).to_hex().to_string() }).collect();
    m.set_author(&key.public());
    m.check()?;
    let json = serde_json::to_vec_pretty(&m).map_err(|e| invalid(e.to_string()))?;
    let sig = manifest::sign(key, &json)?;
    let mut t = tar::Builder::new(Vec::new());
    let mut add = |name: &str, data: &[u8], mode: u32| -> Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        t.append_data(&mut h, name, data)?;
        Ok(())
    };
    add("manifest.json", &json, 0o644)?;
    add("manifest.sig", hex::encode(&sig).as_bytes(), 0o644)?;
    for (p, b) in &files {
        add(&format!("files/{p}"), b, 0o644)?;
    }
    Ok(t.into_inner()?)
}

fn collect(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let t = e.file_type()?;
        let p = e.path();
        if t.is_dir() {
            collect(root, &p, out)?;
        } else if t.is_file() {
            let rel = p.strip_prefix(root).unwrap().components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/");
            manifest::check_path(&rel)?;
            out.insert(rel, std::fs::read(&p)?);
        } else {
            return Err(invalid(format!("{} is not a regular file", p.display())));
        }
    }
    Ok(())
}

/// A verified package in memory.
#[derive(Debug, Clone)]
pub struct Package {
    /// The manifest.
    pub manifest: Manifest,
    manifest_json: Vec<u8>,
    sig: Vec<u8>,
    files: HashMap<String, Vec<u8>>,
}

impl Package {
    /// Reads and verifies a package with the default [`Limits`].
    pub fn open(bytes: &[u8]) -> Result<Self> {
        Self::open_with(bytes, Limits::default())
    }

    /// Reads and verifies a package.
    pub fn open_with(bytes: &[u8], limits: Limits) -> Result<Self> {
        let mut a = tar::Archive::new(bytes);
        let (mut mj, mut sig, mut files) = (None, None, HashMap::new());
        let mut total = 0u64;
        for e in a.entries()? {
            let mut e = e?;
            if e.header().entry_type() != tar::EntryType::Regular {
                return Err(invalid("only regular files are allowed in a package"));
            }
            let name = e.path()?.to_string_lossy().into_owned();
            let size = e.header().size()?;
            total = total.saturating_add(size);
            if total > limits.total || files.len() >= limits.files {
                return Err(invalid("the package is too large"));
            }
            let mut b = Vec::with_capacity(size as usize);
            e.read_to_end(&mut b)?;
            match name.as_str() {
                "manifest.json" if mj.is_none() => mj = Some(b),
                "manifest.sig" if sig.is_none() => sig = Some(b),
                n => {
                    let p = n.strip_prefix("files/").ok_or_else(|| invalid(format!("unexpected entry {n:?}")))?;
                    manifest::check_path(p)?;
                    if files.insert(p.to_string(), b).is_some() {
                        return Err(invalid(format!("{p} appears twice")));
                    }
                }
            }
        }
        let mj = mj.ok_or_else(|| invalid("no manifest.json"))?;
        let sig = hex::decode(sig.ok_or_else(|| invalid("no manifest.sig"))?.trim_ascii()).map_err(|_| invalid("bad manifest.sig"))?;
        let m = manifest::verify(&mj, &sig)?;
        check_files(&m, |p| files.get(p).cloned())?;
        if files.len() != m.files.len() {
            return Err(Error::Verify("the package has files its manifest does not list".into()));
        }
        Ok(Self { manifest: m, manifest_json: mj, sig, files })
    }

    /// A file's bytes.
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }
}

fn check_files(m: &Manifest, mut get: impl FnMut(&str) -> Option<Vec<u8>>) -> Result<()> {
    for f in &m.files {
        let b = get(&f.path).ok_or_else(|| Error::Verify(format!("{} is missing", f.path)))?;
        if b.len() as u64 != f.size || blake3::hash(&b).to_hex().as_str() != f.blake3 {
            return Err(Error::Verify(format!("{} does not match its hash", f.path)));
        }
    }
    Ok(())
}

/// What installing a package would do; from [`Installer::inspect`].
#[derive(Debug, Clone)]
pub struct Plan {
    /// The verified package.
    pub package: Package,
    /// The installed manifest it replaces, if any.
    pub previous: Option<Manifest>,
    /// Capabilities not in the previous version (all of them for a first install). Ask the
    /// user about these.
    pub new_capabilities: Vec<Capability>,
    /// True if a native binary will run on this target; false means WASM only.
    pub native_runs: bool,
    /// True if the extension can run here at all (a native binary or WASM).
    pub runs_here: bool,
}

/// An installed, verified extension.
#[derive(Debug, Clone)]
pub struct Installed {
    /// Its manifest.
    pub manifest: Manifest,
    /// Its read-only directory (the files are under `files/`).
    pub dir: PathBuf,
}

impl Installed {
    /// The native binary for this target, if any.
    pub fn native(&self) -> Option<PathBuf> {
        self.manifest.native_for(&manifest::current_target()).map(|n| self.dir.join("files").join(&n.path))
    }

    /// The WASM component, if any.
    pub fn wasm(&self) -> Option<PathBuf> {
        self.manifest.wasm.as_ref().map(|w| self.dir.join("files").join(w))
    }
}

/// Installs extensions under a per-user directory: `ROOT/<id>/<version>/`, `ROOT/pins.json`
/// (extension id to author user id) and `ROOT/<id>/current` (the active version).
#[derive(Debug, Clone)]
pub struct Installer {
    root: PathBuf,
}

fn set_mode(p: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let mut perm = std::fs::metadata(p)?.permissions();
        perm.set_readonly(mode & 0o200 == 0);
        std::fs::set_permissions(p, perm)?;
    }
    Ok(())
}

impl Installer {
    /// An installer rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn pins(&self) -> Result<BTreeMap<String, String>> {
        match std::fs::read(self.root.join("pins.json")) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| invalid(format!("pins.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// The author an id is pinned to.
    pub fn pinned(&self, id: &str) -> Result<Option<String>> {
        Ok(self.pins()?.get(id).cloned())
    }

    /// The active version of `id`, if installed.
    pub fn current(&self, id: &str) -> Result<Option<String>> {
        match std::fs::read_to_string(self.root.join(id).join("current")) {
            Ok(v) => Ok(Some(v.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Verifies `bytes` and compares it with what is installed. Fails if the id is pinned to
    /// another author or the version is not newer.
    pub fn inspect(&self, bytes: &[u8]) -> Result<Plan> {
        let package = Package::open(bytes)?;
        let m = &package.manifest;
        if let Some(pinned) = self.pinned(&m.id)?
            && pinned != m.author
        {
            return Err(Error::AuthorChanged { id: m.id.clone(), pinned, got: m.author.clone() });
        }
        let previous = match self.current(&m.id)? {
            Some(_) => Some(self.verify(&m.id)?.manifest),
            None => None,
        };
        if let Some(p) = &previous
            && m.semver()? <= p.semver()?
        {
            return Err(Error::NotNewer { id: m.id.clone(), have: p.version.clone(), got: m.version.clone() });
        }
        let new_capabilities = m.capabilities.iter().filter(|c| previous.as_ref().is_none_or(|p| !p.capabilities.contains(c))).cloned().collect();
        let native_runs = m.native_for(&manifest::current_target()).is_some() && crate::sandbox::native_allowed();
        let runs_here = native_runs || m.wasm.is_some();
        Ok(Plan { package, previous, new_capabilities, native_runs, runs_here })
    }

    /// Installs a plan (after the user agreed to its capabilities) and makes it current.
    pub fn install(&self, plan: Plan) -> Result<Installed> {
        let m = plan.package.manifest.clone();
        if let Some(pinned) = self.pinned(&m.id)?
            && pinned != m.author
        {
            return Err(Error::AuthorChanged { id: m.id.clone(), pinned, got: m.author.clone() });
        }
        let base = self.root.join(&m.id);
        std::fs::create_dir_all(&base)?;
        let dir = base.join(&m.version);
        let tmp = base.join(format!(".{}.tmp", m.version));
        if tmp.exists() {
            make_writable(&tmp)?;
            std::fs::remove_dir_all(&tmp)?;
        }
        std::fs::create_dir_all(tmp.join("files"))?;
        std::fs::write(tmp.join("manifest.json"), &plan.package.manifest_json)?;
        std::fs::write(tmp.join("manifest.sig"), hex::encode(&plan.package.sig))?;
        let bins: Vec<&str> = m.native.iter().map(|n| n.path.as_str()).collect();
        for f in &m.files {
            let p = tmp.join("files").join(&f.path);
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d)?;
            }
            std::fs::write(&p, plan.package.file(&f.path).unwrap())?;
            set_mode(&p, if bins.contains(&f.path.as_str()) { 0o555 } else { 0o444 })?;
        }
        read_only_dirs(&tmp)?;
        if dir.exists() {
            make_writable(&dir)?;
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::rename(&tmp, &dir)?;
        crate::store::write_atomic(&base.join("current"), m.version.as_bytes())?;
        let mut pins = self.pins()?;
        pins.entry(m.id.clone()).or_insert(m.author.clone());
        crate::store::write_atomic(&self.root.join("pins.json"), &serde_json::to_vec_pretty(&pins).unwrap())?;
        Ok(Installed { manifest: m, dir })
    }

    /// Checks the active version of `id` again (signature, author pin, every hash); do this
    /// before every launch.
    pub fn verify(&self, id: &str) -> Result<Installed> {
        let v = self.current(id)?.ok_or_else(|| invalid(format!("{id} is not installed")))?;
        let dir = self.root.join(id).join(&v);
        let mj = std::fs::read(dir.join("manifest.json"))?;
        let sig = hex::decode(std::fs::read_to_string(dir.join("manifest.sig"))?.trim()).map_err(|_| invalid("bad manifest.sig"))?;
        let m = manifest::verify(&mj, &sig)?;
        if m.id != id || m.version != v {
            return Err(Error::Verify("the installed manifest is for something else".into()));
        }
        if let Some(pinned) = self.pinned(id)?
            && pinned != m.author
        {
            return Err(Error::AuthorChanged { id: id.into(), pinned, got: m.author });
        }
        check_files(&m, |p| std::fs::read(dir.join("files").join(p)).ok())?;
        Ok(Installed { manifest: m, dir })
    }

    /// Removes every version of `id` (the author pin stays, so a reinstall needs the same key).
    pub fn uninstall(&self, id: &str) -> Result<()> {
        let base = self.root.join(id);
        if base.exists() {
            make_writable(&base)?;
            std::fs::remove_dir_all(&base)?;
        }
        Ok(())
    }
}

fn read_only_dirs(dir: &Path) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            read_only_dirs(&e.path())?;
        } else {
            set_mode(&e.path(), if is_exec(&e.path()) { 0o555 } else { 0o444 })?;
        }
    }
    set_mode(dir, 0o555)
}

fn is_exec(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        false
    }
}

fn make_writable(dir: &Path) -> Result<()> {
    set_mode(dir, 0o755)?;
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            make_writable(&e.path())?;
        } else {
            set_mode(&e.path(), 0o644)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: &str, version: &str, caps: &[&str]) -> Manifest {
        Manifest {
            format: manifest::FORMAT,
            id: id.into(),
            name: "Reader".into(),
            version: version.into(),
            author: String::new(),
            author_key: String::new(),
            api_version: 1,
            capabilities: caps.iter().map(|c| Capability::new(*c)).collect(),
            sites: vec!["https://*.example.com/*".into()],
            native: vec![manifest::Native { target: manifest::current_target(), path: "bin/ext".into() }],
            wasm: Some("ext.wasm".into()),
            files: vec![],
        }
    }

    fn src(d: &Path) -> PathBuf {
        let s = d.join("src");
        std::fs::create_dir_all(s.join("bin")).unwrap();
        std::fs::write(s.join("bin/ext"), b"#!/bin/sh\n").unwrap();
        std::fs::write(s.join("ext.wasm"), b"\0asm").unwrap();
        std::fs::write(s.join("README"), b"hello").unwrap();
        s
    }

    #[test]
    fn build_open_and_reject_tampering() {
        let d = tempfile::tempdir().unwrap();
        let key = Keypair::generate_ed25519();
        let bytes = build(&src(d.path()), manifest("com.example.reader", "1.0.0", &["page.read"]), &key).unwrap();
        let p = Package::open(&bytes).unwrap();
        assert_eq!(p.manifest.files.len(), 3);
        assert_eq!(p.manifest.author, manifest::user_id(&key.public()));
        assert_eq!(p.file("README"), Some(&b"hello"[..]));
        // Change a byte of a file: its hash fails.
        let i = bytes.windows(5).position(|w| w == b"hello").unwrap();
        let mut bad = bytes.clone();
        bad[i] = b'j';
        assert!(matches!(Package::open(&bad), Err(Error::Verify(_))));
        // Change the manifest: the signature fails.
        let i = bytes.windows(6).position(|w| w == b"Reader").unwrap();
        let mut bad = bytes.clone();
        bad[i] = b'X';
        assert!(matches!(Package::open(&bad), Err(Error::Verify(_))));
        // Over the limits.
        assert!(Package::open_with(&bytes, Limits { total: 4, files: 10 }).is_err());
    }

    #[test]
    fn manifests_are_checked() {
        let key = Keypair::generate_ed25519();
        let mut m = manifest("com.example.reader", "1.0.0", &[]);
        m.set_author(&key.public());
        m.native.clear();
        m.wasm = None;
        m.check().unwrap();
        for bad in ["Com.Example", "ab", "../x", ".x"] {
            let mut x = m.clone();
            x.id = bad.into();
            assert!(x.check().is_err(), "{bad}");
        }
        let mut x = m.clone();
        x.version = "1".into();
        assert!(x.check().is_err());
        let mut x = m.clone();
        x.author = "0".repeat(32);
        assert!(matches!(x.check(), Err(Error::Verify(_))));
        let mut x = m.clone();
        x.wasm = Some("missing.wasm".into());
        assert!(x.check().is_err());
        for bad in ["/a", "a/../b", "a\\b", "", "a//b"] {
            assert!(manifest::check_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn install_update_pin_and_verify() {
        let d = tempfile::tempdir().unwrap();
        let s = src(d.path());
        let key = Keypair::generate_ed25519();
        let inst = Installer::new(d.path().join("ext"));
        let v1 = build(&s, manifest("com.example.reader", "1.0.0", &["page.read"]), &key).unwrap();
        let plan = inst.inspect(&v1).unwrap();
        assert!(plan.previous.is_none() && plan.runs_here);
        assert_eq!(plan.new_capabilities, vec![Capability::new("page.read")]);
        let i = inst.install(plan).unwrap();
        assert_eq!(inst.current("com.example.reader").unwrap().as_deref(), Some("1.0.0"));
        assert!(i.native().unwrap().ends_with("files/bin/ext"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&i.dir.join("files/README")), 0o444);
            assert_eq!(mode(&i.dir.join("files/bin/ext")), 0o555);
            assert_eq!(mode(&i.dir), 0o555);
        }
        inst.verify("com.example.reader").unwrap();

        // The same or an older version is refused; a newer one lists only the added capability.
        assert!(matches!(inst.inspect(&v1), Err(Error::NotNewer { .. })));
        let v2 = build(&s, manifest("com.example.reader", "1.1.0", &["page.read", "net.fetch"]), &key).unwrap();
        let plan = inst.inspect(&v2).unwrap();
        assert_eq!(plan.new_capabilities, vec![Capability::new("net.fetch")]);
        inst.install(plan).unwrap();
        assert_eq!(inst.verify("com.example.reader").unwrap().manifest.version, "1.1.0");

        // Another author can't take the id over, even after an uninstall.
        let other = Keypair::generate_ed25519();
        let v3 = build(&s, manifest("com.example.reader", "2.0.0", &[]), &other).unwrap();
        assert!(matches!(inst.inspect(&v3), Err(Error::AuthorChanged { .. })));
        inst.uninstall("com.example.reader").unwrap();
        assert!(matches!(inst.inspect(&v3), Err(Error::AuthorChanged { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn a_changed_installed_file_fails_the_launch_check() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let key = Keypair::generate_ed25519();
        let inst = Installer::new(d.path().join("ext"));
        let i = inst.install(inst.inspect(&build(&src(d.path()), manifest("com.example.reader", "1.0.0", &[]), &key).unwrap()).unwrap()).unwrap();
        let f = i.dir.join("files/README");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&f, b"evil!").unwrap();
        assert!(matches!(inst.verify("com.example.reader"), Err(Error::Verify(_))));
    }
}
