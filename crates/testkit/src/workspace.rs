//! Per-run scratch Git repositories, worktrees, symlinks and submodules for the workspace
//! tests (M05; ADR-0011 §2.2–§2.3; m05-plan U4, U10). Owner: the M05 track.
//!
//! [`Scratch`] owns one temporary directory, created per run and removed on drop. Every
//! repository, clone, linked worktree, copy, move, symlink, submodule and FIFO a test
//! needs is made inside it, and every path it returns is **canonical** (on macOS the
//! temporary directory lives behind the `/var` → `/private/var` symlink, and the observer
//! records canonical roots).
//!
//! Git runs isolated from the account: a cleared environment (only `PATH` and the
//! platform's temporary-directory and system-root variables pass through), `HOME` and
//! `GIT_CONFIG_GLOBAL` inside the scratch directory, no system configuration, a fixed
//! identity, no hooks, no signing, and `protocol.file.allow=always` for the local
//! submodule. Nothing here reads the owner's Git configuration, keys or repositories.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One per-run scratch directory of workspaces (module docs).
#[derive(Debug)]
pub struct Scratch {
    /// Removed (recursively) when the `Scratch` is dropped.
    _dir: tempfile::TempDir,
    root: PathBuf,
}

fn other(msg: String) -> io::Error {
    io::Error::other(msg)
}

impl Scratch {
    /// A fresh scratch directory (with its isolated Git home).
    ///
    /// # Errors
    /// A filesystem error.
    pub fn new() -> io::Result<Self> {
        let dir = tempfile::Builder::new().prefix("hm-ws-").tempdir()?;
        let root = std::fs::canonicalize(dir.path())?;
        std::fs::create_dir_all(root.join(".home"))?;
        std::fs::write(root.join(".home").join("gitconfig"), b"")?;
        Ok(Self { _dir: dir, root })
    }

    /// The canonical scratch root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The isolated home Git runs with (also usable as a test's `HOME`).
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join(".home")
    }

    /// `root/<name>`, canonical once it exists.
    #[must_use]
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Run `git <args>` in `cwd`, isolated (module docs); its output is returned.
    ///
    /// # Errors
    /// The spawn failed, or Git exited unsuccessfully (its stderr in the message).
    pub fn git(&self, cwd: &Path, args: &[&str]) -> io::Result<String> {
        let home = self.home();
        let mut cmd = Command::new("git");
        cmd.env_clear();
        for key in [
            "PATH",
            "SYSTEMROOT",
            "SystemRoot",
            "TMPDIR",
            "TEMP",
            "TMP",
            "LANG",
        ] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
        cmd.env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", home.join("gitconfig"))
            .env("GIT_AUTHOR_NAME", "Heimdall Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Heimdall Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "protocol.file.allow=always",
                "-c",
                "init.defaultBranch=main",
                "-c",
                "core.autocrlf=false",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=.hm-no-hooks",
            ])
            .args(args)
            .current_dir(cwd);
        let out = cmd.output()?;
        if !out.status.success() {
            return Err(other(format!(
                "git {} failed ({:?}): {}",
                args.join(" "),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// A new repository `root/<name>` with one commit, holding `.heimdall.toml` with
    /// `manifest` when given (a manifest-less repository otherwise) and a `README`.
    ///
    /// # Errors
    /// A filesystem or Git error.
    pub fn init_repo(&self, name: &str, manifest: Option<&str>) -> io::Result<PathBuf> {
        let dir = self.path(name);
        std::fs::create_dir_all(&dir)?;
        let dir = std::fs::canonicalize(dir)?;
        self.git(&dir, &["init", "-q"])?;
        std::fs::write(dir.join("README"), b"fixture\n")?;
        if let Some(m) = manifest {
            write_manifest(&dir, m)?;
        }
        self.commit_all(&dir, "initial")?;
        Ok(dir)
    }

    /// `git add -A && git commit` in `repo`.
    ///
    /// # Errors
    /// A Git error.
    pub fn commit_all(&self, repo: &Path, message: &str) -> io::Result<()> {
        self.git(repo, &["add", "-A"])?;
        self.git(repo, &["commit", "-q", "--allow-empty", "-m", message])?;
        Ok(())
    }

    /// `git clone <src> root/<name>` (a new checkout: another root and identity).
    ///
    /// # Errors
    /// A Git error.
    pub fn clone_repo(&self, src: &Path, name: &str) -> io::Result<PathBuf> {
        let dest = self.path(name);
        let (src_s, dest_s) = (path_str(src)?, path_str(&dest)?);
        self.git(&self.root, &["clone", "-q", &src_s, &dest_s])?;
        std::fs::canonicalize(dest)
    }

    /// `git worktree add -b <branch> root/<name>` in `repo` (a verified linked worktree).
    ///
    /// # Errors
    /// A Git error.
    pub fn worktree_add(&self, repo: &Path, name: &str, branch: &str) -> io::Result<PathBuf> {
        let dest = self.path(name);
        let dest_s = path_str(&dest)?;
        self.git(repo, &["worktree", "add", "-q", "-b", branch, &dest_s])?;
        std::fs::canonicalize(dest)
    }

    /// A `cp -R`-style copy of `src` to `root/<name>`: directories and files copied,
    /// symbolic links re-created as links (never followed).
    ///
    /// # Errors
    /// A filesystem error.
    pub fn copy_tree(&self, src: &Path, name: &str) -> io::Result<PathBuf> {
        let dest = self.path(name);
        copy_dir(src, &dest)?;
        std::fs::canonicalize(dest)
    }

    /// A same-filesystem move of `src` to `root/<name>` (`rename`: the identity stays).
    ///
    /// # Errors
    /// A filesystem error.
    pub fn move_tree(&self, src: &Path, name: &str) -> io::Result<PathBuf> {
        let dest = self.path(name);
        std::fs::rename(src, &dest)?;
        std::fs::canonicalize(dest)
    }

    /// A directory symlink `root/<name>` → `target` (not canonicalized: the link itself).
    ///
    /// # Errors
    /// A filesystem error (on Windows, creating a symlink may need developer mode).
    pub fn symlink_dir(&self, target: &Path, name: &str) -> io::Result<PathBuf> {
        let link = self.path(name);
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &link)?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(target, &link)?;
        Ok(link)
    }

    /// `git submodule add <sub> <path>` in `repo`, committed; returns the submodule's
    /// checkout inside `repo`.
    ///
    /// # Errors
    /// A Git error.
    pub fn add_submodule(
        &self,
        repo: &Path,
        sub: &Path,
        path_in_repo: &str,
    ) -> io::Result<PathBuf> {
        let sub_s = path_str(sub)?;
        self.git(repo, &["submodule", "add", "-q", &sub_s, path_in_repo])?;
        self.commit_all(repo, "submodule")?;
        std::fs::canonicalize(repo.join(path_in_repo))
    }

    /// Re-create `repo` from scratch at the same path: delete it, then clone `src` there
    /// (a re-clone at the same path: same root, another identity).
    ///
    /// # Errors
    /// A filesystem or Git error.
    pub fn reclone_at(&self, src: &Path, repo: &Path) -> io::Result<PathBuf> {
        // Keep the old directory's inode alive while the clone is made, so the new
        // directory cannot reuse its inode number (birth times differ anyway where the
        // filesystem records them).
        let parked = self.path(&format!(
            ".parked-{}",
            repo.file_name().and_then(|n| n.to_str()).unwrap_or("repo")
        ));
        std::fs::rename(repo, &parked)?;
        let (src_s, dest_s) = (path_str(src)?, path_str(repo)?);
        self.git(&self.root, &["clone", "-q", &src_s, &dest_s])?;
        std::fs::canonicalize(repo)
    }
}

/// Write `.heimdall.toml` in `root` (replacing it).
///
/// # Errors
/// A filesystem error.
pub fn write_manifest(root: &Path, text: &str) -> io::Result<()> {
    std::fs::write(root.join(".heimdall.toml"), text.as_bytes())
}

/// A manifest asking for `profile`, the given `pairs` (`destination:account` tokens) and,
/// optionally, background work.
#[must_use]
pub fn manifest(label: &str, profile: &str, pairs: &[&str], background_work: bool) -> String {
    let pairs = pairs
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = format!(
        "schema_version = 1\nproject = \"{label}\"\n[access]\nprofile = \"{profile}\"\npairs = [{pairs}]\n"
    );
    if background_work {
        s.push_str("[preferences]\nbackground_work = true\n");
    }
    s
}

/// Create a FIFO at `path` (`mkfifo`).
///
/// # Errors
/// The command failed.
#[cfg(unix)]
pub fn make_fifo(path: &Path) -> io::Result<()> {
    let out = Command::new("mkfifo").arg(path).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(other(format!(
            "mkfifo failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn path_str(p: &Path) -> io::Result<String> {
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| other("a scratch path is not UTF-8".to_owned()))
}

fn copy_dir(src: &Path, dest: &Path) -> io::Result<()> {
    std::fs::create_dir(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        let t = entry.file_type()?;
        if t.is_symlink() {
            let target = std::fs::read_link(&from)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &to)?;
            #[cfg(windows)]
            {
                if std::fs::metadata(&from).is_ok_and(|m| m.is_dir()) {
                    std::os::windows::fs::symlink_dir(&target, &to)?;
                } else {
                    std::os::windows::fs::symlink_file(&target, &to)?;
                }
            }
        } else if t.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}
