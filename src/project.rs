//! Wrap a nix file and manage corresponding state.

use thiserror::Error;

use crate::builder::{OutputPath, RootedPath};
use crate::cas::ContentAddressable;
use crate::nix::StorePath;
use crate::{AbsPathBuf, NixFile};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A “project” knows how to handle the lorri state
/// for a given nix file.
#[derive(Clone)]
pub struct Project {
    /// Absolute path to this project’s nix file.
    pub nix_file: NixFile,

    /// Directory in which this project’s
    /// garbage collection roots are stored.
    gc_root_path: AbsPathBuf,

    /// Hash of the nix file’s absolute path.
    hash: String,

    /// Content-addressable store to save static files in
    pub cas: ContentAddressable,
}

impl Project {
    /// The name for the build output that's sourced in direnv to produce environment variables
    pub const ENV_CONTEXT: &'static str = "shell_gc_root";
    /// Construct a `Project` from nix file path
    /// and the base GC root directory
    /// (as returned by `Paths.gc_root_dir()`),
    pub fn new(
        nix_file: NixFile,
        gc_root_dir: &AbsPathBuf,
        cas: ContentAddressable,
    ) -> std::io::Result<Project> {
        let hash = format!(
            "{:x}",
            md5::compute(nix_file.as_absolute_path().as_os_str().as_bytes())
        );
        let project_gc_root = gc_root_dir.join(&hash).join("gc_root");

        std::fs::create_dir_all(&project_gc_root)?;

        let nix_file_symlink = project_gc_root.clone().join("nix_file");
        let (remove, create) = match std::fs::read_link(&nix_file_symlink) {
            Ok(path) => {
                if path == nix_file.as_absolute_path() {
                    (false, false)
                } else {
                    (true, true)
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    (false, true)
                } else {
                    (true, true)
                }
            }
        };
        if remove {
            std::fs::remove_file(&nix_file_symlink)?;
        }
        if create {
            std::os::unix::fs::symlink(nix_file.as_absolute_path(), nix_file_symlink)?;
        }

        Ok(Project {
            nix_file,
            gc_root_path: project_gc_root,
            hash,
            cas,
        })
    }

    /// Generate a "unique" ID for this project based on its absolute path.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    // final path in the `self.gc_root_path` directory,
    // the symlink which points to the lorri-keep-env-hack-nix-shell drv (see ./logged-evaluation.nix)
    fn gc_root(&self, base: &PathBuf) -> AbsPathBuf {
        self.gc_root_path.join(base)
    }

    /// Return the filesystem paths for these roots.
    pub fn root_paths(&self) -> OutputPath<RootPath> {
        OutputPath {
            shell_gc_root: RootPath(self.gc_root(&Self::ENV_CONTEXT.into())),
        }
    }

    /// Create roots to store paths.
    pub fn create_roots(
        &self,
        rooted_path: RootedPath,
    ) -> Result<OutputPath<RootPath>, AddRootError> {
        self.create_root(Self::ENV_CONTEXT.into(), rooted_path.path)
    }

    fn create_root(
        &self,
        base_name: PathBuf,
        store_path: StorePath,
    ) -> Result<OutputPath<RootPath>, AddRootError> {
        // nix-store --add-root /tmp/test-root --realise
        let mut cmd = Command::new("nix-store");
        cmd.args([
            OsStr::new("--realise"),
            OsStr::new("--add-root"),
            self.gc_root(&base_name).as_path().as_os_str(),
            store_path.as_path().as_os_str(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

        if !cmd
            .status()
            .map_err(|e| AddRootError::nix_run_error(e, store_path.as_path()))?
            .success()
        {
            return Err(AddRootError::nix_failed(store_path.as_path()));
        }

        Ok(OutputPath {
            shell_gc_root: RootPath(self.gc_root(&base_name)),
        })
    }
}

/// A path to a gc root.
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct RootPath(pub AbsPathBuf);

impl RootPath {
    /// `display` the path.
    pub fn display(&self) -> std::path::Display {
        self.0.display()
    }
}

impl OutputPath<RootPath> {
    /// Check whether all all GC roots exist.
    pub fn all_exist(&self) -> bool {
        let crate::builder::OutputPath { shell_gc_root } = self;

        shell_gc_root.0.as_path().exists()
    }
}

/// Error conditions encountered when adding roots
#[derive(Error, Debug)]
#[error("{msg}: {source}")]
pub struct AddRootError {
    #[source]
    source: std::io::Error,
    msg: String,
}

impl AddRootError {
    fn nix_run_error(source: std::io::Error, path: &Path) -> AddRootError {
        AddRootError {
            source,
            msg: format!("error running nix command for {}", path.display()),
        }
    }

    fn nix_failed(path: &Path) -> AddRootError {
        AddRootError {
            source: std::io::Error::new(std::io::ErrorKind::Other, "nix failed"),
            msg: format!("nix build returned non-zero status for {}", path.display()),
        }
    }
}
