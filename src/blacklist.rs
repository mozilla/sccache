use crate::config;
use crate::compiler::rust::RustCompilationBlacklist;
use crate::errors::*;


use std::sync::Arc;

/// a blacklist implementation
#[derive(Clone)]
pub struct Blacklist {
    pub rust : Arc<RustCompilationBlacklist>,
    // cxx :
}


impl Blacklist {
    /// initialize
    pub fn from_config(cfg: &config::BlacklistConfig) -> Self {
        let mut rust = RustCompilationBlacklist::new();

        if let Some(cfg) =  &cfg.rust {
            trace!(
                "blacklist(rust)> load from config: files: {}, crates: {}, build_script: {:?}",
                cfg.files.len(),
                cfg.crates.len(),
                cfg.build_script,
            );

            cfg.files.iter().for_each(|file| {
                rust.enlist_file(file);
            });

            cfg.crates.iter().for_each(|crate_name| {
                rust.enlist_crate(crate_name);
            });

            cfg.crate_dependencies.iter().for_each(|crate_name| {
                rust.enlist_crate_dependency(crate_name);
            });

            if cfg.build_script {
                rust.enlist_build_script();
            }
        }

        Self {
            rust : Arc::new(rust),
        }
    }

    /// load possibly more up date information from the context
    pub fn refresh_context(&mut self, cwd : &std::path::Path) -> Result<()> {
        trace!("blacklist> refresh blacklist context {}", cwd.display());
        self.rust.as_ref().refresh_context(cwd)?;
        Ok(())
    }

    /// obtain the rust specific blacklist
    pub fn get_rust_blacklist(&self) -> Arc<RustCompilationBlacklist> {
        self.rust.clone()
    }

    pub fn new() -> Self {
        Self {
            rust : Arc::new(RustCompilationBlacklist::default())
        }
    }
}

/// Result of a check operation, if the compilation is blacklisted
#[derive(Debug,Clone,PartialEq,Eq)]
pub enum BlacklistCheckResult {
    Blacklisted(String),
    Passed,
}

impl BlacklistCheckResult {
    /// Short cut for an if let to determine if the variant is `Blacklisted(_)`
    pub fn is_blacklisted(&self) -> bool {
        if let Self::Blacklisted(_) = self {
            true
        } else {
            false
        }
    }
}
