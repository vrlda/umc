//! External-plugin OS confinement policy. Process isolation remains mandatory;
//! this module adds platform confinement without hiding reduced assurance.
#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    Disabled,
    BestEffort,
    Strict,
}

impl SandboxMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::BestEffort => "best-effort",
            Self::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxIsolation {
    Disabled,
    Enforced,
    Reduced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub isolation: SandboxIsolation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    UnsupportedPlatform,
    LauncherUnavailable,
    InvalidCommand,
}

impl SandboxPlan {
    pub fn prepare(
        command: PathBuf,
        args: Vec<String>,
        private_root: &Path,
        mode: SandboxMode,
    ) -> Result<Self, SandboxError> {
        if command.as_os_str().is_empty() {
            return Err(SandboxError::InvalidCommand);
        }
        match mode {
            SandboxMode::Disabled => Ok(Self {
                program: command,
                args,
                isolation: SandboxIsolation::Disabled,
            }),
            SandboxMode::BestEffort => Self::platform_plan(command, args, private_root, false),
            SandboxMode::Strict => Self::platform_plan(command, args, private_root, true),
        }
    }

    fn platform_plan(
        command: PathBuf,
        args: Vec<String>,
        private_root: &Path,
        strict: bool,
    ) -> Result<Self, SandboxError> {
        // The platform-specific launchers below are unavailable on other
        // targets, but the path is still part of the cross-platform API.
        // Mark it as consumed so those targets remain warning-free under
        // `-D warnings`.
        let _ = private_root;
        #[cfg(target_os = "macos")]
        {
            if let Some(launcher) = find_program("sandbox-exec") {
                let profile = mac_profile(private_root, &command);
                let mut wrapped =
                    vec!["-p".into(), profile, command.to_string_lossy().into_owned()];
                wrapped.extend(args);
                return Ok(Self {
                    program: launcher,
                    args: wrapped,
                    isolation: SandboxIsolation::Enforced,
                });
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(launcher) = find_program("bwrap") {
                let mut wrapped = vec![
                    "--die-with-parent".into(),
                    "--new-session".into(),
                    "--unshare-pid".into(),
                    "--unshare-uts".into(),
                    "--unshare-ipc".into(),
                    "--share-net".into(),
                    "--ro-bind".into(),
                    "/".into(),
                    "/".into(),
                    "--bind".into(),
                    private_root.to_string_lossy().into_owned(),
                    private_root.to_string_lossy().into_owned(),
                    "--proc".into(),
                    "/proc".into(),
                    "--dev".into(),
                    "/dev".into(),
                    "--".into(),
                    command.to_string_lossy().into_owned(),
                ];
                wrapped.extend(args);
                return Ok(Self {
                    program: launcher,
                    args: wrapped,
                    isolation: SandboxIsolation::Enforced,
                });
            }
        }

        if strict {
            Err(if platform_supported() {
                SandboxError::LauncherUnavailable
            } else {
                SandboxError::UnsupportedPlatform
            })
        } else {
            Ok(Self {
                program: command,
                args,
                isolation: SandboxIsolation::Reduced,
            })
        }
    }
}

#[must_use]
pub fn platform_enforcer_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        find_program("sandbox-exec").is_some()
    }
    #[cfg(target_os = "linux")]
    {
        find_program("bwrap").is_some()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn platform_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux"))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_program(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(Path::new)
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

#[cfg(target_os = "macos")]
fn mac_profile(private_root: &Path, command: &Path) -> String {
    let root = private_root
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let executable = command
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!(
        "(version 1) (deny default) (allow process*) (allow network*) (allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/Library\")) (allow file-read* (literal \"{executable}\")) (allow file-read* (subpath \"{root}\")) (allow file-write* (subpath \"{root}\"))"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy_requires_platform_enforcer() {
        let result = SandboxPlan::prepare(
            PathBuf::from("plugin"),
            Vec::new(),
            Path::new("/tmp/umc-plugin"),
            SandboxMode::Strict,
        );
        if platform_enforcer_available() {
            assert!(matches!(
                result,
                Ok(SandboxPlan {
                    isolation: SandboxIsolation::Enforced,
                    ..
                })
            ));
        } else {
            assert!(matches!(
                result,
                Err(SandboxError::LauncherUnavailable | SandboxError::UnsupportedPlatform)
            ));
        }
    }

    #[test]
    fn disabled_policy_preserves_direct_command() {
        let plan = SandboxPlan::prepare(
            PathBuf::from("plugin"),
            vec!["arg".into()],
            Path::new("/tmp/umc-plugin"),
            SandboxMode::Disabled,
        )
        .expect("disabled policy");
        assert_eq!(plan.program, PathBuf::from("plugin"));
        assert_eq!(plan.args, vec!["arg"]);
        assert_eq!(plan.isolation, SandboxIsolation::Disabled);
    }

    #[test]
    fn best_effort_never_fails_when_launcher_missing() {
        let plan = SandboxPlan::prepare(
            PathBuf::from("plugin"),
            Vec::new(),
            Path::new("/tmp/umc-plugin"),
            SandboxMode::BestEffort,
        )
        .expect("best effort");
        assert!(matches!(
            plan.isolation,
            SandboxIsolation::Enforced | SandboxIsolation::Reduced
        ));
    }
}
