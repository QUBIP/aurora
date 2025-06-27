pub type Error = anyhow::Error;
pub use self::Error as OurError;

#[cfg(feature = "env_logger")]
use env_logger as logger;

pub(crate) fn setup() -> Result<(), OurError> {
    try_init_logging().expect("Failed to initialize the logging system");

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    build::build_cdylib_before_tests(profile);
    env::set_openssl_modules_env_var(profile);
    Ok(())
}

#[cfg(feature = "env_logger")]
fn inner_try_init_logging() -> Result<(), OurError> {
    logger::Builder::from_default_env()
        //.filter_level(log::LevelFilter::Debug)
        .format_timestamp(None) // Optional: disable timestamps
        .format_module_path(false) // Optional: disable module path
        .format_target(true) // Optional: enable target
        .format_source_path(true)
        .is_test(cfg!(test))
        .try_init()
        .map_err(OurError::from)
}

fn try_init_logging() -> Result<(), OurError> {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        #[cfg(feature = "env_logger")]
        inner_try_init_logging().expect("Failed to initialize the logging system");
    });

    Ok(())
}

mod build {
    use std::process::Command;

    pub(super) fn build_cdylib_before_tests(profile: &str) {
        let profile_arg = match profile {
            "debug" => None,
            "release" => {
                log::error!("{profile:?} is intentionally not supported at the moment");
                unimplemented!();
                //Some(format!("--{profile:}"))
            }
            _ => {
                log::error!("Unknown profile: {profile:?}");
                panic!("Unknown profile: {profile:?}")
            }
        };

        let mut args = vec!["build".to_string()];
        if let Some(arg) = profile_arg {
            args.push(arg);
        }

        let status = Command::new("cargo")
            .args(&args)
            .status()
            .expect("Failed to build cdylib");

        assert!(status.success());
    }
}

mod env {
    use std::{path::PathBuf, str::FromStr};

    pub(super) fn cargo_metadata() -> serde_json::Result<serde_json::Value> {
        use std::process::Command;

        let output = Command::new("cargo")
            .args(["metadata", "--format-version", "1"])
            .output()
            .expect("Failure running `cargo metadata`");
        assert!(output.status.success());

        let stdout = output.stdout.as_slice();

        let v = serde_json::from_slice(stdout)?;

        serde_json::Result::Ok(v)
    }

    pub(super) fn cargo_target_directory() -> Option<PathBuf> {
        let m = cargo_metadata().expect("Failure running `cargo metadata`");
        let target_dir = m
            .get("target_directory")
            .expect("Missing key: \"target_directory\"");
        let target_dir = target_dir.as_str().expect("Invalid value");
        std::path::PathBuf::from_str(target_dir).ok()
    }

    pub(super) fn set_openssl_modules_env_var(profile: &str) {
        let target_dir = cargo_target_directory()
            .expect("Unable to determine target_directory")
            .join(profile);

        assert!(target_dir.exists(), "{target_dir:?} does not exist");
        let p = target_dir.as_os_str();
        let v = "OPENSSL_MODULES";
        std::env::set_var(v, p);
        log::info!(
            "Set {v:?} env variable to {:?}",
            std::env::var_os(v).unwrap()
        )
    }
}
