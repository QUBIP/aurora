pub type Error = anyhow::Error;
pub use self::Error as OurError;

#[cfg(feature = "env_logger")]
use env_logger as logger;

pub(crate) fn setup() -> Result<(), OurError> {
    try_init_logging().expect("Failed to initialize the logging system");
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
