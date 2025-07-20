use super::*;

pub fn new_provctx_for_testing<'a>() -> OpenSSLProvider<'a> {
    let handle = std::ptr::null();
    let core_dispatch =
        CoreDispatch::try_from(core::ptr::null()).expect("Could not create a test CoreDispatch");

    return OpenSSLProvider::new(handle, core_dispatch);
}

pub(crate) mod common {
    pub(crate) use crate::Error as OurError;

    pub(crate) fn setup() -> Result<(), OurError> {
        crate::init::try_init_logging().expect("Failed to initialize the logging system");
        Ok(())
    }
}
