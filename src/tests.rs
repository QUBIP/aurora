use super::*;

pub fn new_provctx_for_testing<'a>() -> ProviderInstance<'a> {
    let handle = std::ptr::null();
    let core_dispatch = CoreDispatch::new_mock_for_testing();

    return ProviderInstance::new(handle, core_dispatch);
}

pub(crate) mod common {
    pub(crate) use crate::Error as OurError;

    pub(crate) fn setup() -> Result<(), OurError> {
        crate::init::try_init_logging().expect("Failed to initialize the logging system");
        Ok(())
    }
}
