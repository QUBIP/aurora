#[macro_use]
extern crate log;

use ::function_name::named;

macro_rules! function_path {
    () => {
        concat!(module_path!(), "::", function_name!(), "()")
    };
}

macro_rules! log_target {
    () => {
        function_path!()
    };
}

mod bindings;
mod init;

use crate::bindings::dispatch_table_entry;
use crate::init::OSSL_CORE_HANDLE;
use bindings::{OSSL_DISPATCH, OSSL_FUNC_PROVIDER_TEARDOWN};

/// This is an abstract representation of one Provider instance.
/// Remember that a single provider module could be loaded multiple
/// times within the same process, either in the same OpenSSL libctx or
/// within different libctx's.
///
/// At the moment a single instance holds nothing of relevance, but in
/// the future all the context which is specific to an instance should
/// be encapsulated within it, so that different instances could have
/// different configurations, and their own separate state.
#[derive(Debug)]
pub struct OpenSSLProvider<'a> {
    pub data: [u8; 10],
    _handle: *const OSSL_CORE_HANDLE,
    _core_dispatch: *const OSSL_DISPATCH,
    pub name: &'a str,
}

/// We implement the Drop trait to make it explicit when a provider
/// instance is dropped: this should only happen after `teardown()` has
/// been called.
impl<'a> Drop for OpenSSLProvider<'a> {
    #[named]
    fn drop(&mut self) {
        let tname = std::any::type_name_of_val(self);
        let name = self.name;
        trace!(
            target: log_target!(),
            "🗑️\tDropping {tname} named {name}",
        )
    }
}

impl<'a> OpenSSLProvider<'a> {
    pub const NAME: &'a str = env!("CARGO_PKG_NAME");
    pub const VERSION: &'a str = env!("CARGO_PKG_VERSION");

    pub fn new(handle: *const OSSL_CORE_HANDLE, core_dispatch: *const OSSL_DISPATCH) -> Self {
        Self {
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            _handle: handle,
            _core_dispatch: core_dispatch,
            name: Self::NAME,
        }
    }

    /// Retrieve a heap allocated `OSSL_DISPATCH` table associated with this provider instance.
    pub fn get_provider_dispatch(&mut self) -> *const OSSL_DISPATCH {
        let ret = Box::new([
            dispatch_table_entry!(OSSL_FUNC_PROVIDER_TEARDOWN, crate::init::provider_teardown),
            OSSL_DISPATCH::END,
        ]);
        Box::into_raw(ret).cast()
    }
}
