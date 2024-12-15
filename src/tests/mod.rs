use super::*;

pub fn new_provctx_for_testing<'a>() -> OpenSSLProvider<'a> {
    let handle = std::ptr::null();
    let core_dispatch = std::ptr::null();

    return OpenSSLProvider::new(handle, core_dispatch);
}
