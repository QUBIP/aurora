use super::named;
use crate::forge::{self, bindings::*, keymgmt::selection::Selection};
use crate::ProviderInstance;

#[allow(dead_code)]
#[named]
pub(crate) unsafe extern "C" fn export_forbidden(
    _keydata: *mut c_void,
    _selection: c_int,
    _param_cb: OSSL_CALLBACK,
    _cbarg: *mut c_void,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS_RET: c_int = 1;

    trace!(target: log_target!(), "{}", "Called!");
    debug!(target: log_target!(), "Key export is not allowed");
    return ERROR_RET;
}

#[named]
pub(crate) unsafe extern "C" fn export_types_ex_forbidden(
    vprovctx: *mut c_void,
    selection: c_int,
) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &ProviderInstance<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    return export_types_forbidden(selection);
}

#[named]
pub(crate) unsafe extern "C" fn export_types_forbidden(selection: c_int) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Key export is not allowed");

    let _selection = crate::handleResult!(Selection::try_from(selection as u32));

    let ret = &forge::osslparams::EMPTY_PARAMS;
    let ret = std::ptr::from_ref(ret).cast();
    return ret;
}

#[cfg(test)]
mod tests {
    use crate::tests::common::setup;
    #[expect(unused_imports)]
    use crate::tests::common::OurError;

    #[test]
    fn test_compatibility() {
        let testctx = setup().expect("Failed to initialize test setup");
        //let provctx = testctx.provctx;
        let _ = testctx;

        use crate::forge::bindings::OSSL_FUNC_keymgmt_export_fn;
        use crate::forge::bindings::OSSL_FUNC_keymgmt_export_types_ex_fn;
        use crate::forge::bindings::OSSL_FUNC_keymgmt_export_types_fn;

        let _export: OSSL_FUNC_keymgmt_export_fn = Some(super::export_forbidden);
        let _export_types: OSSL_FUNC_keymgmt_export_types_fn = Some(super::export_types_forbidden);
        let _export_types_ex: OSSL_FUNC_keymgmt_export_types_ex_fn =
            Some(super::export_types_ex_forbidden);
    }
}
