use super::*;
use anyhow::anyhow;
use bindings::ffi_c_types::{c_char, c_int, c_void, CStr};
use bindings::{
    OSSL_CORE_BIO, OSSL_DISPATCH, OSSL_FUNC_BIO_READ_EX, OSSL_FUNC_BIO_WRITE_EX,
    OSSL_FUNC_CORE_OBJ_ADD_SIGID, OSSL_FUNC_CORE_OBJ_CREATE,
};
#[cfg(not(test))]
use std::collections::HashMap;

