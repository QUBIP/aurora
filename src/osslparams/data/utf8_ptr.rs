use std::ffi::{c_char, CStr};

use crate::bindings::{ossl_param_st, OSSL_PARAM_UTF8_PTR};
use crate::osslparams::{impl_setter, new_null_param, setter_type_err_string, KeyType, OSSLParam, OSSLParamData, OSSLParamError, OSSLParamGetter, TypedOSSLParamData, Utf8PtrData};

impl OSSLParamData for Utf8PtrData {
    fn new_null(key: &KeyType) -> Self where Self: Sized {
        new_null_param!(Utf8PtrData, OSSL_PARAM_UTF8_PTR, key)
    }
}

impl_setter!(*const CStr, Utf8Ptr);
impl_setter!(&'static CStr, Utf8Ptr);

// and we can get the value of a UTF-8 pointer param value as &CStr
impl<'a> OSSLParamGetter<&'a CStr> for OSSLParam {
    fn get_inner(&self) -> Option<&'a CStr> {
        if let OSSLParam::Utf8Ptr(d) = self {
            unsafe {
                let ptr = (*d.param).data as *const *mut c_char;
                Some(CStr::from_ptr(*ptr))
            }
        } else {
            None
        }
    }
}

impl TypedOSSLParamData<*const CStr> for Utf8PtrData {
    fn set(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        unsafe {
            if value.is_null() {
                return Err("new value for parameter data was null".to_string());
            } else if (*self.param).data.is_null() {
                (*self.param).return_size = 0;
            } else {
                match value.as_ref() {
                    Some(cstr) => {
                        (*self.param).return_size = cstr.to_bytes().len();
                        *((*self.param).data as *mut *const c_char) = cstr.as_ptr();
                    },
                    None => return Err("couldn't get &CStr from *const CStr".to_string()),
                }
            }
        }
        Ok(())
    }
}

/* We don't need to `impl TypedOSSLParamData<&'static CStr> for Utf8PtrData` separately,
 * because Rust can implicitly convert a &'static CStr reference to a raw *const CStr pointer.
 * However, if we want to add an explicit non-static lifetime to an impl of it over CStr, I
 * think things would get more complicated.
 */

impl TryFrom<*mut ossl_param_st> for Utf8PtrData {
    type Error = OSSLParamError;

    fn try_from(param: *mut ossl_param_st) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) =>
                if param.data_type != OSSL_PARAM_UTF8_PTR {
                    Err("tried to make Utf8PtrData from ossl_param_st with data_type != OSSL_PARAM_UTF8_PTR".to_string())
                } else {
                    Ok(Utf8PtrData { param })
                },
            None => Err("tried to make Utf8PtrData from null pointer".to_string()),
        }
    }
}
