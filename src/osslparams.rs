use crate::bindings::{ossl_param_st, OSSL_PARAM_INTEGER, OSSL_PARAM_UTF8_PTR};
use libc::c_void;
use std::ffi::CStr;

// List of supported types: https://docs.openssl.org/master/man3/OSSL_PARAM/#supported-types

#[derive(Debug, Clone)]
pub enum OSSLParam {
    Utf8Ptr(Utf8PtrData),
    Int(IntData),
}

impl OSSLParam {
    pub fn get_c_struct(&self) -> *mut ossl_param_st {
        match self {
            OSSLParam::Utf8Ptr(d) => d.param,
            OSSLParam::Int(d) => d.param,
        }
    }
}

type OSSLParamError = &'static str;

impl TryFrom<*mut ossl_param_st> for OSSLParam {
    type Error = OSSLParamError;

    fn try_from(p: *mut ossl_param_st) -> std::result::Result<Self, Self::Error> {
        match unsafe { p.as_mut() } {
            Some(p) => match p.data_type {
                OSSL_PARAM_UTF8_PTR => Ok(OSSLParam::Utf8Ptr(
                    Utf8PtrData::try_from(p as *mut ossl_param_st).unwrap(),
                )),
                OSSL_PARAM_INTEGER => Ok(OSSLParam::Int(
                    IntData::try_from(p as *mut ossl_param_st).unwrap(),
                )),
                _ => Err("Couldn't convert to OSSLParam from *mut ossl_param_st"),
            },
            None => Err("Couldn't convert to OSSLParam from null pointer"),
        }
    }
}

type KeyType = CStr;

pub trait OSSLParamData {
    type DataType;

    /* We have kind of an interesting memory allocation problem here: new_null needs to allocate an
     * ossl_param_st on the heap, because the Utf8PtrData etc structs store a pointer to it rather
     * than storing the struct itself, but when the Rust struct impl-ing this trait goes out of
     * scope, we don't currently have a way of knowing whether or not to rebox and drop that C
     * struct, because we don't know whether it was created by us with a call to new_null or
     * whether it was created on the C side and only passed to us temporarily. Allocating in an
     * arena might be wise, for this reason.
     */
    fn new_null(key: &KeyType) -> Self;

    /* For setting the inner value, we can use Self::DataType to ensure that we're giving it the
     * right kind of data. However, I'm not sure yet how to make this function usable from the
     * outer enum, or even exactly how to implement it for Utf8PtrData and IntData.
     */
    //fn set(&mut self, value: Self::DataType);
}

#[derive(Debug, Clone)]
pub struct Utf8PtrData {
    param: *mut ossl_param_st,
}

impl OSSLParamData for Utf8PtrData {
    type DataType = *mut CStr;

    fn new_null(key: &KeyType) -> Self {
        let b = Box::new(ossl_param_st {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_UTF8_PTR,
            data: std::ptr::null::<c_void>() as *mut c_void,
            data_size: 0,
            return_size: 0,
        });
        Utf8PtrData {
            param: Box::into_raw(b),
        }
    }
}

impl TryFrom<*mut ossl_param_st> for Utf8PtrData {
    type Error = OSSLParamError;

    fn try_from(param: *mut ossl_param_st) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) => {
                if param.data_type != OSSL_PARAM_UTF8_PTR {
                    Err("tried to make Utf8PtrData from ossl_param_st with data_type != OSSL_PARAM_UTF8_PTR")
                } else {
                    Ok(Utf8PtrData { param })
                }
            }
            None => Err("tried to make Utf8PtrData from null pointer"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntData {
    param: *mut ossl_param_st,
}

impl OSSLParamData for IntData {
    type DataType = i64;

    fn new_null(key: &KeyType) -> Self {
        let b = Box::new(ossl_param_st {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::null::<c_void>() as *mut c_void,
            data_size: 0,
            return_size: 0,
        });
        IntData {
            param: Box::into_raw(b),
        }
    }
}

impl TryFrom<*mut ossl_param_st> for IntData {
    type Error = &'static str;

    fn try_from(param: *mut ossl_param_st) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) => {
                if param.data_type != OSSL_PARAM_INTEGER {
                    Err("tried to make IntData from ossl_param_st with data_type != OSSL_PARAM_INTEGER")
                } else {
                    Ok(IntData { param })
                }
            }
            None => Err("tried to make IntData from null pointer"),
        }
    }
}

unsafe impl Sync for ossl_param_st {}

pub const OSSL_PARAM_END: ossl_param_st = ossl_param_st {
    key: std::ptr::null(),
    data_type: 0,
    data: std::ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};
