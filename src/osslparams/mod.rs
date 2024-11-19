use std::ffi::CStr;

use crate::bindings::{OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_PTR, ossl_param_st};

pub mod data;

// List of supported types: https://docs.openssl.org/master/man3/OSSL_PARAM/#supported-types
#[derive(Debug, Clone)]
pub enum OSSLParam {
    Utf8Ptr(Utf8PtrData),
    Int(IntData),
    UInt(UIntData),
}

#[derive(Debug, Clone)]
pub struct Utf8PtrData {
    param: *mut ossl_param_st
}

#[derive(Debug, Clone)]
pub struct IntData {
    param: *mut ossl_param_st
}

#[derive(Debug, Clone)]
pub struct UIntData {
    param: *mut ossl_param_st
}

pub type OSSLParamError = String;

pub type KeyType = CStr;

impl OSSLParam {
    pub fn set<T>(&mut self, value: T) -> Result<(), OSSLParamError>
    where
        Self: OSSLParamSetter<T>,
    {
        self.set_inner(value)
    }

    pub fn get<T>(&self) -> Option<T>
    where
        Self: OSSLParamGetter<T>,
    {
        self.get_inner()
    }

    pub fn get_c_struct(&self) -> *mut ossl_param_st {
        match self {
            OSSLParam::Utf8Ptr(d) => d.param,
            OSSLParam::Int(d) => d.param,
            OSSLParam::UInt(d) => d.param,
        }
    }

    pub fn get_key(&self) -> &KeyType {
        unsafe {
            CStr::from_ptr((*self.get_c_struct()).key)
        }
    }

    // corresponds to OSSL_PARAM_modified()
    #[allow(dead_code)]
    pub fn modified(&self) -> bool {
        unsafe {
            (*self.get_c_struct()).return_size != OSSL_PARAM_UNMODIFIED
        }
    }

    // right now this method is just here to show we can return &dyn OSSLParamData if we need it
    #[allow(dead_code)]
    fn inner_data(&self) -> &dyn OSSLParamData {
        match self {
            OSSLParam::Utf8Ptr(d) => d,
            OSSLParam::Int(d) => d,
            OSSLParam::UInt(d) => d,
        }
    }

    // returns e.g. "Int" if self is an OSSLParam::Int(IntData)
    fn variant_name(&self) -> String {
        let s = format!("{:?}", self);
        s.split("(").next().unwrap().to_owned()
    }
}

pub trait OSSLParamSetter<T> {
    fn set_inner(&mut self, value: T) -> Result<(), OSSLParamError>;
}

pub trait OSSLParamGetter<T> {
    fn get_inner(&self) -> Option<T>;
}

pub trait OSSLParamData {
    fn new_null(key: &KeyType) -> Self where Self: Sized;
}

pub trait TypedOSSLParamData<T>: OSSLParamData {
    fn set(&mut self, value: T) -> Result<(), OSSLParamError>;
}

macro_rules! setter_type_err_string {
    ($param:expr, $value:ident) => {
        format!("Type {} could not be stored in OSSLParam::{}",
            std::any::type_name_of_val(&$value),
            $param.variant_name())
    }
}

pub(crate) use setter_type_err_string;

macro_rules! new_null_param {
    ($constructor:ident, $data_type:ident, $key:expr) => {
        $constructor {
            param: Box::into_raw(Box::new(crate::bindings::ossl_param_st {
                key: $key.as_ptr().cast(),
                data_type: $data_type,
                data: std::ptr::null::<std::ffi::c_void>() as *mut std::ffi::c_void,
                data_size: 0,
                return_size: 0,
            }))
        }
    }
}

pub(crate) use new_null_param;

macro_rules! impl_setter {
    ($t:ty, $variant:ident) => {
        impl crate::osslparams::OSSLParamSetter<$t> for OSSLParam {
            fn set_inner(&mut self, value: $t) -> Result<(), OSSLParamError> {
                if let OSSLParam::$variant(d) = self {
                    d.set(value)
                } else {
                    Err(setter_type_err_string!(self, value))
                }
            }
        }
    }
}

pub(crate) use impl_setter;

impl TryFrom<*mut ossl_param_st> for OSSLParam {
    type Error = OSSLParamError;

    fn try_from(p: *mut ossl_param_st) -> std::result::Result<Self, Self::Error> {
        match unsafe { p.as_mut() } {
            Some(p) => match p.data_type {
                OSSL_PARAM_UTF8_PTR => {
                    Ok(OSSLParam::Utf8Ptr(Utf8PtrData::try_from(p as *mut ossl_param_st).unwrap()))
                },
                OSSL_PARAM_INTEGER => {
                    Ok(OSSLParam::Int(IntData::try_from(p as *mut ossl_param_st).unwrap()))
                },
                OSSL_PARAM_UNSIGNED_INTEGER => {
                    Ok(OSSLParam::UInt(UIntData::try_from(p as *mut ossl_param_st).unwrap()))
                },
                _ => Err("Couldn't convert to OSSLParam from *mut ossl_param_st".to_string())
            },
            None => Err("Couldn't convert to OSSLParam from null pointer".to_string()),
        }
    }
}

pub const OSSL_PARAM_END: ossl_param_st = ossl_param_st {
    key: std::ptr::null(),
    data_type: 0,
    data: std::ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};

/*
 * core::ffi:c_size_t is only in nightly, and unstable
 *
 * https://github.com/rust-lang/rust/issues/88345 seems to have stalled,
 * so for now we just assume c_size_t and usize are the same.
 *
 * TODO: revisit if c_size_t goes stable
 */
// const OSSL_PARAM_UNMODIFIED: usize = core::ffi::c_size_t::MAX;
const OSSL_PARAM_UNMODIFIED: usize = usize::MAX;

pub fn ossl_param_locate<'a>(params: &'a mut [OSSLParam], key: &KeyType) -> Option<&'a mut OSSLParam> {
    params.iter_mut().find(|p| {
        p.get_key() == key
    })
}
