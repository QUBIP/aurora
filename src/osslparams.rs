use crate::bindings::{OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_PTR, ossl_param_st};
use std::ffi::{c_char, c_void, CStr};

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

macro_rules! setter_type_err_string {
    ($param:expr, $value:ident) => {
        format!("Type {} could not be stored in OSSLParam::{}",
            std::any::type_name_of_val(&$value),
            $param.variant_name())
    }
}

// we can store a *const CStr in a UTF-8 pointer param
impl OSSLParamSetter<*const CStr> for OSSLParam {
    fn set_inner(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        if let OSSLParam::Utf8Ptr(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

// we can store a &'static CStr in a UTF-8 pointer param
impl OSSLParamSetter<&'static CStr> for OSSLParam {
    fn set_inner(&mut self, value: &'static CStr) -> Result<(), OSSLParamError> {
        if let OSSLParam::Utf8Ptr(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

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

trait PrimIntMarker: num_traits::PrimInt {}

impl PrimIntMarker for i8 {}
impl PrimIntMarker for i16 {}
impl PrimIntMarker for i32 {}
impl PrimIntMarker for i64 {}
impl PrimIntMarker for i128 {}

impl<T: PrimIntMarker> OSSLParamSetter<T> for OSSLParam {
    fn set_inner(&mut self, value: T) -> Result<(), OSSLParamError> {
        if let OSSLParam::Int(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

// we can store a u64 in an unsigned integer param
impl OSSLParamSetter<u64> for OSSLParam {
    fn set_inner(&mut self, value: u64) -> Result<(), OSSLParamError> {
        if let OSSLParam::UInt(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

macro_rules! new_null_param {
    ($constructor:ident, $data_type:ident, $key:expr) => {
        $constructor {
            param: Box::into_raw(Box::new(ossl_param_st {
                key: $key.as_ptr().cast(),
                data_type: $data_type,
                data: std::ptr::null::<c_void>() as *mut c_void,
                data_size: 0,
                return_size: 0,
            }))
        }
    }
}


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

pub trait OSSLParamData {
    /* We have kind of an interesting memory allocation problem here: new_null needs to allocate an
     * ossl_param_st on the heap, because the Utf8PtrData etc structs store a pointer to it rather
     * than storing the struct itself, but when the Rust struct impl-ing this trait goes out of
     * scope, we don't currently have a way of knowing whether or not to rebox and drop that C
     * struct, because we don't know whether it was created by us with a call to new_null or
     * whether it was created on the C side and only passed to us temporarily. Allocating in an
     * arena might be wise, for this reason.
     */
    fn new_null(key: &KeyType) -> Self where Self: Sized;
}

pub trait TypedOSSLParamData<T>: OSSLParamData {
    fn set(&mut self, value: T) -> Result<(), OSSLParamError>;
}

impl OSSLParamData for Utf8PtrData {
    fn new_null(key: &KeyType) -> Self where Self: Sized {
        new_null_param!(Utf8PtrData, OSSL_PARAM_UTF8_PTR, key)
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

/* We don't need to `impl TypedOSSLParamData<&'static CStr> for Utf8PtrData` separately, because
* Rust can implicitly convert a &'static CStr reference to a raw *const CStr pointer. However, if
* we want to add an explicit non-static lifetime to an impl of it over CStr, I think things would
* get more complicated.
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


impl OSSLParamData for IntData {
    fn new_null(key: &KeyType) -> Self {
        new_null_param!(IntData, OSSL_PARAM_INTEGER, key)
    }
}

impl<T: PrimIntMarker> TypedOSSLParamData<T> for IntData {
    // https://github.com/openssl/openssl/blob/7f62adaf2b088de38ad2e534d0bfae2ff7ae01f2/crypto/params.c#L780-L796
    fn set(&mut self, value: T) -> Result<(), OSSLParamError> {
        unsafe {
            (*self.param).return_size = size_of::<i64>();
            if (*self.param).data.is_null() {
                Ok(())
            } else {
                match (*self.param).data_size {
                    s if s == size_of::<i32>() => {
                        if let Some(x) = value.to_i32() {
                            (*self.param).return_size = size_of::<i32>();
                            std::ptr::write((*self.param).data as *mut i32, x);
                            Ok(())
                        } else {
                            Err("value could not be converted to i32".to_string())
                        }
                    },
                    s if s == size_of::<i64>() => {
                        if let Some(x) = value.to_i64() {
                            std::ptr::write((*self.param).data as *mut i64, x);
                            Ok(())
                        } else {
                            Err("value could not be converted to i64".to_string())
                        }
                    },
                    _ => Err("param.data_size was neither the size of i32 nor of i64".to_string()),
                }
            }
        }
    }
}

impl TryFrom<*mut ossl_param_st> for IntData {
    type Error = &'static str;

    fn try_from(param: *mut ossl_param_st) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) =>
                if param.data_type != OSSL_PARAM_INTEGER {
                    Err("tried to make IntData from ossl_param_st with data_type != OSSL_PARAM_INTEGER")
                } else {
                    Ok(IntData { param })
                },
            None => Err("tried to make IntData from null pointer"),
        }
    }
}

impl OSSLParamData for UIntData {
    fn new_null(key: &KeyType) -> Self where Self: Sized {
        new_null_param!(UIntData, OSSL_PARAM_UNSIGNED_INTEGER, key)
    }
}

impl TypedOSSLParamData<u64> for UIntData {
    // https://github.com/openssl/openssl/blob/7f62adaf2b088de38ad2e534d0bfae2ff7ae01f2/crypto/params.c#L937-L951
    fn set(&mut self, value: u64) -> Result<(), OSSLParamError> {
        unsafe {
            (*self.param).return_size = size_of::<u64>();
            if (*self.param).data.is_null() {
                Ok(())
            } else {
                match (*self.param).data_size {
                    s if s == size_of::<u32>() => {
                        if let Ok(x) = u32::try_from(value) {
                            (*self.param).return_size = size_of::<u32>();
                            std::ptr::write((*self.param).data as *mut u32, x);
                            Ok(())
                        } else {
                            Err("value could not be converted to u32".to_string())
                        }
                    },
                    s if s == size_of::<u64>() => {
                        std::ptr::write((*self.param).data as *mut u64, value);
                        Ok(())
                    },
                    _ => Err("param.data_size was neither the size of u32 nor of u64".to_string()),
                }
            }
        }
    }
}

impl TryFrom<*mut ossl_param_st> for UIntData {
    type Error = &'static str;

    fn try_from(param: *mut ossl_param_st) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) =>
                if param.data_type != OSSL_PARAM_UNSIGNED_INTEGER {
                    Err("tried to make UIntData from ossl_param_st with data_type != OSSL_PARAM_UNSIGNED_INTEGER")
                } else {
                    Ok(UIntData { param })
                },
            None => Err("tried to make UIntData from null pointer"),
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

const OSSL_PARAM_UNMODIFIED: usize = core::ffi::c_size_t::MAX;

pub fn ossl_param_locate<'a>(params: &'a mut [OSSLParam], key: &KeyType) -> Option<&'a mut OSSLParam> {
    params.iter_mut().find(|p| {
        p.get_key() == key
    })
}
