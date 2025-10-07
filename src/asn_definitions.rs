mod inner {
    #[cfg(feature = "_transcoders_deps")]
    include!(concat!(env!("OUT_DIR"), "/rasn-generated.rs"));
}

#[allow(unused_imports)]
pub use inner::*;
