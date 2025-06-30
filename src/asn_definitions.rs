mod inner {
    include!(concat!(env!("OUT_DIR"), "/rasn-generated.rs"));
}

pub use inner::*;
