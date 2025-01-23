use super::OSSL_ALGORITHM;

use std::collections::HashMap;

pub trait AdapterContextTrait {
    fn get_algorithms(&self) -> HashMap<u32, Vec<OSSL_ALGORITHM>>;
}
