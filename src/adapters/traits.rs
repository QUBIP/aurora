use std::fmt::Debug;

use crate as aurora;

use aurora::adapters::AdaptersHandle;

pub trait AdapterContextTrait: Debug {
    fn register_algorithms(&self, handle: &mut AdaptersHandle) -> Result<(), aurora::Error>;
}
