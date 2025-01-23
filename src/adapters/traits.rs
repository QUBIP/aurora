use crate as aurora;

use aurora::adapters::AdaptersHandle;

pub trait AdapterContextTrait {
    fn register_algorithms(&self, handle: &mut AdaptersHandle) -> Result<(), aurora::Error>;
}
