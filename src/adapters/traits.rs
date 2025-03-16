use std::fmt::Debug;

use crate as aurora;

use aurora::adapters::AdaptersHandle;

pub trait AdapterContextTrait: Debug {
    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    #[function_name::named]
    fn register_algorithms(&self, _handle: &mut AdaptersHandle) -> Result<(), aurora::Error> {
        debug!(target: log_target!(), "No algorithms to register for {}", self.name());
        Ok(())
    }

    #[function_name::named]
    fn register_capabilities(&self, _handle: &mut AdaptersHandle) -> Result<(), aurora::Error> {
        debug!(target: log_target!(), "No capabilities to register for {}", self.name());
        Ok(())
    }
}
