pub(crate) mod libcrux;

#[derive(Debug)]
pub(crate) struct Contexts {
    pub libcrux: libcrux::AdapterContext,
}

impl Default for Contexts {
    fn default() -> Self {
        Self { libcrux: Default::default() }
    }
}