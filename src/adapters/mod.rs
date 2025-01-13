use std::collections::HashMap;

use crate::bindings::OSSL_ALGORITHM;

pub(crate) mod libcrux;

#[derive(Debug, PartialEq)]
pub struct AdapterContext {
    algorithms: HashMap<u32, Vec<*const OSSL_ALGORITHM>>,
    op_kem_ptr: Option<*const OSSL_ALGORITHM>,
    op_keymgmt_ptr: Option<*const OSSL_ALGORITHM>,
}

impl Default for AdapterContext {
    fn default() -> Self {
        Self {
            op_kem_ptr: Default::default(),
            op_keymgmt_ptr: Default::default(),
            algorithms: Default::default(),
        }
    }
}

pub trait AdapterContextTrait {
    fn get_algorithms(&self) -> HashMap<u32, Vec<OSSL_ALGORITHM>>;
}

pub(crate) struct Contexts {
    pub contexts: Vec<Box<dyn AdapterContextTrait>>,
    pub algorithms: HashMap<u32, *const OSSL_ALGORITHM>,
    finalized: bool,
}

impl std::fmt::Debug for Contexts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contexts")
            .field(
                "contexts",
                &format!("(there are {} of them)", self.contexts.len()),
            )
            .field("algorithms", &self.algorithms)
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Contexts {
    pub fn register<T: AdapterContextTrait + std::fmt::Debug + 'static>(&mut self, ctx: T) {
        if self.finalized {
            error!("Attempted to register new adapter on finalized Contexts struct");
            return;
        }

        self.contexts.push(Box::new(ctx));

        // with Box<dyn Trait> I don't think there's an easy way to compare for equality....
        /*
        if self.contexts.contains(&ctx) {
            warn!("Ignoring atttempt to reregister AdapterContext: {:?}", &ctx);
        } else {
            self.contexts.push(Box::new(ctx));
        }
        */
    }

    pub fn finalize(&mut self) {
        // merge the hashmaps into one, where each operation ID maps to the concatenation of all the
        // vectors it mapped to in the different adapters' algorithm lists
        let hashmap_of_vecs: HashMap<u32, Vec<OSSL_ALGORITHM>> = self
            .contexts
            .iter()
            .flat_map(|ctx| ctx.get_algorithms())
            .fold(HashMap::new(), |mut acc, (op_id, algs)| {
                acc.entry(op_id)
                    .and_modify(|entry| entry.extend(&algs))
                    .or_insert(algs);
                acc
            });
        // allocate a C array with OSSL_ALGORITHM_END for each operation ID
        self.algorithms = hashmap_of_vecs
            .into_iter()
            .map(|(op_id, v)| {
                let boxed_slice = Box::new(
                    v.into_iter()
                        .chain(std::iter::once(OSSL_ALGORITHM::END))
                        .collect::<Vec<_>>(),
                )
                .into_boxed_slice();
                (op_id, Box::into_raw(boxed_slice) as *const OSSL_ALGORITHM)
            })
            .collect();
        self.finalized = true;
    }

    pub fn get_algorithms_by_op_id(&self, op: u32) -> Option<*const OSSL_ALGORITHM> {
        // HashMap::get() returns an Option<&*const OSSL_ALGORITHM>, so we have to dereference
        self.algorithms.get(&op).map(|p| *p)
    }
}

impl Default for Contexts {
    // after default() returns, we should have a valid (fully initialized) Contexts struct
    fn default() -> Self {
        let mut super_ctx = Self {
            contexts: Default::default(),
            algorithms: Default::default(),
            finalized: false,
        };
        // initialize and register each adapter
        super_ctx.register(libcrux::LibcruxAdapter);
        // then finalize
        super_ctx.finalize();
        super_ctx
    }
}
