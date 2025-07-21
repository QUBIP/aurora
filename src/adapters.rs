use crate as aurora;
use aurora::bindings;
use aurora::forge;
use aurora::upcalls::{traits::*, CoreDispatchWithCoreHandle};
use bindings::OSSL_ALGORITHM;
use bindings::OSSL_PARAM;
use forge::osslparams::OSSLParam;
use function_name::named;
use std::collections::HashMap;
use std::ffi::CStr;

use anyhow::anyhow;

mod libcrux;
mod libcrux_draft;
mod pqclean;

pub(crate) mod common;

mod traits;
pub use traits::AdapterContextTrait;

#[derive(Debug)]
pub(crate) struct ObjSigId {
    pub oid: &'static CStr,
    pub short_name: &'static CStr,
    pub long_name: &'static CStr,
    pub digest_name: Option<&'static CStr>,
}

pub struct AdaptersHandle<'a> {
    upcaller: &'a CoreDispatchWithCoreHandle<'a>,
    contexts: Vec<Box<dyn AdapterContextTrait>>,
    algorithms: HashMap<u32, *const OSSL_ALGORITHM>,
    alg_iters: HashMap<u32, Box<dyn Iterator<Item = OSSL_ALGORITHM>>>,
    capabilities: HashMap<&'static CStr, Vec<*const OSSL_PARAM>>,
    obj_sigids: Vec<ObjSigId>,
    finalized: bool,
}

impl<'a> std::fmt::Debug for AdaptersHandle<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptersHandle")
            .field("upcaller", &self.upcaller)
            .field(
                "contexts",
                &format!("(there are {} of them)", self.contexts.len()),
            )
            .field("algorithms", &self.algorithms)
            //.field("alg_iters", &self.alg_iters)
            .field("capabilities", &self.capabilities)
            .field("obj_sigids", &self.obj_sigids)
            .field("finalized", &self.finalized)
            .finish()
    }
}

#[derive(Debug)]
pub struct FinalizedAdaptersHandle {
    #[expect(dead_code)]
    contexts: Vec<Box<dyn AdapterContextTrait>>,
    algorithms: HashMap<u32, *const OSSL_ALGORITHM>,
    capabilities: HashMap<&'static CStr, Vec<*const OSSL_PARAM>>,
    #[expect(dead_code)]
    obj_sigids: Vec<ObjSigId>,
}

impl<'a> AdaptersHandle<'a> {
    #[named]
    pub fn register_adapter<T: AdapterContextTrait + std::fmt::Debug + 'static>(&mut self, ctx: T) {
        trace!(target: log_target!(), "{}", "Called!");
        if self.finalized {
            error!("Attempted to register new adapter on finalized AdaptersHandle struct");
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

    #[named]
    fn check_state(&self) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");
        if self.finalized {
            return Err(anyhow::anyhow!(
                "AdaptersHandle struct was already finalized!"
            ));
        }
        return Ok(());
    }

    #[named]
    pub fn register_algorithms(
        &mut self,
        op_id: u32,
        algs: impl Iterator<Item = OSSL_ALGORITHM> + std::fmt::Debug + 'static,
    ) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");
        self.check_state()?;

        #[cfg(not(debug_assertions))] // code compiled only in release builds
        todo!();

        trace!(target: log_target!(), "Registering algorithms for op {op_id:}: {algs:?}");

        match self.alg_iters.entry(op_id) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                // Move the currently existing boxed iterator out of the map.
                // (Moving it like this is the way around "does not live long enough" errors.)
                // We have to insert something to take its place; an empty iterator suffices.
                let current_box = entry.insert(Box::new(std::iter::empty()));

                // Chain the new algorithms onto the existing boxed iterator, and put it back into
                // the hashmap, discarding the empty iterator that temporarily took its place.
                let _ = entry.insert(Box::new(current_box.chain(algs)));
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Box::new(algs));
            }
        }

        Ok(())
    }

    #[named]
    pub fn register_capability(
        &mut self,
        capability: &'static CStr,
        params_list: *const OSSL_PARAM,
    ) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");
        self.check_state()?;

        trace!(target: log_target!(), "Registering capability {capability:?}:");
        #[cfg(debug_assertions)] // code compiled only in debug builds
        {
            let params = OSSLParam::try_from(params_list).map_err(|e| {
                anyhow! {e}
            })?;
            for p in params {
                trace!(target: log_target!(), "  {p:?}\n");
            }
        }

        match self.capabilities.entry(&capability) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                trace!(target: log_target!(), "Adding first capability for {:?}", capability);
                let _ = entry.insert(vec![params_list]);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                trace!(target: log_target!(), "Appending capability for {:?}", capability);
                let v = entry.get_mut();
                v.push(params_list);
            }
        };

        Ok(())
    }

    #[named]
    pub fn register_obj_sigid(&self, obj_sigid: ObjSigId) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "Registering obj_sigid {obj_sigid:?}:");

        #[cfg(test)]
        {
            // Note test builds are those built for integration and unit tests by cargo, in which case we are not loading
            // the provider from within OpenSSL but rather using it standalone.
            // In such case, we do not have valid core_handle or core_dispatch pointers, so we cannot do upcalls.
            debug!(target: log_target!(), "In test builds, we skip registering obj_sigid {obj_sigid:?}:");
            return Ok(());
        }

        #[allow(unreachable_code)]
        let (oid, sn, ln, digest_name) = (
            obj_sigid.oid,
            obj_sigid.short_name,
            obj_sigid.long_name,
            obj_sigid.digest_name,
        );
        match self.OBJ_create(oid, sn, ln) {
            Ok(_) => {
                debug!(target: log_target!(), "Registered OBJ_create({oid:?},{sn:?},{ln:?})");
            }
            Err(e) => {
                error!(target: log_target!(), "Failed to OBJ_create({oid:?},{sn:?},{ln:?}): {e:?}");
                return Err(e.into());
            }
        }

        let sign_name = oid;
        let pkey_name = ln;
        match self.OBJ_add_sigid(sign_name, digest_name, pkey_name) {
            Ok(_) => {
                debug!(target: log_target!(), "Registered OBJ_add_sigid({sign_name:?}, {digest_name:?}, {pkey_name:?})");
            }
            Err(e) => {
                error!(target: log_target!(), "Failed to OBJ_add_sigid({sign_name:?}, {digest_name:?}, {pkey_name:?}): {e:?}");
                return Err(e.into());
            }
        }

        Ok(())
    }

    #[named]
    fn finalize(mut self) -> FinalizedAdaptersHandle {
        trace!(target: log_target!(), "{}", "Called!");
        if self.finalized {
            unreachable!("AdaptersHandle struct was already finalized!");
        }

        // allocate a C array with OSSL_ALGORITHM_END for each operation ID
        self.algorithms = std::mem::take(&mut self.alg_iters)
            .into_iter()
            .map(|(op_id, boxitr)| {
                //let e = Box::new(std::iter::empty());
                //let boxitr = std::mem::replace(&mut boxitr, e);
                //let boxitr = std::mem::take(&mut boxitr);
                let itr = boxitr.chain(std::iter::once(OSSL_ALGORITHM::END));
                let vec = itr.collect::<Vec<_>>();
                let boxed_slice = vec.into_boxed_slice();

                // Return the raw pointer to the boxed slice
                (op_id, Box::into_raw(boxed_slice) as *const OSSL_ALGORITHM)
            })
            .collect();

        self.finalized = true;

        let fh = FinalizedAdaptersHandle {
            contexts: self.contexts,
            algorithms: self.algorithms,
            capabilities: self.capabilities,
            obj_sigids: self.obj_sigids,
        };

        fh
    }
}

impl<'a> FinalizedAdaptersHandle {
    // After `new()` returns, we should have a valid (fully initialized)
    // `FinalizedAdaptersHandle` struct.
    //
    // Internally, an `AdaptersHandle` is temporarily used while each adapter is
    // initialized, and dropped before returning the `FinalizedAdaptersHandle`.
    pub fn new(upcaller: &'a CoreDispatchWithCoreHandle<'a>) -> Self {
        let mut handle = AdaptersHandle {
            upcaller,
            contexts: Default::default(),
            algorithms: Default::default(),
            alg_iters: Default::default(),
            capabilities: Default::default(),
            obj_sigids: Default::default(),
            finalized: false,
        };

        // initialize and register each adapter
        libcrux::init(&mut handle).expect("Failure initializing adapter `libcrux`");
        libcrux_draft::init(&mut handle).expect("Failure initializing adapter `libcrux_draft`");
        pqclean::init(&mut handle).expect("Failure initializing adapter `pqclean`");

        let mut contexts = std::mem::take(&mut handle.contexts); // Temporarily move out

        let res = contexts.iter().try_for_each(|ctx| {
            debug!("🚀 🧮 Calling register_algorithms() on {ctx:?}");
            ctx.register_algorithms(&mut handle)
        });
        match res {
            Ok(_) => {
                trace!("Registered all algorithms from all registered adapters");
            }
            Err(e) => {
                error!("Failed registering algorithms: {e:?}");
                panic!("Failed registering algorithms: {e:?}")
            }
        };

        let res = contexts.iter().try_for_each(|ctx| {
            debug!("🚀 🌟 Calling register_capabilities() on {ctx:?}");
            ctx.register_capabilities(&mut handle)
        });
        match res {
            Ok(_) => {
                trace!("Registered all capabilities from all registered adapters");
            }
            Err(e) => {
                error!("Failed registering capabilities: {e:?}");
                panic!()
            }
        };

        let res = contexts.iter().try_for_each(|ctx| {
            debug!("🚀 🌟 Calling register_obj_sigids() on {ctx:?}");
            ctx.register_obj_sigids(&mut handle)
        });
        match res {
            Ok(_) => {
                trace!("Registered all obj_sigids from all registered adapters");
            }
            Err(e) => {
                error!("Failed registering obj_sigids: {e:?}");
                panic!("Failed registering obj_sigids: {e:?}")
            }
        };

        std::mem::swap(&mut handle.contexts, &mut contexts); // Place it back

        // then finalize
        handle.finalize()
    }

    #[named]
    pub(crate) fn get_algorithms_by_op_id(&self, op: u32) -> Option<*const OSSL_ALGORITHM> {
        trace!(target: log_target!(), "{}", "Called!");
        // HashMap::get() returns an Option<&*const OSSL_ALGORITHM>, so we have to dereference
        self.algorithms.get(&op).map(|p| *p)
    }

    #[named]
    pub(crate) fn get_capabilities(
        &self,
        capability: &'static CStr,
    ) -> Option<Box<dyn Iterator<Item = *const OSSL_PARAM> + '_>> {
        trace!(target: log_target!(), "{}", "Called!");
        self.capabilities.get(&capability).map(|p| {
            let it = Box::new(p.iter().copied());
            it as Box<dyn Iterator<Item = _>>
        })
    }
}

impl<'a> CoreUpcaller for AdaptersHandle<'a> {
    fn fn_from_core_dispatch(&self, id: u32) -> Option<unsafe extern "C" fn()> {
        self.upcaller.fn_from_core_dispatch(id)
    }
}

impl<'a> CoreUpcallerWithCoreHandle for AdaptersHandle<'a> {
    fn get_core_handle(&self) -> *const crate::init::OSSL_CORE_HANDLE {
        self.upcaller.get_core_handle()
    }
}
