use super::{named, OpenSSLProvider};
use rand_core::CryptoRngCore;

impl<'a> OpenSSLProvider<'a> {
    #[named]
    pub fn get_rng(&self) -> &'a mut dyn CryptoRngCore {
        trace!(target: log_target!(), "Called ");

        let rng = Box::new(rand::rngs::OsRng);

        // FIXME: we should not leak memory and properly derive an RNG instance from the provctx
        let leakyrng = Box::into_raw(rng);

        return unsafe { &mut *leakyrng };
    }
}
