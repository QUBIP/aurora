pub use openssl_provider_forge::*;

pub mod upcalls {
    pub use openssl_provider_forge::upcalls::*;

    pub mod traits {
        pub use openssl_provider_forge::upcalls::traits::*;
    }
}

#[cfg(any())]
pub(crate) mod bindings {
    pub(super) const OSSL_FUNC_KEYMGMT_UNUSED: u32 = 42;

    #[allow(dead_code)]
    pub const OSSL_FUNC_KEYMGMT_EXPORT: u32 = {
        #[cfg(not(feature = "export"))]
        {
            OSSL_FUNC_KEYMGMT_UNUSED
        }
        #[cfg(feature = "export")]
        {
            openssl_provider_forge::bindings::OSSL_FUNC_KEYMGMT_EXPORT
        }
    };

    #[allow(dead_code)]
    pub const OSSL_FUNC_KEYMGMT_EXPORT_TYPES: u32 = {
        #[cfg(not(feature = "export"))]
        {
            OSSL_FUNC_KEYMGMT_UNUSED
        }
        #[cfg(feature = "export")]
        {
            openssl_provider_forge::bindings::OSSL_FUNC_KEYMGMT_EXPORT_TYPES
        }
    };

    pub use openssl_provider_forge::bindings::*;

    #[cfg(test)]
    mod tests {
        use crate::tests::common::OurError;

        struct TestCTX<'a> {
            //provctx: OpenSSLProvider<'a>,
            phantom: std::marker::PhantomData<&'a ()>,
        }

        impl<'a> Default for TestCTX<'a> {
            fn default() -> Self {
                Self {
                    phantom: Default::default(),
                }
            }
        }

        fn setup<'a>() -> Result<TestCTX<'a>, OurError> {
            crate::tests::common::setup()?;

            //use crate::tests::new_provctx_for_testing;
            //let provctx = new_provctx_for_testing();
            //let testctx = TestCTX { provctx };

            let testctx = TestCTX::default();

            Ok(testctx)
        }

        #[test]
        fn test_constants() {
            let testctx = setup().expect("Failed to initialize test setup");
            //let provctx = testctx.provctx;
            let _ = testctx;

            assert_eq!(
                crate::forge::bindings::OSSL_FUNC_KEYMGMT_EXPORT,
                openssl_provider_forge::bindings::OSSL_FUNC_KEYMGMT_EXPORT
            )
        }
    }
}
