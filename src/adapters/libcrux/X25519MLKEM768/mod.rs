use super::*;
use bindings::dispatch_table_entry;
use bindings::{OSSL_FUNC_kem_decapsulate_fn, OSSL_FUNC_KEM_DECAPSULATE};
use bindings::{OSSL_FUNC_kem_decapsulate_init_fn, OSSL_FUNC_KEM_DECAPSULATE_INIT};
use bindings::{OSSL_FUNC_kem_encapsulate_fn, OSSL_FUNC_KEM_ENCAPSULATE};
use bindings::{OSSL_FUNC_kem_encapsulate_init_fn, OSSL_FUNC_KEM_ENCAPSULATE_INIT};
use bindings::{OSSL_FUNC_kem_freectx_fn, OSSL_FUNC_KEM_FREECTX};
use bindings::{OSSL_FUNC_kem_newctx_fn, OSSL_FUNC_KEM_NEWCTX};
use bindings::{OSSL_FUNC_keymgmt_export_fn, OSSL_FUNC_KEYMGMT_EXPORT};
use bindings::{OSSL_FUNC_keymgmt_export_types_ex_fn, OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX};
use bindings::{OSSL_FUNC_keymgmt_free_fn, OSSL_FUNC_KEYMGMT_FREE};
use bindings::{OSSL_FUNC_keymgmt_gen_cleanup_fn, OSSL_FUNC_KEYMGMT_GEN_CLEANUP};
use bindings::{OSSL_FUNC_keymgmt_gen_fn, OSSL_FUNC_KEYMGMT_GEN};
use bindings::{OSSL_FUNC_keymgmt_gen_init_fn, OSSL_FUNC_KEYMGMT_GEN_INIT};
use bindings::{OSSL_FUNC_keymgmt_has_fn, OSSL_FUNC_KEYMGMT_HAS};
use bindings::{OSSL_FUNC_keymgmt_import_fn, OSSL_FUNC_KEYMGMT_IMPORT};
use bindings::{OSSL_FUNC_keymgmt_import_types_ex_fn, OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX};
use bindings::{OSSL_FUNC_keymgmt_new_fn, OSSL_FUNC_KEYMGMT_NEW};

mod kem_functions;
mod keymgmt_functions;

// Ensure proper null-terminated C string
// https://docs.openssl.org/master/man7/provider/#algorithm-naming
pub(super) const NAMES: &CStr = c"X25519MLKEM768";

// Ensure proper null-terminated C string
pub(super) const DESCRIPTION: &CStr = c"X25519MLKEM768 from libcrux";

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/master/man7/provider-kem/
pub(super) const KEM_FUNCTIONS: [OSSL_DISPATCH; 7] = [
    dispatch_table_entry!(
        OSSL_FUNC_KEM_NEWCTX,
        OSSL_FUNC_kem_newctx_fn,
        kem_functions::newctx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_FREECTX,
        OSSL_FUNC_kem_freectx_fn,
        kem_functions::freectx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        OSSL_FUNC_kem_encapsulate_init_fn,
        kem_functions::encapsulate_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_ENCAPSULATE,
        OSSL_FUNC_kem_encapsulate_fn,
        kem_functions::encapsulate
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_DECAPSULATE_INIT,
        OSSL_FUNC_kem_decapsulate_init_fn,
        kem_functions::decapsulate_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_DECAPSULATE,
        OSSL_FUNC_kem_decapsulate_fn,
        kem_functions::decapsulate
    ),
    OSSL_DISPATCH::END,
];

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/master/man7/provider-keymgmt/
pub(super) const KMGMT_FUNCTIONS: [OSSL_DISPATCH; 11] = [
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_NEW,
        OSSL_FUNC_keymgmt_new_fn,
        keymgmt_functions::new
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_FREE,
        OSSL_FUNC_keymgmt_free_fn,
        keymgmt_functions::free
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_HAS,
        OSSL_FUNC_keymgmt_has_fn,
        keymgmt_functions::has
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN,
        OSSL_FUNC_keymgmt_gen_fn,
        keymgmt_functions::gen
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        OSSL_FUNC_keymgmt_gen_cleanup_fn,
        keymgmt_functions::gen_cleanup
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN_INIT,
        OSSL_FUNC_keymgmt_gen_init_fn,
        keymgmt_functions::gen_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_IMPORT,
        OSSL_FUNC_keymgmt_import_fn,
        keymgmt_functions::import
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_EXPORT,
        OSSL_FUNC_keymgmt_export_fn,
        keymgmt_functions::export
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX,
        OSSL_FUNC_keymgmt_import_types_ex_fn,
        keymgmt_functions::import_types_ex
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX,
        OSSL_FUNC_keymgmt_export_types_ex_fn,
        keymgmt_functions::export_types_ex
    ),
    OSSL_DISPATCH::END,
];
