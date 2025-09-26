# Changelog

All notable changes to this project will be documented in this file.

## [0.8.5] - 2025-09-26

### 🚀 Features

- *(rustcrypto)* Add SLH-DSA-SHAKE-256s algorithm support
- *(slhdsa_c)* Add slhdsa_c adapter
- *(rustcrypto)* Add SLH-DSA-SHAKE-128f algorithm and tests
- *(pqclean/MLDSA65_Ed25519)* Update algorithm identifiers and links
- *(pqclean)* Add MLDSA44_Ed25519 algorithm support
- *(pqclean/mldsa)* Use upstream crate for pubkey derivation

### 🐛 Bug Fixes

- *(deps)* Remove version pin for openssl_provider_forge
- *(tests)* Support optional trailing comma in macro syntax

### 🚜 Refactor

- *(adapters)* Return Result<_, KMGMTError> instead of risking unwrap() in keygen
- *(adapters)* Use fallible API design for keygen in all adapters
- *(SLHDSASHAKE192f/signature/tests)* Move unit tests to separate file
- *(tests)* Modularize SLHDSASHAKE192f signature helpers
- *(signature)* Move signature.rs and signature_functions.rs to src/adapters/common
- *(rustcrypto,macros)* Add registration macros, simplify adapter
- *(tests)* Simplify macro usage for test generation
- *(pqclean)* Replace algorithms registrations with new macros
- *(libcrux_draft)* Use the new macros for alghoritm registration

### ⚙️ Miscellaneous Tasks

- *(release)* Bump to v0.8.5-dev
- *(relase)* Rename crate to `qubip_aurora`
- *(release)* Add crates.io metadata to `Cargo.toml`
- *(README)* Update crates links
- Exclude test data from package

### Build

- *(test)* Ensure cdylib built only once before tests

### Cleanup

- *(encoder)* Add explanatory comments for unwrap()

### Refctor

- *(libcrux)* Use new macros for algorithms registration

## [0.8.4] - 2025-08-27

### 🚀 Features

- *(mldsa65/encoder)* Add PrivateKeyInfo -> DER encoder
- *(mldsa65/encoder)* Add SubjectPublicKeyInfo -> DER encoder
- *(encoder)* Add PrivateKeyInfo -> PEM encoder
- *(encoder)* Add SubjectPublicKeyInfo -> PEM encoder
- *(mldsa65)* Enable getting the algorithm ID param
- *(tests)* Build cdylib and set OPENSSL_MODULES before tests
- *(pqclean)* Add MLDSA44 and MLDSA87 support
- *(pqclean)* Add mldsa65_ed25519
- *(test)* Use cargo metadata to resolve target directory
- *(tests)* Add mldsa65 and slhdsa artifacts from openssl 3.5
- *(core)* Add BIO_write_ex upcall support
- *(asn)* Add rasn ASN.1 support and X509-ML-DSA-2025 spec
- *(pqclean/MLDSA65)* Add ASN.1 definitions and PKCS8 OID constant
- *(MLDSA65)* Add public key derivation from private key
- *(pqclean/MLDSA65)* Refactor PKCS8 private key decoding
- *(pqclean/MLDSA65)* Add DER encoding for private keys
- *(data/asn1)* Add ML-DSA-44/65/87 key ASN.1 definitions
- *(pqclean/ml-dsa-87)* Add PKCS#8/SPKI support and test vectors
- *(pqcclean/MLDSA44)* Add PKCS#8/SPKI support and test vectors
- *(pqclean/MLDSA65_Ed25519)* Add PKCS8/SPKI DER/PEM support
- *(upcalls)* Add OBJ_create core upcall support
- *(core)* Add CoreDispatchWithCoreHandle conversions
- *(rustcrypto/slhdsa)* Add SLH-DSA
- *(upcalls)* Move upcalls to forge crate

### 🐛 Bug Fixes

- *(mldsa65/encoder)* Use error and debug macro in the right places
- *(mldsa/encoder)* Output bit string instead of octet string in pubkey DER
- *(pqclean)* Encode OID in AlgorithmIdentifier as a module-level constant
- *(tests)* Insert aurora args after first openssl arg
- *(tests)* Update openssl genpkey usage and enable tests
- *(upcalls)* Add OBJ_add_sigid upcall and usage
- *(mldsa)* Register all ML-DSA OIDs and sigids. Enable all tests.
- *(tests)* Use explicit testing mock CoreDispatch
- *(deps)* Update openssl_provider_forge to v0.8.4

### 🚜 Refactor

- *(encoder)* Move private-key-to-DER-bytes conversion to its own function
- *(encoder)* Move SPKI-to-DER-bytes conversion to its own function
- *(adapters/decoder)* Register decoders in register_algorithms function
- *(encoder)* Use the transcoders module from forge with dedicated Encoder trait
- *(tests)* Refactor integration tests for genpkey and certs
- *(pqclean/MLDSA65/encoder)* Simplify PrivateKeyInfo encoding logic
- *(pqclean/MLDSA65/decoder)* Improve SPKI decoding and key handling
- *(pqclean/MLDSA65/encoder)* Unify SPKI encoding and simplify BIO writes
- *(pqclean)* Improve debug logging for MLDSA65
- *(upcalls)* Move BIO_read_ex/write_ex to upcalls.rs
- *(upcalls)* Move OBJ_ upcalls to adapter and use module constants
- *(upcalls)* Update obj_sigid handling and core dispatch
- *(init)* Move obj_sigid registration to AdaptersHandle
- *(pqclean)* Simplify obj_sigid registration
- *(adapters)* Derive Debug for FinalizedAdaptersHandle
- *(adapters/common)* Move keymgmt_functions to its own file

### 🧪 Testing

- Add openssl integration tests through Cargo
- *(openssl)* Load aurora as a provider
- Algorithms provided by aurora should all include some properties
- *(openssl)* Add helpers and integration tests
- *(openssl_certs)* Add (optional) CAfile verification test
- *(openssl_decode35/mldsa65)* Refactor tests for decoders using openssl 3.5 generated inputs
- *(openssl_certs)* Add pubkey extraction check
- *(openssl_certs)* Limit active gencert tests to MLDSA65
- *(openssl_certs)* !BREAKING! enable verify with cert as CAfile

### ⚙️ Miscellaneous Tasks

- Bump version to 0.8.4-dev for next dev cycle
- *(logging, pqclean/mldsa65)* Demote some debug! logs to trace!
- *(data/asn1/ML-DSA)* Add comment with source link for the ASN.1 module
- *(release)* Bump version to 0.8.4

### Cleanup

- *(encoder)* Rename some encoder functions to specify that they encode to DER

## [0.8.3] - 2025-04-23

### 🚀 Features

- *(pqclean)* Add (mock) ML-DSA-65 keymgmt
- *(pqclean)* Add MLDSA65 keygen and encode/decode
- *(pqclean)* Add signature context management
- *(pqclean)* Implement MLDSA65 message signing
- *(pqclean)* Implement MLDSA65 message verification
- *(pqclean)* Ensure the relevant part of the keypair is available in {sign,verify}_init
- *(pqclean)* Register TLS capabilities for MLDSA65
- *(pqclean/MLDSA65)* Add extra OQS-compatible TLSSigAlg capability
- *(pqclean)* Add skeleton for decoder implementation
- *(pqclean/MLDSA65)* Report settable ctx param
- *(pqclean/MLDSA65)* Implement logic for does_selection()
- *(pqclean/MLDSA65)* Impl TryFrom<*mut c_void> for DecoderContext references
- Wrap BIO_read_ex() and expose it as a method on the provider context
- *(pqclean/MLDSA65)* Implement set_ctx_params() in the decoder
- *(pqclean/MLDSA65)* Store a reference to the provider context in the decoder context
- *(pqclean/MLDSA65)* Implement gettable_params for decoder
- *(pqclean)* Update decoder to support SubjectPublicKeyInfo
- *(pqclean/MLDSA65)* Implement decode
- Enhance OpenSSLProvider with core_dispatch_map
- *(pqclean)* Add from_parts function to KeyPair
- *(pqclean/mldsa/decoder)* Rename decode to decodeSPKI and refactor
- *(pqclean/MLDSA65/keymgmt)* Add load function
- *(pqclean/MLDSA65/keymgmt)* Improve debug formatting for keys
- *(pqclean/MLDSA65)* Re-export key management constants
- *(pqclean/MLDSA65/keymgmt)* Add `TryFrom<*const c_void>` implementation for `&KeyPair`
- *(pqclean/MLDSA65/sig)* [**breaking**] Add digest_verify functions
- *(pqclean/MLDSA65)* Implement digest_sign{,_init}
- *(pqclean/MLDSA65)* Export key data
- *(pqclean/MLDSA65)* Implement decoder for PrivateKeyInfo
- *(pqclean/MLDSA65)* Pretend to support checking whether two keys match
- *(pqclean/MLDSA65)* Check whether two keys match
- *(aurora/forge)* Allow more fine-grained control over definitions exposed from the forge module
- *(aurora/forge)* (disabled) example of how to redefine constants locally for aurora
- *(feature)* Feature-gate for export
- *(pqclean/MLDSA65/decoder)* Add new constructor for DecoderContext
- *(pqclean/mldsa65)* Relegate backend references inside keymgmt

### 🐛 Bug Fixes

- Update OSSLParam usage to new API with Option
- *(dependencies)* Update openssl_provider_forge to v0.8.0
- *(pqclean)* Add mldsa65 as one of the aliases for id-ml-dsa-65
- *(pqclean)* Correct SIGALG capabilities for ML-DSA-65
- *(ci/github)* Add pull_request_target event handling
- *(pqclean/MLDSA65)* Include "input=der" in decoder properties
- Search core dispatch table properly for BIO_read_ex()'s function ID
- *(tests)* Update core_dispatch initialization
- *(pqclean/MLDSA65/decoder)* Adapt ASN.1 parsing logic to encoding in certs from OQS test server
- *(pqclean/MLDSA65/keymgmt)* Add constants and fix get_params
- *(pqclean/MLDSA65/keymgmt)* Fill implementation for OSSL_FUNC_KEYMGMT_HAS
- *(pqclean)* Actually register OSSL_OP_SIGNATURE for MLDSA65
- *(pqclean/MLDSA65)* Generate detached signatures instead of entire signed messages

### 🚜 Refactor

- *(mldsa65)* Simplify key struct definitions
- *(pqclean)* Rename SignatureContext.own_keypair to keypair
- *(pqclean)* Make some keypair things public
- Migrate to modern Rust module file naming convention
- *(adapters)* Simplify TLS group capabilities
- *(adapters)* Simplify `AdapterContext` implementation
- Replace pretty_env_logger with env_logger
- *(pqclean/MLDSA64/decoder)* Simplify error handling in decoder functions
- *(pqclean/MLDSA65)* Store the core dispatch table as a slice
- *(adapters/pqclean)* Use slices for OSSL_DISPATCH arrays
- *(pqclean)* [**breaking**] Consolidate decoder functions
- *(aurora)* [**breaking**] Improve `BIO_read_ex` upcall debug and error handling
- *(logging)* Add target to log macros
- *(pqclean/MLDSA65/keymgmt)* Align with OQS-provider for BITS and SECURITY_BITS values
- *(pqclean/MLDSA65)* Macroize does_selection_fn
- *(decoder)* Use forge for decoder support

### 📚 Documentation

- *(README)* Improve compatibility with rustdoc inclusion
- *(pqclean)* [**breaking**] Update MLDSA65 constants and comments

### 🎨 Styling

- *(pqclean)* Don't use underscore on argument

### 🧪 Testing

- *(pqclean)* Add skeleton of future tests for sign-and-verify
- *(pqclean)* Add test for verification failure with wrong key
- *(pqclean)* Add test for verification failure with tampered signature
- *(pqclean)* Add test for verification failure with tampered message
- *(pqclean/MLDSA65)* Sanity checks on constants
- *(logging)* Ensure env_logger is initialized in test mode when testing

### ⚙️ Miscellaneous Tasks

- Bump version to 0.7.2-dev
- *(ci/github)* Disable lock worflow
- *(ci/github)* Update CODEOWNERS
- *(ci/github)* Limit CodeQL tasks to github-action workflows
- *(ci/github)* Add workflow similar to the gitlab one
- *(LICENSE)* Revise LICENSE to fully conform to Apache-2.0
- *(ci/gitlab)* Add initial GitLab CI configuration
- *(misc)* Add .gitignore to exclude /target directory
- *(ci/gitlab)* Add test-doc job
- *(ci/gitlab)* Add CODEOWNERS file
- Update Cargo.lock dependencies
- Bump version to 0.8.0-dev
- Update Cargo.lock dependencies
- Cargo fmt MLDSA65 keymgmt
- Update local Cargo.lock dependencies
- *(pqclean)* Remove unused import
- *(log)* Update log levels and add emojis
- *(ci)* Add `just test` workflow to github and gitlab
- *(dependencies)* Bump openssl_provider_forge to pre-release nt/v0.8.2-alpha1
- *(dependencies)* Update forge dependency
- Fix spelling (s/dispath/dispatch)
- *(dependencies)* Update forge dependency
- *(dependencies)* Cargo update
- Bump version to 0.8.3 (to match forge version)

### Cleanup

- *(params)* Remove leftover uses of ossl_param_locate_raw()
- *(pqclean)* Remove leftover uses of ossl_param_locate_raw()
- *(adapters)* Remove unused handle parameters
- *(pqclean/MLDSA65)* Refactor SigAlg capability for clarity
- Cleanup `use` statements
- *(pqclean/MLDSA65)* Remove legacy support for OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY
- *(pqclean/MLDSA65/keymgmt)* Mark unused result with `_`
- *(pqclean/MLDSA65/sig)* Disable exposing sign{,_init} and verify{,_init} in dispatch table
- *(pqclean)* Be consistent about SIGNATURE_LEN constant
- *(pqclean/MLDSA65/decoder)* Remove unused decoder functions
- *(pqclean/MLDSA65/decoder)* Remove unused properties field

## [0.7.1] - 2025-02-21

### 🚀 Features

- *(docs)* Add GPG keys for secure communication
- *(params:version)* Aurora now reports its own version
- *(params:buildinfo)* List `git describe --tags` as BUILD INFO

### 🐛 Bug Fixes

- *(build.rs)* Improve error handling for git describe

### 🚜 Refactor

- *(get_params)* Remove `bindings::forbidden` and replace with idiomatic Rust

### ⚙️ Miscellaneous Tasks

- Bump version to 0.7.1-dev
- Bump version to 0.7.1

### Cleanup

- *(get_params)* Misc fixes to error messages

## [0.7.0] - 2025-02-18

### 🚀 Features

- *(doc)* Initial commit with README and license
- Refactor project structure
- Ensure function has expected type when creating dispatch table entry
- *(aurora/adapters/libcrux)* Add description to X25519MLKEM768
- *(adapter/libcrux)* Add KEM functions and update imports
- *(adapters/libcrux)* Add keymgmt function stubs and dispatch table
- *(libcrux/X25519MLKEM768/keymgmt_functions)* Add conditional compilation for gen_set{,table}_params
- *(query)* Handle OSSLParamError in get_capabilities
- Improve error handling replacing From with TryFrom
- *(libcrux)* Replace From with TryFrom for KeyPair
- *(libcrux::X25519MLKEM768)* Refactor encapsulate_init to be more Rusty
- *(libcrux::X25519MLKEM768)* Refactor decapsulate_init to be more Rusty
- *(libcrux)* Rename key functions for clarity
- Refactor encapsulate method in KeyPair
- *(aurora)* Refactor RNG usage in key management functions
- *(kem)* Refactor key management and encapsulation
- *(libcrux)* Add decapsulation support for X25519MLKEM768
- *(libcrux)* Implement TryFrom for GenCTX
- *(libcrux)* Update X25519MLKEM768 to X25519MLKEM768Draft00
- *(libcrux)* Add new KeyPair constructor and tests
- *(tests)* Add full key exchange test
- Add debug and selection support for key management
- Modified import_types_ex function to return HANDLED_KEY_TYPES
- Add conditional private key printing
- Add key management functions for X25519MLKEM768
- *(adapters)* Extract AdapterContextTrait to traits.rs
- *(adapters)* Implement algorithm registration
- *(adapters)* Rename register to register_adapter
- *(adapters/libcrux)* Replace X25519MLKEM768Draft00 with SecP256r1MLKEM768
- Add X25519MLKEM768Draft00 support via libcrux_draft
- *(libcrux)* Add comments on ownership transfer
- Rename rust-openssl-core-provider to openssl_provider_forge
- *(adapters)* Add registration of capabilities in adapters

### 🐛 Bug Fixes

- *(aurora)* Update clippy lint directive
- *(aurora/libcrux)* Fix PROPERTY_DEFINITION
- *(libcrux)* Use correct RNG in key management functions
- *(libcrux)* Add todo for unwrap removal in release builds
- Improve error logging format
- *(keymgmt)* Handle encoded public key in set_params
- *(query)* Replace return value with FAILURE constant
- Update version in Cargo.toml to 0.7.0

### 🚜 Refactor

- Use try_into for conversions in KEM functions
- *(libcrux)* Replace anyhow::Error with custom error
- *(libcrux)* Improve error handling in keymgmt functions
- *(libcrux)* Rename X25519MLKEM768 to X25519MLKEM768Draft00
- *(adapters)* Centralize error handling
- *(adapters)* Rename Contexts to AdaptersHandle
- *(aurora/adapters)* Modularize TLS group capabilities
- *(aurora/query)* Updated `get_capabilities` to use the refactored structure
- Clarify ownership "trick" when updating boxed iterator in hashmap
- *(query.rs)* Simplify OSSLParam initialization
- *(query)* Introduce OSSLCallback for cleaner handling
- *(query)* Introduce conditional capability handling
- *(query)* Simplify capability retrieval logic

### 🧪 Testing

- *(aurora/query)* Test the correctness of the new OSSLParam constructors
- *(adapters)* Disable libcrux adapter initialization

### ⚙️ Miscellaneous Tasks

- Restructure osslparams module
- *(aurora)* Cargo fmt
- *(aurora/src/adapters/libcrux/X25519MLKEM768)* Refactor structure
- *(keymgmt)* Add doc comment for `KeyPair`'s `encapsulate_ex` method
- *(aurora)* Apply `cargo fmt`
- Rename `osslcb` as `ossl_callback`
- *(adapters)* Add empty line between `use` statements and the other statements in the scope

### Broken

- *(keymgmt)* Add encapsulate_ex method to KeyPair
- *(get_rng)* Use OsRng as a temporary workaround in encapsulate_ex

<!-- generated by git-cliff -->

[0.8.5]: https://github.com/QUBIP/aurora/compare/v0.8.4...v0.8.5
[0.8.4]: https://github.com/QUBIP/aurora/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/QUBIP/aurora/compare/v0.7.1...v0.8.3
[0.7.1]: https://github.com/QUBIP/aurora/compare/v0.7.0...v0.7.1
[0.7.1]: https://github.com/QUBIP/aurora/releases/tag/v0.7.0
