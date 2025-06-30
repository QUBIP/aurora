use std::env;
use std::error::Error;
use std::process::Command;

fn get_git_describe() -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(["describe", "--tags"])
        .output()
        .expect("Failed to execute git describe");

    if !output.status.success() {
        return Err(format!("git describe failed with status: {}", output.status).into());
    }

    let git_describe = match String::from_utf8(output.stdout) {
        Ok(str) => str.trim().to_string(),
        Err(e) => return Err(format!("Invalid UTF-8 output: {e:?}").into()),
    };

    Ok(git_describe)
}

fn compile_with_rasn() -> Result<(), Box<dyn Error>> {
    use rasn_compiler::prelude::*;
    use std::path::PathBuf;

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = out_path.join("rasn-generated.rs");

    eprintln!("rasn-compiler output to be written at {out_file:?}");

    // Initialize the compiler with the rust/rasn backend.
    // To use the typescript backend, initialize the compiler using
    // `Compiler::<TypescriptBackend, _>::new()`
    match Compiler::<RasnBackend, _>::new()
        // add a single ASN1 source file
        .add_asn_by_path(PathBuf::from("data/asn1/X509-ML-DSA-2025.asn"))
        // add several ASN1 source files
        //.add_asn_sources_by_path(
        //    vec![PathBuf::from("spec_2.asn"), PathBuf::from("spec_3.asn")].iter(),
        //)
        // set an output path for the generated rust code
        .set_output_path(out_file)
        // you may also compile literal ASN1 snippets
        //.add_asn_literal(
        //    format!(
        //        "TestModule DEFINITIONS AUTOMATIC TAGS::= BEGIN {} END",
        //        "My-test-integer ::= INTEGER (1..128)"
        //    )
        //)
        .compile()
    {
        Ok(warnings) => {
            /* handle compilation warnings */
            for w in warnings {
                println!("cargo:warning=rasn-compiler issued {w:?}");
            }
            Ok(())
        }
        Err(error) => {
            /* handle unrecoverable compilation error */
            panic!("rasn-compiler failed with: {error:?}")
        }
    }
}

fn main() {
    let git_describe = get_git_describe().unwrap_or_else(|e| {
        println!("cargo:warning=Failed to get git describe");
        eprintln!("Error was {e:?}");
        "FAILED_TO_GATHER_GIT_DESCRIBE".to_string()
    });
    compile_with_rasn().expect("rasn-compiler failed");
    println!("cargo:rustc-env=CARGO_GIT_DESCRIBE={}", git_describe);
}
