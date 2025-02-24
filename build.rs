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

fn main() {
    let git_describe = get_git_describe().unwrap_or_else(|e| {
        println!("cargo:warning=Failed to get git describe");
        eprintln!("Error was {e:?}");
        "FAILED_TO_GATHER_GIT_DESCRIBE".to_string()
    });
    println!("cargo:rustc-env=CARGO_GIT_DESCRIBE={}", git_describe);
}
