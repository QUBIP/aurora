use std::error::Error;
use std::process::Command;

fn get_git_describe() -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(&["describe", "--tags"])
        .output()
        .expect("Failed to execute git describe");

    if !output.status.success() {
        println!("cargo:warning=Failed to get git describe");
        return Err(format!("git describe failed with status: {}", output.status).into());
    }

    let git_describe = String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 output")
        .trim()
        .to_string();

    Ok(git_describe)
}

fn main() {
    let git_describe = get_git_describe().unwrap();
    println!("cargo:rustc-env=CARGO_GIT_DESCRIBE={}", git_describe);
}
