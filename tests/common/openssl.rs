use std::ffi::{OsStr, OsString};
use std::io;
use std::process::{Command, Output};

pub fn run_openssl<I, S>(args: I) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("openssl").args(args).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Explicitly print the output
    println!("--- OpenSSL stdout ---\n{stdout}");
    println!("--- OpenSSL stderr ---\n{stderr}");

    io::Result::Ok(output)
}

#[allow(dead_code)]
fn append_arguments<'a, S1, S2>(
    args: impl Iterator<Item = S1> + 'a,
    extra_args: impl Iterator<Item = S2> + 'a,
) -> impl Iterator<Item = OsString> + 'a
where
    S1: AsRef<OsStr> + 'a,
    S2: AsRef<OsStr> + 'a,
{
    args.map(|a| a.as_ref().to_owned())
        .chain(extra_args.map(|b| b.as_ref().to_owned()))
}

/// Predefined Aurora wrapper: appends `-provider base -provider libaurora`
#[allow(dead_code)]
pub fn run_openssl_with_aurora<I, S>(args: I) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let aurora_args = ["-provider", "base", "-provider", "libaurora"];
    let full_args = append_arguments(args.into_iter(), aurora_args.iter().copied());

    run_openssl(full_args)
}
