use std::ffi::OsStr;
use std::io;
use std::process::{Command, Output};

pub fn run_openssl<I, S>(args: I) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("openssl").args(args).output()
}
