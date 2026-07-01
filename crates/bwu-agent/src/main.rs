#![forbid(unsafe_code)]

use std::{env, process};

fn main() {
    let outcome = bwu_agent::run(env::args().skip(1));
    print!("{}", outcome.stdout);
    eprint!("{}", outcome.stderr);
    process::exit(outcome.code);
}
