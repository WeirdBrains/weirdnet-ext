//! A test extension. `probe` tries what the sandbox should stop and reports; `crash` exits
//! with an error after the handshake; `echo` sends app events back through a host call;
//! `hang` ignores Stop.

#[cfg(unix)]
mod unix;

fn main() {
    #[cfg(unix)]
    unix::main();
}
