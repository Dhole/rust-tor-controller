#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tor_controller;

use tor_controller::process::TorProcess;

fn main() {
    env_logger::init().unwrap();
    let mut tor = TorProcess::new();
    tor.torrc_path("torrc").timeout(1).launch().unwrap();
    // tor.kill().unwrap();
}
