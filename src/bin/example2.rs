#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tor_controller;

use tor_controller::process::TorProcess;

fn main() {
    env_logger::init().unwrap();
    TorProcess::new().torrc_path("torrc").launch().unwrap();
}
