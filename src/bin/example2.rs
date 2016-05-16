#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tor_controller;

use tor_controller::process;

fn main() {
    env_logger::init().unwrap();
    process::launch_tor().unwrap();
}
