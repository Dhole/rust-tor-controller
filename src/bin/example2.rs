#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tor_controller;

use std::io::BufRead;
use tor_controller::process::TorProcess;

fn main() {
    env_logger::init();
    let mut tor = TorProcess::new();
    tor.torrc_path("torrc").timeout(5).completion_percent(50).launch().unwrap();


    for line in tor.stdout.as_mut().unwrap().lines() {
        println!("{:?}", line);
    }
    // tor.kill().unwrap();
}
