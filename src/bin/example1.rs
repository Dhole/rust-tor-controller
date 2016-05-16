#[macro_use]
extern crate env_logger;
extern crate tor_controller;

use tor_controller::control::Controller;

fn main() {
    env_logger::init().unwrap();

    let mut controller = Controller::from_port(9051).unwrap();
    controller.authenticate().unwrap();

    let bytes_read = controller.cmd_getinfo("traffic/read").unwrap();
    let bytes_written = controller.cmd_getinfo("traffic/written").unwrap();

    println!("My Tor relay has read {} bytes and written {}.",
             bytes_read,
             bytes_written);
}
