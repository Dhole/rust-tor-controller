#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tor_controller;

use tor_controller::control::Controller;

fn main() {
    env_logger::init().unwrap();

    info!("Starting Tor Controller!");
    let mut controller = Controller::from_port(9051).unwrap();
    // controller.assert("PROTOCOLINFO");
    controller.authenticate().unwrap();
    // controller.raw_cmd("GETINFO version md/name/moria1 md/name/GoldenCapybara").unwrap();
    println!("{:?}", controller.cmd_getinfo("version"));
    println!("{}", controller.cmd_getinfo("md/name/moria1").unwrap());
    println!("{}",
             controller.cmd_getinfo("md/name/GoldenCapybara").unwrap());
    println!("{:?}", controller.cmd_getinfo("traffic/read"));
    println!("{:?}", controller.cmd_getinfo("traffic/written"));
    println!("{:?}", controller.cmd_getinfo("foo"));
    controller.raw_cmd("QUIT").unwrap();
    //    controller.write("PROTOCOLINFO\r\n");
    //    controller.write("PROTOCOLINFO\r\n");
}
