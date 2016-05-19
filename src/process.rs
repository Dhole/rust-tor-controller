extern crate regex;

use std::io;
use std::process::{Command, Stdio, Child};
use std::io::{BufReader, BufRead};
use regex::Regex;

#[derive(Debug)]
pub enum Error {
    Process(io::Error),
    Tor(String, Vec<String>),
    InvalidLogLine,
    InvalidBootstrapLine(String),
    Regex(regex::Error),
}

#[derive(Debug)]
pub struct TorProcess {
    tor_cmd: String,
    args: Vec<String>,
    torrc_path: Option<String>,
    completion_percent: u8,
    timeout: u32,
}

impl TorProcess {
    pub fn new() -> Self {
        TorProcess {
            tor_cmd: "tor".to_string(),
            args: vec![],
            torrc_path: None,
            completion_percent: 100 as u8,
            timeout: 0 as u32,
        }
    }

    pub fn tor_cmd(&mut self, tor_cmd: &str) -> &mut Self {
        self.tor_cmd = tor_cmd.to_string();
        self
    }

    pub fn torrc_path(&mut self, torrc_path: &str) -> &mut Self {
        self.torrc_path = Some(torrc_path.to_string());
        self
    }

    pub fn arg(&mut self, arg: String) -> &mut Self {
        self.args.push(arg);
        self
    }

    pub fn args(&mut self, args: Vec<String>) -> &mut Self {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub fn completion_percent(&mut self, completion_percent: u8) -> &mut Self {
        self.completion_percent = completion_percent;
        self
    }

    pub fn timeout(&mut self, timeout: u32) -> &mut Self {
        self.timeout = timeout;
        self
    }

    pub fn launch(&self) -> Result<(), Error> {
        let mut tor = Command::new(&self.tor_cmd);
        if let Some(ref torrc_path) = self.torrc_path {
            tor.args(&vec!["-f", torrc_path]);
        }
        let mut tor_process = try!(tor.args(&self.args)
                                      .stdin(Stdio::piped())
                                      .stdout(Stdio::piped())
                                      .stderr(Stdio::piped())
                                      .spawn()
                                      .map_err(|err| Error::Process(err)));
        let mut stdout = BufReader::new(tor_process.stdout.unwrap());

        let re_bootstrap = try!(Regex::new(r"^\[notice\] Bootstrapped (?P<perc>[0-9]+)%: ")
                                    .map_err(|err| Error::Regex(err)));

        let timestamp_len = "May 16 02:50:08.792".len();
        let mut raw_line = String::new();
        let mut warnings = Vec::new();
        while try!(stdout.read_line(&mut raw_line).map_err(|err| Error::Process(err))) > 0 {
            if raw_line.len() < timestamp_len + 1 {
                return Err(Error::InvalidLogLine);
            } else {
                let timestamp = &raw_line[..timestamp_len];
                let line = &raw_line[timestamp_len + 1..raw_line.len() - 1];
                debug!("{} {}", timestamp, line);
                match line.split(' ').nth(0) {
                    Some("[notice]") => {
                        if let Some("Bootstrapped") = line.split(' ').nth(1) {
                            println!("{}", line);
                            let cap = try!(re_bootstrap.captures(line)
                                        .ok_or(Error::InvalidBootstrapLine("A".to_string())));
                            let perc_srt = try!(cap.name("perc")
                                        .ok_or(Error::InvalidBootstrapLine("B".to_string())));
                            let perc = try!(perc_srt.parse::<u8>().map_err(|_| {
                                Error::InvalidBootstrapLine(line.to_string())
                            }));
                            if perc >= self.completion_percent {
                                break;
                            }
                        }
                    }
                    Some("[warn]") => warnings.push(line.to_string()),
                    Some("[err]") => return Err(Error::Tor(line.to_string(), warnings)),
                    _ => (),
                }
            }
            raw_line.clear();
        }
        // tor_process.kill().unwrap();
        Ok(())
    }
}
