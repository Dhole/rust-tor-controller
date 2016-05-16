use std::io;
use std::process::{Command, Stdio};
use std::io::{BufReader, BufRead};

#[derive(Debug)]
pub enum Error {
    Process(io::Error),
    InvalidLogLine,
}

// parameters:
// tor_cmd str
// args list str
// torrc_path str
// completion_percent int
// timeout int
pub fn launch_tor() -> Result<(), Error> {
    let tor = try!(Command::new("tor")
                       .stdin(Stdio::piped())
                       .stdout(Stdio::piped())
                       .stderr(Stdio::piped())
                       .spawn()
                       .map_err(|err| Error::Process(err)));
    let mut stdout = BufReader::new(tor.stdout.unwrap());

    let timestamp_len = "May 16 02:50:08.792".len();
    let mut raw_line = String::new();
    while try!(stdout.read_line(&mut raw_line).map_err(|err| Error::Process(err))) > 0 {
        if raw_line.len() < timestamp_len + 1 {
            return Err(Error::InvalidLogLine);
        }
        {
            let timestamp = &raw_line[..timestamp_len];
            let line = &raw_line[timestamp_len + 1..raw_line.len() - 1];
            match line.split(' ').nth(0) {
                Some("[notice]") => (),
                Some("[warn]") => (),
                Some("[err]") => (),
                _ => (),
            }
            debug!("{} {}", timestamp, line);
        }
        raw_line.clear();
    }
    Ok(())
}
