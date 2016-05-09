#[macro_use]
extern crate log;
extern crate env_logger;
extern crate regex;
extern crate rustc_serialize;
extern crate crypto;
extern crate rand;

use std::fmt;
use std::num;
use std::path::Path;
use std::net::{SocketAddr, TcpStream, Shutdown};
use std::io;
use std::io::{Read, Write};
// use std::str;
use std::io::{BufReader, BufRead, BufWriter};
// use std::option::Option;
use std::collections::HashMap;
use std::fs::File;

use regex::Regex;
use rustc_serialize::hex;
use rustc_serialize::hex::{ToHex, FromHex};
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::mac::Mac;
use crypto::util::fixed_time_eq;
use rand::Rng;

// Gives val from Some(val) or returns Err(Error::Reply($rep_err))
macro_rules! some_or_rep_err {
    ($expr:expr, $rep_err:expr) => (match $expr {
        Some(val) => val,
        None => {
            return Err(Error::Reply($rep_err));
        }
    })
}

// Gives the $re regex capture of $str or returns Reply(RegexCapture) error
macro_rules! re_cap_or_err {
    ($re:expr, $str:expr) => (match $re.captures($str) {
        Some(val) => val,
        None => {
            return Err(Error::ParseReply(ParseReplyError::RegexCapture));
        }
    })
}

// Gives the $name found in $cap regex capture or returns Reply(MissingField) error
macro_rules! cap_name_or_err {
    ($cap:expr, $name:expr) => (match $cap.name($name) {
        Some(val) => val,
        None => {
            return Err(Error::ParseReply(ParseReplyError::MissingField));
        }
    })
}

// enum Auth {
//    None,
//    Cookie(Path),
//    HashPass(&str),
// }

// enum Connection {
//    Tcp(SocketAddr),
//    Unix(Path),
// }

#[derive(Debug)]
enum ReplyStatus {
    Positive,
    TempNegative,
    PermNegative,
    Async,
    Unknown,
}

#[derive(Debug)]
struct ReplyLine {
    reply: String,
    data: Option<String>,
}

#[derive(Debug)]
struct Reply {
    //    code: u16,
    //    status: ReplyStatus,
    lines: Vec<ReplyLine>,
}

#[derive(Debug)]
enum AuthMethod {
    Null,
    HashedPassword,
    Cookie,
    SafeCookie,
}

#[derive(Debug)]
struct ProtocolInfo {
    protocol_info_ver: u8,
    tor_ver: String,
    auth_methods: Vec<AuthMethod>,
    cookie_files: Vec<String>,
}

#[derive(Debug)]
struct AuthChallenge {
    server_hash: [u8; 32],
    server_nonce: [u8; 32],
}

struct Connection<T: Read + Write> {
    raw_stream: T,
    buf_reader: BufReader<T>,
    buf_writer: BufWriter<T>,
}

struct Controller<T: Read + Write> {
    con: Connection<T>, /*    auth: Auth,
                         *    connection: Connection,
                         *    hash_pass: Option<&str>, */
}

#[derive(Debug)]
enum Error {
    Stream(io::Error),
    StringParse(num::ParseIntError),
    Regex(regex::Error),
    RawReply(RawReplyError),
    ParseReply(ParseReplyError),
    Auth(AuthError),
    Reply(ReplyError),
}

#[derive(Debug)]
enum RawReplyError {
    NonNumericStatusCode(num::ParseIntError),
    VaryingStatusCode,
    InvalidReplyMode,
    InvalidReplyLine,
    InvalidStatusCode,
    InvalidReply,
}

#[derive(Debug)]
enum ParseReplyError {
    MissingField,
    ParseIntError(num::ParseIntError),
    RegexCapture,
    FromHexError(hex::FromHexError),
    KeyNotFound,
}

#[derive(Debug)]
struct ReplyError {
    code: u16,
    status: ReplyStatus,
    line: String,
}

#[derive(Debug)]
enum AuthError {
    ServerNotVerified,
    AuthFailed(ReplyError),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Stream(err)
    }
}

// impl From<num::ParseIntError> for Error {
//    fn from(err: num::ParseIntError) -> Self {
//        Error::StringParse(err)
//    }
// }

impl From<regex::Error> for Error {
    fn from(err: regex::Error) -> Self {
        Error::Regex(err)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::ParseReply(ParseReplyError::FromHexError(err))
    }
}

impl Controller<TcpStream> {
    fn from_port(port: u16) -> Result<Controller<TcpStream>, io::Error> {
        let raw_stream = try!(TcpStream::connect(("127.0.0.1", port)));
        let buf_reader = BufReader::new(try!(raw_stream.try_clone()));
        let buf_writer = BufWriter::new(try!(raw_stream.try_clone()));
        Ok(Controller {
            con: Connection {
                raw_stream: raw_stream,
                buf_reader: buf_reader,
                buf_writer: buf_writer,
            },
        })
    }
}

impl<T: Read + Write> Controller<T> {
    fn authenticate(&mut self) -> Result<(), Error> {
        let protocolinfo = try!(self.cmd_protocolinfo());

        let mut rng = rand::thread_rng();
        let client_nonce = rng.gen::<[u8; 32]>();
        let authchallenge = try!(self.cmd_authchallenge(&client_nonce));
        let mut cookie_file = try!(File::open(protocolinfo.cookie_files[0].clone()));
        let mut cookie = Vec::new();
        try!(cookie_file.read_to_end(&mut cookie));
        let sha256 = Sha256::new();

        // First we compute the hmac that the server should have sent us, to check its validity.
        let mut hmac = Hmac::new(sha256,
                                 b"Tor safe cookie authentication server-to-controller hash");
        hmac.input(cookie.as_slice());
        hmac.input(&client_nonce);
        hmac.input(&authchallenge.server_nonce);
        let hmac_res = hmac.result();
        let pwd = hmac_res.code();

        if !fixed_time_eq(pwd, &authchallenge.server_hash) {
            return Err(Error::Auth(AuthError::ServerNotVerified));
        }

        // We then compute the client's hmac in order to authenticate ourselves.
        let mut hmac = Hmac::new(sha256,
                                 b"Tor safe cookie authentication controller-to-server hash");
        hmac.input(cookie.as_slice());
        hmac.input(&client_nonce);
        hmac.input(&authchallenge.server_nonce);
        let hmac_res = hmac.result();
        let pwd = hmac_res.code();

        match self.cmd_authenticate(pwd) {
            Ok(_) => Ok(()),
            Err(Error::Reply(rep_err)) => Err(Error::Auth(AuthError::AuthFailed(rep_err))),
            Err(err) => Err(err),
        }
    }

    fn raw_cmd(&mut self, cmd: &str) -> Result<Reply, Error> {
        debug!("{}", cmd);
        try!(self.con.buf_writer.write_all(cmd.as_bytes()));
        try!(self.con.buf_writer.write_all(b"\r\n"));
        try!(self.con.buf_writer.flush());

        let mut raw_line = String::new();
        let mut reply_lines = Vec::new();
        let mut multi_line = false;
        let mut multi_line_reply = String::new();
        let mut multi_line_data = String::new();
        let mut status_code_str = String::new();
        let mut status_code = 0 as u16;

        while try!(self.con.buf_reader.read_line(&mut raw_line)) > 0 {
            if multi_line {
                if raw_line == ".\r\n" {
                    multi_line = false;
                    debug!("\n{}", multi_line_data);
                    reply_lines.push(ReplyLine {
                        reply: multi_line_reply.to_string(),
                        data: Some(multi_line_data.to_string()),
                    });
                    multi_line_data.clear();
                } else {
                    // Store the multi line reply, replacing "\r\n" by "\n"
                    multi_line_data.push_str(&raw_line[..raw_line.len() - 2]);
                    multi_line_data.push_str("\n");
                }
            } else {
                // A sinle line reply line should be at least "XYZ_\r\n"
                if raw_line.len() < 6 {
                    return Err(Error::RawReply(RawReplyError::InvalidReplyLine));
                }
                let code = &raw_line[..3];
                let mode = &raw_line[3..4];
                let line = &raw_line[4..raw_line.len() - 2]; // remove status code, mode and "\r\n"
                debug!("{}{}{}", code, mode, line);
                if mode != "+" {
                    reply_lines.push(ReplyLine {
                        reply: line.to_string(),
                        data: None,
                    });
                }

                if status_code_str == "" {
                    status_code_str = String::from(code);
                    status_code = try!(status_code_str.parse::<u16>().map_err(|err| {
                        Error::RawReply(RawReplyError::NonNumericStatusCode(err))
                    }));
                } else {
                    // TODO Parse Async replies here
                    if code != status_code_str {
                        return Err(Error::RawReply(RawReplyError::VaryingStatusCode));
                    }
                }
                match mode {
                    "-" => (), // Single line
                    " " => break, // End of reply
                    "+" => {
                        // Multiple line
                        multi_line = true;
                        multi_line_reply = line.to_string();
                    }
                    _ => return Err(Error::RawReply(RawReplyError::InvalidReplyMode)),
                }
            }
            raw_line.clear();
        }

        let status = match status_code_str.chars().nth(0) {
            Some('2') => return Ok(Reply { lines: reply_lines }),
            Some('4') => ReplyStatus::TempNegative,
            Some('5') => ReplyStatus::PermNegative,
            Some('6') => ReplyStatus::Async,
            _ => return Err(Error::RawReply(RawReplyError::InvalidStatusCode)),
        };

        Err(Error::Reply(ReplyError {
            code: status_code,
            status: status,
            line: reply_lines[0].reply.clone(),
        }))

        //        if let Some(reply_line) = reply_lines.iter().nth(0) {
        //            return Err(Error::Reply(ReplyError {
        //                code: status_code,
        //                status: status,
        //                line: reply_line.reply.clone(),
        //            }));
        //        } else {
        //            return Err(Error::RawReply(RawReplyError::InvalidReply));
        //        }
    }

    fn cmd_protocolinfo(&mut self) -> Result<ProtocolInfo, Error> {
        let reply = try!(self.raw_cmd("PROTOCOLINFO"));
        // regex for QuotedString = (\\.|[^\"])*
        let re_protocolinfo = try!(Regex::new("^PROTOCOLINFO (?P<version>[0-9]+)$"));
        let re_tor_version = try!(Regex::new("^VERSION Tor=\"(?P<tor_version>(\\.|[^\"])*)\"[ ]*\
                                        (?P<opt_arguments>.*)$"));
        let re_auth = try!(Regex::new("^AUTH METHODS=(?P<auth_methods>[A-Z,]+)[ ]*\
                                 (?P<maybe_cookie_files>.*)$"));
        let re_cookie_file = try!(Regex::new("COOKIEFILE=\"(?P<cookie_file>(\\.|[^\"])*)\""));

        let prot_inf = re_cap_or_err!(re_protocolinfo, reply.lines[0].reply.as_str());
        let version_str = cap_name_or_err!(prot_inf, "version");
        let version = try!(version_str.parse::<u8>()
                                      .map_err(|err| {
                                          Error::ParseReply(ParseReplyError::ParseIntError(err))
                                      }));
        match version {
            1 => (),
            _ => panic!("Version {} not supported", version),
        }

        let mut tor_version = String::new();
        let mut cookie_files = Vec::new();
        let mut auth_methods = Vec::new();

        for line in reply.lines.iter().skip(1) {
            match line.reply.split(' ').nth(0) {
                Some("AUTH") => {
                    let auth = re_cap_or_err!(re_auth, &line.reply);
                    auth_methods = cap_name_or_err!(auth, "auth_methods")
                                       .split(',')
                                       .map(|x| match x {
                                           "NULL" => AuthMethod::Null,
                                           "HASHEDPASSWORD" => AuthMethod::HashedPassword,
                                           "COOKIE" => AuthMethod::Cookie,
                                           "SAFECOOKIE" => AuthMethod::SafeCookie,
                                           _ => panic!("Auth method {} not supported", x),
                                       })
                                       .collect::<Vec<_>>();
                    let maybe_cookie_files = cap_name_or_err!(auth, "maybe_cookie_files");
                    for caps in re_cookie_file.captures_iter(maybe_cookie_files) {
                        cookie_files.push(cap_name_or_err!(caps, "cookie_file").to_string());
                    }
                }
                Some("VERSION") => {
                    let ver = re_cap_or_err!(re_tor_version, &line.reply);
                    tor_version = cap_name_or_err!(ver, "tor_version").to_string();
                    let opt_arguments = cap_name_or_err!(ver, "opt_arguments");
                }
                Some("OK") => (), // End of PROTOCOLINFO reply
                _ => (), // Unrecognized InfoLine
            }
        }
        Ok(ProtocolInfo {
            protocol_info_ver: version,
            tor_ver: tor_version,
            auth_methods: auth_methods,
            cookie_files: cookie_files,
        })
    }

    fn cmd_authchallenge(&mut self, client_nonce: &[u8; 32]) -> Result<AuthChallenge, Error> {
        let reply = try!(self.raw_cmd(format!("AUTHCHALLENGE SAFECOOKIE {}",
                                              client_nonce.to_hex())
                                          .as_str()));
        let re_authchallenge = try!(Regex::new("^AUTHCHALLENGE \
                                           SERVERHASH=(?P<server_hash>[0-9A-F]{64}) \
                                           SERVERNONCE=(?P<server_nonce>[0-9A-F]{64})$"));
        let server_challenge = re_cap_or_err!(re_authchallenge, reply.lines[0].reply.as_str());
        let server_hash = cap_name_or_err!(server_challenge, "server_hash");
        let server_nonce = cap_name_or_err!(server_challenge, "server_nonce");

        let mut res = AuthChallenge {
            server_hash: [0; 32],
            server_nonce: [0; 32],
        };
        res.server_hash.clone_from_slice(try!(server_hash.from_hex()).as_slice());
        res.server_nonce.clone_from_slice(try!(server_nonce.from_hex()).as_slice());

        Ok(res)
    }

    // So far we only support one keyword
    fn cmd_getinfo(&mut self, info_key: &str) -> Result<String, Error> {
        let reply = try!(self.raw_cmd(format!("GETINFO {}", info_key).as_str()));
        let reply_line = &reply.lines[0];
        if !(reply_line.reply.starts_with(info_key) &&
             reply_line.reply.chars().nth(info_key.len()) == Some('=')) {
            return Err(Error::ParseReply(ParseReplyError::KeyNotFound));
        }
        match &reply_line.data {
            &Some(ref data) => Ok(data.clone()),
            &None => Ok(reply_line.reply[info_key.len() + 1..].to_string()),
        }
    }

    fn cmd_authenticate(&mut self, pwd: &[u8]) -> Result<Reply, Error> {
        self.raw_cmd(format!("AUTHENTICATE {}", pwd.to_hex()).as_str())
    }
    //    fn connect(mut &self) {
    //        match self.connection {
    //            Tcp(addr) => self.stream = TcpStream::connect(addr).unwrap(),
    //            Unix(path) => unimplemented!(),
    //        }
    //    }
    //    fn close(mut &self) {
    //        self.stream.shutdown(Shutdown::Both).unwrap();
    //    }
}

fn main() {
    env_logger::init().unwrap();

    info!("Starting Tor Controller!");
    let mut controller = Controller::from_port(9051).unwrap();
    // controller.assert("PROTOCOLINFO");
    controller.authenticate().unwrap();
    // controller.raw_cmd("GETINFO version md/name/moria1 md/name/GoldenCapybara").unwrap();
    println!("{:?}", controller.raw_cmd("GETINFO md/name/GoldenCapybara"));
    println!("{:?}", controller.cmd_getinfo("version"));
    println!("{:?}", controller.cmd_getinfo("md/name/moria1"));
    println!("{:?}", controller.cmd_getinfo("md/name/GoldenCapybara"));
    println!("{:?}", controller.cmd_getinfo("traffic/read"));
    println!("{:?}", controller.cmd_getinfo("traffic/written"));
    println!("{:?}", controller.cmd_getinfo("foo"));
    controller.raw_cmd("FOO");
    controller.raw_cmd("BAR");
    controller.raw_cmd("QUIT").unwrap();
    //    controller.write("PROTOCOLINFO\r\n");
    //    controller.write("PROTOCOLINFO\r\n");
}
