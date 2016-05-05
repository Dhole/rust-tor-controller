#[macro_use]
extern crate log;
extern crate env_logger;
extern crate regex;
extern crate rustc_serialize;
extern crate crypto;

use std::fmt;
use std::path::Path;
use std::net::{SocketAddr, TcpStream, Shutdown};
use std::io::{Read, Write};
// use std::str;
use std::io::{BufReader, BufRead, BufWriter};
// use std::option::Option;
use std::collections::HashMap;
use std::fs::File;

use regex::Regex;
use rustc_serialize::hex::{ToHex, FromHex};
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::mac::Mac;

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

impl Controller<TcpStream> {
    fn from_port(port: u16) -> Controller<TcpStream> {
        let raw_stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let buf_reader = BufReader::new(raw_stream.try_clone().unwrap());
        let buf_writer = BufWriter::new(raw_stream.try_clone().unwrap());
        Controller {
            con: Connection {
                raw_stream: raw_stream,
                buf_reader: buf_reader,
                buf_writer: buf_writer,
            },
        }
    }
}

impl<T: Read + Write> Controller<T> {
    fn authenticate(&mut self) {
        let protocolinfo = self.cmd_protocolinfo();
        let client_nonce: &[u8; 32] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                                        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let authchallenge = self.cmd_authchallenge(client_nonce);
        let mut cookie_file = File::open(protocolinfo.cookie_files[0].clone()).unwrap();
        let mut cookie = Vec::new();
        cookie_file.read_to_end(&mut cookie).unwrap();
        let mut sha256 = Sha256::new();
        let mut hmac = Hmac::new(sha256,
                                 b"Tor safe cookie authentication controller-to-server hash");
        hmac.input(cookie.as_slice());
        hmac.input(client_nonce);
        hmac.input(&authchallenge.server_nonce);
        let hmac_res = hmac.result();
        let pwd = hmac_res.code();

        self.cmd_authenticate(pwd);
    }

    fn raw_cmd(&mut self, cmd: &str) -> Vec<String> {
        debug!("{}", cmd);
        self.con.buf_writer.write_all(cmd.as_bytes()).unwrap();
        self.con.buf_writer.write_all(b"\r\n").unwrap();
        self.con.buf_writer.flush().unwrap();
        let mut raw_line = String::new();
        let mut reply = Vec::new();

        // self.con.buf_reader.read_line(&mut raw_line).unwrap();
        // {
        // let line = &raw_line[..raw_line.len()-2];
        // debug!("{}", line);
        // reply.push(line.to_string());
        // }
        //
        // let status_code = &raw_line.clone()[..3];
        // raw_line.clear();
        let status_code_reply = "250";

        while self.con.buf_reader.read_line(&mut raw_line).unwrap() > 0 {
            {
                let line = &raw_line[..raw_line.len() - 2];
                debug!("{}", line);
                reply.push(line.to_string());
                if &line[..3] != status_code_reply {
                    panic!("Reply Error");
                }
                if &line[3..4] == " " {
                    break;
                }
            }
            raw_line.clear();
        }
        reply
    }

    fn cmd_protocolinfo(&mut self) -> ProtocolInfo {
        let reply = self.raw_cmd("PROTOCOLINFO");
        // regex for QuotedString = (\\.|[^\"])*
        let re_protocolinfo = Regex::new("^250-PROTOCOLINFO (?P<version>[0-9]+)$").unwrap();
        let re_tor_version = Regex::new("^250-VERSION \
                                         Tor=\"(?P<tor_version>(\\.|[^\"])*)\"[ ]*\
                                         (?P<opt_arguments>.*)$")
                                 .unwrap();
        let re_auth = Regex::new("^250-AUTH METHODS=(?P<auth_methods>[A-Z,]+)[ ]*\
                                  (?P<maybe_cookie_files>.*)$")
                          .unwrap();
        let re_cookie_file = Regex::new("COOKIEFILE=\"(?P<cookie_file>(\\.|[^\"])*)\"").unwrap();
        let prot_inf = re_protocolinfo.captures(reply[0].as_str()).unwrap();
        let version = prot_inf.name("version").unwrap().parse::<u8>().unwrap();
        match version {
            1 => (),
            _ => panic!("Version {} not supported", version),
        }

        let mut tor_version = String::new();
        let mut cookie_files = Vec::new();
        let mut auth_methods = Vec::new();
        for line in &reply[1..] {
            match line.split(' ').collect::<Vec<_>>()[0] {
                "250-AUTH" => {
                    let auth = re_auth.captures(line).unwrap();
                    auth_methods = auth.name("auth_methods")
                                       .unwrap()
                                       .split(',')
                                       .map(|x| match x {
                                           "NULL" => AuthMethod::Null,
                                           "HASHEDPASSWORD" => AuthMethod::HashedPassword,
                                           "COOKIE" => AuthMethod::Cookie,
                                           "SAFECOOKIE" => AuthMethod::SafeCookie,
                                           _ => panic!("Auth method {} not supported", x),
                                       })
                                       .collect::<Vec<_>>();
                    let maybe_cookie_files = auth.name("maybe_cookie_files").unwrap();
                    for caps in re_cookie_file.captures_iter(maybe_cookie_files) {
                        cookie_files.push(caps.name("cookie_file").unwrap().to_string());
                    }
                    // debug!("Auth methods={:?}", auth_methods);
                    // debug!("Cookie files={:?}", cookie_files);
                }
                "250-VERSION" => {
                    let ver = re_tor_version.captures(line).unwrap();
                    tor_version = ver.name("tor_version").unwrap().to_string();
                    let opt_arguments = ver.name("opt_arguments").unwrap();
                    // debug!("Tor version={}, optional args={}", tor_version, opt_arguments);
                }
                "250" => debug!("OK"), // End of PROTOCOLINFO reply
                _ => (), // Unrecognized InfoLine
            }
        }
        // debug!("version = {}", version);
        ProtocolInfo {
            protocol_info_ver: version,
            tor_ver: tor_version,
            auth_methods: auth_methods,
            cookie_files: cookie_files,
        }
    }

    fn cmd_authchallenge(&mut self, client_nonce: &[u8; 32]) -> AuthChallenge {
        let reply = self.raw_cmd(format!("AUTHCHALLENGE SAFECOOKIE {}", client_nonce.to_hex())
                                     .as_str());
        let re_authchallenge = Regex::new("^250 AUTHCHALLENGE \
                                           SERVERHASH=(?P<server_hash>[0-9A-F]{64}) \
                                           SERVERNONCE=(?P<server_nonce>[0-9A-F]{64})$")
                                   .unwrap();
        let server_challenge = re_authchallenge.captures(reply[0].as_str()).unwrap();
        let server_hash = server_challenge.name("server_hash").unwrap();
        let server_nonce = server_challenge.name("server_nonce").unwrap();

        let mut res = AuthChallenge {
            server_hash: [0; 32],
            server_nonce: [0; 32],
        };
        res.server_hash.clone_from_slice(server_hash.from_hex().unwrap().as_slice());
        res.server_nonce.clone_from_slice(server_nonce.from_hex().unwrap().as_slice());

        res
    }

    fn cmd_authenticate(&mut self, pwd: &[u8]) {
        let reply = self.raw_cmd(format!("AUTHENTICATE {}", pwd.to_hex()).as_str());
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
    let mut controller = Controller::from_port(9051);
    // controller.assert("PROTOCOLINFO");
    let protocolinfo = controller.authenticate();
    // controller.raw_cmd("GETINFO version md/name/moria1 md/name/GoldenCapybara");
    //    controller.write("PROTOCOLINFO\r\n");
    //    controller.write("PROTOCOLINFO\r\n");
}
