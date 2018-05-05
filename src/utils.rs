use std::io;
use std::process::Command;
use regex;
use regex::Regex;
use std::string;
use regex::Match;

// Gives the $name found in $cap regex capture or returns MissingField error
macro_rules! cap_name_or_err {
    ($cap:expr, $name:expr) => (match $cap.name($name) {
        Some(val) => val.as_str(),
        None => {
            return Err(Error::MissingField);
        }
    })
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct TorVersion {
    major: u16,
    minor: u16,
    micro: u16,
    patch_level: u16,
    status_tag: Option<String>,
    extra_info: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    Regex(regex::Error),
    RegexCapture,
    MissingField,
    Command(io::Error),
    CommandOutput(string::FromUtf8Error),
    TorVersionTooShort,
}

pub fn get_system_tor_version(tor_cmd: Option<&str>) -> Result<TorVersion, Error> {
    let tor_cmd = tor_cmd.unwrap_or("tor");
    let begin = "Tor version ";
    let end = ".\n";
    let output = Command::new(tor_cmd)
        .arg("--version")
        .output()
        .map_err(|err| Error::Command(err))?;
    let tor_version_str = String::from_utf8(output.stdout)
        .map_err(|err| Error::CommandOutput(err))?;
    if tor_version_str.len() < begin.len() + end.len() {
        return Err(Error::TorVersionTooShort);
    }
    let tor_version_str = &tor_version_str[begin.len()..tor_version_str.len() - end.len()];
    parse_tor_version(tor_version_str)
}

pub fn parse_tor_version(tor_version_str: &str) -> Result<TorVersion, Error> {
    let re_tor_version_details = Regex::new("^(?P<major>[0-9]+)[.]\
                                             (?P<minor>[0-9]+)[.]\
                                             (?P<micro>[0-9]+)[.]\
                                             (?P<patch_level>[0-9]+)\
                                             (?P<status_tag>[-][^ ]*)?\
                                             (?P<extra_info> [(].*[)])?$")
        .map_err(|err| Error::Regex(err))?;
    let ver_cap = match re_tor_version_details.captures(tor_version_str) {
        Some(cap) => cap,
        None => return Err(Error::RegexCapture),
    };
    let major = cap_name_or_err!(ver_cap, "major");
    let minor = cap_name_or_err!(ver_cap, "minor");
    let micro = cap_name_or_err!(ver_cap, "micro");
    let patch_level = cap_name_or_err!(ver_cap, "patch_level");
    let status_tag = ver_cap.name("status_tag").map( |m| m.as_str() );
    let extra_info = ver_cap.name("extra_info").map( |m| m.as_str() );

    // At this point the parse should always be sucessfull becuse the regex limit the captured
    // strings to be integer numbers for major, minor, micro and patch_level.
    Ok(TorVersion {
        major: major.parse::<u16>().unwrap(),
        minor: minor.parse::<u16>().unwrap(),
        micro: micro.parse::<u16>().unwrap(),
        patch_level: patch_level.parse::<u16>().unwrap(),
        status_tag: status_tag.map(|s| s[1..].to_string()),
        extra_info: extra_info.map(|s| s[2..s.len() - 1].to_string()),
    })
}

#[cfg(test)]
mod test {
    use super::{parse_tor_version, TorVersion};

    #[test]
    fn test_parse_tor_version() {
        assert_eq!(parse_tor_version("0.2.7.6 (git-605ae665009853bd)").unwrap(),
                   TorVersion {
                       major: 0,
                       minor: 2,
                       micro: 7,
                       patch_level: 6,
                       status_tag: None,
                       extra_info: Some("git-605ae665009853bd".to_string()),
                   });
        assert_eq!(parse_tor_version("0.2.7.6-dev (git-605ae665009853bd)").unwrap(),
                   TorVersion {
                       major: 0,
                       minor: 2,
                       micro: 7,
                       patch_level: 6,
                       status_tag: Some("dev".to_string()),
                       extra_info: Some("git-605ae665009853bd".to_string()),
                   });
        assert_eq!(parse_tor_version("0.1.1.1-alpha").unwrap(),
                   TorVersion {
                       major: 0,
                       minor: 1,
                       micro: 1,
                       patch_level: 1,
                       status_tag: Some("alpha".to_string()),
                       extra_info: None,
                   });
        assert_eq!(parse_tor_version("0.1.2.1-alpha-dev").unwrap(),
                   TorVersion {
                       major: 0,
                       minor: 1,
                       micro: 2,
                       patch_level: 1,
                       status_tag: Some("alpha-dev".to_string()),
                       extra_info: None,
                   });
        assert_eq!(parse_tor_version("0.1.2.1").unwrap(),
                   TorVersion {
                       major: 0,
                       minor: 1,
                       micro: 2,
                       patch_level: 1,
                       status_tag: None,
                       extra_info: None,
                   });
    }
}
