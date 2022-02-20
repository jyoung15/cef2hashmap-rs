use fancy_regex::Regex;
use std::collections::HashMap;

lazy_static! {
    static ref CEF_HEADER: Regex = Regex::new(
        &[
            r"^(?:(?:<(?P<pri>\d+)>))?",
            r"(?P<date>(?:[a-z]+[ ])?",
            r"(?:[\d :\-T]+\b[ ]?))?.*?",
            r"CEF:0(?:\|(?P<deviceVendor>.*?(?=\|)))?",
            r"(?:\|(?P<deviceProduct>.*?(?=\|)))?",
            r"(?:\|(?P<deviceVersion>.*?(?=\|)))?",
            r"(?:\|(?P<signatureId>.*?(?=\|)))?",
            r"(?:\|(?P<name>.*?(?=\|)))?",
            r"(?:\|(?P<severity>.*?(?=\|)))?",
            r"\|(?P<cef_ext>.*)"
        ]
        .join("")
    )
    .unwrap();
    static ref CEF_EXT: Regex =
        Regex::new(r"[ ]?(?P<key>[^= ]+?)=(?P<value>[^=]*?)(?=(?:[ ][^= ]*?=|$))").unwrap();
}

pub trait CefToHashMap {
    fn to_hashmap(&self) -> HashMap<String, String>;
}

impl CefToHashMap for &str {
    fn to_hashmap(&self) -> HashMap<String, String> {
        cef_to_map(self)
    }
}

impl CefToHashMap for String {
    fn to_hashmap(&self) -> HashMap<String, String> {
        cef_to_map(self)
    }
}

/// Convert the CEF String into HashMap
fn cef_to_map(cef_str: &str) -> HashMap<String, String> {
    let mut header = get_cef_header(cef_str);
    if header.contains_key("cef_ext") {
        let extension = get_cef_ext(header.get("cef_ext").unwrap());
        header.remove("cef_ext");
        header.extend(extension)
    }
    // if found, add the facility & priority/severity from syslog line
    if header.contains_key("pri") {
        let pri = header.get("pri").unwrap().parse::<u8>().unwrap();
        header.remove("pri");
        let facility = (pri >> 3).to_string();
        let priority = (pri & 7).to_string();
        header.insert("facility".to_string(), facility);
        header.insert("priority".to_string(), priority);
    }
    header
}

/// Gets the CEF Header as well as the CEF_Extension in hashmap
fn get_cef_header(cef_str: &str) -> HashMap<String, String> {
    let caps = CEF_HEADER.captures(cef_str).unwrap();
    CEF_HEADER
        .capture_names()
        .flatten()
        .filter_map(|n| Some((n.to_string(), caps.as_ref().unwrap().name(n).unwrap().as_str().to_string())))
        .collect()
}

/// Extracts all the key=value pairs into HashMap from the CEF_Extension
fn get_cef_ext(cef_ext: &str) -> HashMap<String, String> {
    CEF_EXT
        .captures_iter(cef_ext)
        .flat_map(|c| {
            c.into_iter()
                .flat_map(|m| {
                    m.iter()
                        .map(|x| x.unwrap().as_str().trim())
                        .filter(|s| s.contains('='))
                        .collect::<Vec<_>>()
                })
                .map(|s|s.split_at(s.find('=').unwrap()))
                .map(|(k, v)| (k.trim().to_string(), v[1..].trim().to_string()))
                .collect::<HashMap<String, String>>()
        })
        .collect()
}
