use crate::{Error, Result};
use std::collections::HashMap;

const CEF_HEADERS: [&str; 6] = [
    "deviceVendor",
    "deviceProduct",
    "deviceVersion",
    "signatureId",
    "name",
    "severity",
];

#[derive(Clone, Debug, Default)]
struct CefLine {
    syslog_facility: Option<String>,
    syslog_priority: Option<String>,
    at: Option<String>,
    ahost: Option<String>,
    cef_header: HashMap<String, String>,
    cef_ext: String,
}

/// A Simple CEF Parser to a Standardised HashMap
pub trait CefToHashMap {
    /// Converts a CEF &str or String into a HashMap.
    /// Also accepts syslog strings.
    /// ###
    /// Example CEF Strings:
    /// - <134>2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 suser=Admin
    /// - <134>Feb 14 19:04:54 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1
    /// - CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 suser=Admin
    /// ###
    /// ## Example Usage:
    /// ```rust
    /// use cef2hashmap::CefToHashMap;
    ///
    /// let cef_str = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 suser=Admin";
    /// assert!(cef_str.to_hashmap(true).is_ok())
    /// ```
    fn to_hashmap(&self, keep_raw: bool) -> Result<HashMap<String, String>>;
}

impl CefToHashMap for &str {
    fn to_hashmap(&self, keep_raw: bool) -> Result<HashMap<String, String>> {
        cef_to_map(self, keep_raw)
    }
}

impl CefToHashMap for String {
    fn to_hashmap(&self, keep_raw: bool) -> Result<HashMap<String, String>> {
        cef_to_map(self, keep_raw)
    }
}

/// Convert the CEF String into HashMap
fn cef_to_map(cef_str: &str, keep_raw: bool) -> Result<HashMap<String, String>> {
    // get the initial parsed struct
    let parsed = parse_cef_line(cef_str)?;
    let mut map = parsed.cef_header;

    if let Some(ahost) = parsed.ahost {
        // agent host available
        map.insert("ahost".to_string(), ahost);
    }
    if let Some(at) = parsed.at {
        // agent received time available
        map.insert("at".to_string(), at);
    }
    if let Some(facility) = parsed.syslog_facility {
        // syslog facility available
        map.insert("syslog_facility".to_string(), facility);
    }
    if let Some(pri) = parsed.syslog_priority {
        // syslog priority available
        map.insert("syslog_priority".to_string(), pri);
    }
    if !parsed.cef_ext.is_empty() {
        // get the cef extension
        map.extend(parse_cef_ext(&parsed.cef_ext));
    }
    if keep_raw {
        // Keep the raw log cef str
        map.insert("rawEvent".to_string(), cef_str.trim().to_string());
    }

    Ok(map)
}

/// Parse the given cef string to a struct of fields
/// which will further be used for forming the map with ease
fn parse_cef_line(s: &str) -> Result<CefLine> {
    if !s.to_lowercase().contains("cef:0|") {
        // if we dont have the cef and version, then we are
        // not dealing with a cef string
        return Err(Error::NotCef);
    }
    if s.matches('|').count().lt(&7) {
        // Malformed CEF as the header is not complete
        return Err(Error::MalformedCef);
    }

    // resulting struct
    let mut res = CefLine::default();

    // form the cef header
    let arr = s
        .split("CEF:0")
        .filter(|&x| !x.is_empty())
        .collect::<Vec<_>>();
    let header = arr
        .last()
        .unwrap()
        .rsplitn(2, '|')
        .take(2)
        .collect::<Vec<_>>()[1]
        .split('|')
        .skip(1)
        .map(|x| x.trim().to_string());
    res.cef_header = CEF_HEADERS
        .into_iter()
        .map(|x| x.to_string())
        .zip(header.into_iter())
        .collect();

    // form the cef extension
    res.cef_ext = arr
        .last()
        .unwrap()
        .rsplitn(2, '|')
        .take(2)
        .collect::<Vec<_>>()[0]
        .to_string();

    // we mostly have syslog information
    if arr.len().eq(&2) {
        let syslog_data = arr.first().unwrap().trim();
        let data;
        // we might have syslog facility & priority to extract
        if syslog_data.starts_with('<') && syslog_data.contains('>') {
            let pri = &syslog_data[1..syslog_data.find('>').unwrap()];
            if let Ok(parsed) = pri.parse::<i16>() {
                res.syslog_facility = Some((parsed >> 3).to_string());
                res.syslog_priority = Some((parsed & 7).to_string());
            }
            data = &syslog_data[syslog_data.find('>').unwrap() + 1..];
        } else {
            // no syslog facility & priority
            data = syslog_data;
        }

        // see if host and/or datetime is found and extract
        // 1 space means we have hostname/ip and/or datetime
        // more than 1 space- taking for granted that it could be
        // a human readable datetime string & may/not be hostname
        if data.matches(' ').count().eq(&1) {
            let x = data.rsplitn(2, ' ').filter(|&x| !x.is_empty()).collect::<Vec<_>>();
            if x.len().eq(&2) {
                // we have hostname & date
                res.ahost = x.first().map(|x|x.to_string());
                res.at = x.last().map(|x|x.to_string());
            } else if x.len().eq(&1) {
                // Malformed Syslog - We either have a host or datetime
                let ss = x.first().unwrap();
                // need to check if its datetime/hostname
                if is_datetime_str(ss) {
                    res.at = Some(ss.to_string())
                } else {
                    res.ahost = Some(ss.to_string())
                }
            }
        } else if data.matches(' ').count().eq(&2) {
            // assuming that this is only a human date string
            res.at = Some(data.to_string())
        } else if data.matches(' ').count().gt(&2) {
            // assuming that this could be a human datetime string + host
            let x = data.rsplitn(2, ' ').filter(|&x| !x.is_empty()).collect::<Vec<_>>();
            res.ahost = x.first().map(|x|x.to_string());
            res.at = x.last().map(|x|x.to_string());
        } else if data.matches(' ').count().eq(&0) {
            // need to check if its datetime/hostname
            if is_datetime_str(data) {
                res.at = Some(data.to_string())
            } else {
                res.ahost = Some(data.to_string())
            }
        }
    }

    Ok(res)
}

/// Parse the CEF Extension
fn parse_cef_ext(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let split_by_equalto = s
        .split('=')
        .collect::<Vec<&str>>();
    let mut key = "".to_string();
    // go over to take before the last as last is the key
    for s in split_by_equalto.windows(2) {
        let key_t = s[0].split(' ').collect::<Vec<&str>>();
        key = key_t.last().unwrap().to_string();
        let value = s[1]
            .split(' ')
            .collect::<Vec<&str>>()
            .split_last()
            .unwrap()
            .1
            .join(" ");
        map.insert(key.clone(), value);
    }
    if !&key.is_empty() {
        let (last, _) = split_by_equalto.split_last().unwrap();
        map.insert(key, last.to_string());
    }

    // convert labels as KV pair
    let mut elems = vec![];
    for key in map.keys() {
        if key.ends_with("Label") && map.contains_key(&key[..key.len() - 5]) {
            elems.push(key[..key.len() - 5].to_string());
        }
    }
    for e in elems {
        let (_, key) = map.remove_entry(&format!("{}Label", e)).unwrap();
        let (_, value) = map.remove_entry(&e).unwrap();
        map.insert(key.replace(' ', ""), value);
    }

    map
}

/// Quick dirty way to check and see if a given string could be a datetime str
/// This Logic is for the current library context only (maybe)
/// eg: Feb 19 19:00:00 or 2020-02-19T00:00:00 etc...
fn is_datetime_str(s: &str) -> bool {
    (s.contains(':') && s.contains('-')) || s.contains('-') || s.matches(' ').count().ge(&1)
}
