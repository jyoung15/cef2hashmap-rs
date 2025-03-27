use crate::{
    Error, Result,
    util::{count_unescaped_chars, escape_rsplitn, escape_split},
};
use std::{borrow::Cow, collections::HashMap};

const CEF_HEADERS: [&str; 6] = [
    "deviceVendor",
    "deviceProduct",
    "deviceVersion",
    "signatureId",
    "name",
    "severity",
];

#[derive(Clone, Debug, Default)]
pub struct CefLine {
    pub syslog_priority: Option<String>,
    pub syslog_facility: Option<String>,
    pub syslog_severity: Option<String>,
    pub at: Option<String>,
    pub ahost: Option<String>,
    pub cef_header: HashMap<String, String>,
    pub cef_ext: String,
}

/// A Simple CEF Parser to a Standardised `HashMap`
pub trait CefToHashMap {
    /// Converts a CEF &str or String into a `HashMap`.
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
    /// # Errors
    ///
    /// This function will return an error if it fails to generate a `HashMap`
    fn to_hashmap(&self, preserve_orig: bool) -> Result<HashMap<String, String>>;
}

impl CefToHashMap for &str {
    fn to_hashmap(&self, preserve_orig: bool) -> Result<HashMap<String, String>> {
        cef_to_map(self, preserve_orig)
    }
}

impl CefToHashMap for String {
    fn to_hashmap(&self, preserve_orig: bool) -> Result<HashMap<String, String>> {
        cef_to_map(self, preserve_orig)
    }
}

/// Convert the CEF String into `HashMap`
fn cef_to_map(cef_str: &str, preserve_orig: bool) -> Result<HashMap<String, String>> {
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
    if let Some(pri) = parsed.syslog_severity {
        // syslog severity available
        map.insert("syslog_severity".to_string(), pri);
    }
    if let Some(pri) = parsed.syslog_priority {
        // syslog priority available
        map.insert("syslog_priority".to_string(), pri);
    }
    if !parsed.cef_ext.is_empty() {
        // get the cef extension
        map.extend(parse_cef_ext(&parsed.cef_ext)?);
    }
    if preserve_orig {
        // Preserve the raw log cef str
        map.insert("rawEvent".to_string(), cef_str.trim().to_string());
    }

    Ok(map)
}

/// Like `str::split_once` but ignore case and take multiple split patterns. First matching pattern is used.
fn isplit_once<'a>(text: &'a str, patterns: &[&str]) -> Option<(&'a str, &'a str)> {
    let split = *patterns
        .iter()
        .find(|s| text.to_ascii_lowercase().contains(&s.to_ascii_lowercase()))?;

    let split_lower = split.to_ascii_lowercase();
    let text_lower = text.to_ascii_lowercase();

    text_lower
        .find(&split_lower)
        .and_then(|index| text.split_at_checked(index))
        .and_then(|(left, right)| {
            right
                .split_at_checked(split_lower.len())
                .map(|rsplit| (left, rsplit))
        })
        .map(|(left, (_, right))| (left, right))
}

/*
From "Implementing ArcSight Common Event Format (CEF) - Version 27".

Syslog with CEF:
  <Syslog_prefix> <CEF_header>|[Extension]

CEF Header:
  CEF:Version|Vendor|Product|Version|Message ID|Name|Severity|

Extension Field:
  - An event can contain any number of key-value pairs in any order, separated by spaces (" "). If a field contains a space, such as a file name, this is valid and can be logged in exactly that manner
  - If there are multiple spaces before a key, all spaces but the last space are treated as trailing spaces in the prior value in the key. If you need trailing spaces, use multiple spaces, otherwise, use one space between the end of a value and the start of the following key.
  - Trailing spaces are not preserved for the final key-value pair in the extension. It is highly recommended to not utilize leading or trailing spaces in CEF events unless absolutely necessary. If that is the case, ensure the ordering of key-value pairs in the extension is such that any value with trailing spaces is not the final value.
  - Extension values must follow the escape character guidelines defined for encoding symbols in CEF

Ensure the following when encoding symbols in CEF:
  -  The entire message must be UTF-8 encoded.
  -  Spaces used in the header are valid. Do not encode a space character by using <space>.
  -  If a pipe (|) is used in the header, it must be escaped with a backslash (\). But note that the pipes in the extension do not need escaping. For example:
       Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|detected a \| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1
  -  If a backslash (\) is used in the header or the extension, it must be escaped with another backslash (\). For example:
       Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|detected a \\ in packet|10|src=10.0.0.1 act=blocked a \\ dst=1.1.1.1
  -  If an equal sign (=) is used in the extensions, it has to be escaped with a backslash (\). Equal signs in the header need no escaping. For example:
       Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|detected a = in message|10|src=10.0.0.1 act=blocked a \= dst=1.1.1.1
  -  Multi-line fields can be sent by CEF by encoding the newline character as \n or \r. Note that multiple lines are only allowed in the value part of the extensions. For example:
       Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|Detected a threat. No action needed.|10|src=10.0.0.1 msg=Detected a threat.\n No action needed

NOTABLE OMISSIONS IN THE SPECIFICATION:
  - Does not explicitly state that keys and values in the extension are separated by equal sign (=)
  - No mention of quoting. Quotes have no significance in the CEF format
  - Poor clarity on what is different in CEF 1.x versus CEF 0.x

CEF 0.x vs CEF 1.x differences (from ChatGPT review of specification):
    - In the header, the version number distinguishes them: version 0.x messages begin with “CEF:0|” while 1.x messages begin with “CEF:1|”.
    - Data types for certain fields have been updated: for example, in CEF 0.x the bytesIn and bytesOut fields were strictly integers, whereas in CEF 1.x they can also be long values.
    - IP address fields in CEF 0.x supported only IPv4 addresses, but CEF 1.x extends support to include IPv6 addresses.

*/

/// Parse the given cef string to a struct of fields
/// which will further be used for forming the map with ease
pub fn parse_cef_line(s: &str) -> Result<CefLine> {
    // In rust, the &str type guarantees UTF-8 encoding, meeting the first requirement above

    // CEF specification does not explicitly state if "CEF" may be lowercase
    if !(s.to_lowercase().contains("cef:0|") || s.to_lowercase().contains("cef:1|")) {
        // if we dont have the cef and version, then we are
        // not dealing with a cef string
        return Err(Error::NotCef);
    }

    if count_unescaped_chars(s, '|') < 7 {
        // Malformed CEF as the header is not complete
        return Err(Error::MalformedCef);
    }

    // resulting struct
    let mut res = CefLine::default();

    // form the cef header
    let (syslog_data, cef_body) = isplit_once(s, &["CEF:0", "CEF:1"]).ok_or(Error::CefSplit)?;
    let header = escape_split(
        escape_rsplitn(cef_body, 2, '|').take(2).collect::<Vec<_>>()[1],
        '|',
    )
    .skip(1)
    .map(|x| x.trim().to_string());

    res.cef_header = CEF_HEADERS
        .into_iter()
        .map(ToString::to_string)
        .zip(header)
        .collect();

    // form the cef extension
    res.cef_ext = escape_rsplitn(cef_body, 2, '|').take(2).collect::<Vec<_>>()[0].to_string();

    // we mostly have syslog information
    let syslog_data = syslog_data.trim();
    let mut data;
    // we might have syslog facility & priority to extract
    if syslog_data.starts_with('<') && syslog_data.contains('>') {
        let pri = &syslog_data[1..syslog_data.find('>').ok_or(Error::CharFind('>'))?];
        let parsed = pri.parse::<i16>()?;
        res.syslog_facility = Some((parsed >> 3).to_string());
        res.syslog_severity = Some((parsed & 7).to_string());
        res.syslog_priority = Some(pri.to_string());
        data = &syslog_data[syslog_data.find('>').ok_or(Error::CharFind('>'))? + 1..];
        if data.starts_with("1 ") {
            // assuming that version is always "1" for RFC 5424
            data = &data[2..];
        }
    } else {
        // no syslog facility & priority
        data = syslog_data;
    }

    // see if host and/or datetime is found and extract
    // 1 space means we have hostname/ip and/or datetime
    // more than 1 space- taking for granted that it could be
    // a human readable datetime string & may/not be hostname
    if data.matches(' ').count().eq(&1) {
        let x = data
            .rsplitn(2, ' ')
            .filter(|&x| !x.is_empty())
            .collect::<Vec<_>>();
        if x.len().eq(&2) {
            // we have hostname & date
            res.ahost = x.first().map(|x| (*x).to_string());
            res.at = x.last().map(|x| (*x).to_string());
        } else if x.len().eq(&1) {
            // Malformed Syslog - We either have a host or datetime
            let ss = x.first().ok_or(Error::MalformedCef)?;
            // need to check if its datetime/hostname
            if is_datetime_str(ss) {
                res.at = Some((*ss).to_string());
            } else {
                res.ahost = Some((*ss).to_string());
            }
        }
    } else if data.matches(' ').count().eq(&2) {
        // assuming that this is only a human date string
        res.at = Some(data.to_string());
    } else if data.matches(' ').count().gt(&2) {
        // assuming that this could be a human datetime string + host
        let x = data
            .rsplitn(2, ' ')
            .filter(|&x| !x.is_empty())
            .collect::<Vec<_>>();
        res.ahost = x.first().map(|x| (*x).to_string());
        res.at = x.last().map(|x| (*x).to_string());
    } else if data.matches(' ').count().eq(&0) {
        // need to check if its datetime/hostname
        if is_datetime_str(data) {
            res.at = Some(data.to_string());
        } else {
            res.ahost = Some(data.to_string());
        }
    }

    Ok(res)
}

fn unescape(s: &str, ch: char) -> Cow<'_, str> {
    let split: Vec<_> = s.split(&format!("\\{ch}")).collect();
    if split.len() == 1 {
        s.into()
    } else {
        split.join(&ch.to_string()).into()
    }
}

fn split_with_escaped(s: &str, ch: char) -> Vec<Cow<'_, str>> {
    let mut res = vec![];
    let mut offset = 0;
    for i in 0..s.len() {
        if s.as_bytes()[i] == ch as u8 {
            if i > 0 && s.as_bytes()[i - 1] == b'\\' {
                continue;
            }
            res.push(unescape(&s[offset..i], ch));
            offset = i + 1;
        }
    }
    res.push(unescape(&s[offset..], ch));
    res
}

/// Parse the CEF Extension
fn parse_cef_ext(s: &str) -> Result<HashMap<String, String>> {
    use crate::util::HasOddNonEmptyCount as _;

    let mut map = HashMap::new();
    let split_by_equalto = split_with_escaped(s, '=');
    if split_by_equalto.is_uneven() {
        return Err(Error::CefExtension("Uneven Key-Value Pairs"));
    }
    let mut key = String::new();
    // go over to take before the last as last is the key
    for s in split_by_equalto.windows(2) {
        let key_t = s[0].split(' ').collect::<Vec<&str>>();
        key = (*key_t
            .last()
            .ok_or(Error::CefExtension("Missing Last Key"))?)
        .to_string();
        let value = s[1]
            .split(' ')
            .collect::<Vec<&str>>()
            .split_last()
            .ok_or(Error::CefExtension("Missing Last Value"))?
            .1
            .join(" ");
        map.insert(key.clone(), value);
    }
    if !&key.is_empty() {
        let (last, _) = split_by_equalto
            .split_last()
            .ok_or(Error::CefExtension("Missing Last Split"))?;
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
        let (_, key) = map
            .remove_entry(&format!("{e}Label"))
            .ok_or(Error::CefExtension("Error Removing Label"))?;
        let (_, value) = map
            .remove_entry(&e)
            .ok_or(Error::CefExtension("Error Removing Extension"))?;
        map.insert(key.replace(' ', ""), value);
    }

    Ok(map)
}

/// Quick dirty way to check and see if a given string could be a datetime str
/// This Logic is for the current library context only (maybe)
/// eg: Feb 19 19:00:00 or 2020-02-19T00:00:00 etc...
fn is_datetime_str(s: &str) -> bool {
    (s.contains(':') && s.contains('-')) || s.contains('-') || s.matches(' ').count().ge(&1)
}
