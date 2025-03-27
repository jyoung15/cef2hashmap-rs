use crate::CefToHashMap as _;
use crate::to_map::parse_cef_line;

type E = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, E>;

#[test]
fn test_non_cef_string() {
    let s = "this is not a cef string|key=value";
    assert!(s.to_hashmap(false).is_err());
}

#[test]
fn test_malformed_cef_string() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|src=127.0.0.1";
    assert!(s.to_hashmap(false).is_err());
}

#[test]
fn test_string_to_hashmap() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|".to_string();
    assert!(s.to_hashmap(false).is_ok());
}

#[test]
fn test_str_to_hashmap() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    assert!(s.to_hashmap(false).is_ok());
}

#[test]
fn test_with_raw_event() -> Result<()> {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(true);
    assert!(x.is_ok());
    assert!(x?.contains_key("rawEvent"));
    Ok(())
}

#[test]
fn test_without_raw_event() -> Result<()> {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    assert!(!x?.contains_key("rawEvent"));
    Ok(())
}

#[test]
fn test_pri_facility() -> Result<()> {
    let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("syslog_priority"));
    assert!(x.contains_key("syslog_facility"));
    Ok(())
}

#[test]
fn test_no_pri_facility() -> Result<()> {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(!x.contains_key("syslog_priority"));
    assert!(!x.contains_key("syslog_facility"));
    Ok(())
}

#[test]
fn test_host_and_datetime() -> Result<()> {
    let s = "<134>2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("ahost"));
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_host_and_human_datetime() -> Result<()> {
    let s = "<134>Feb 14 19:04:54 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("ahost"));
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_only_datetime() -> Result<()> {
    let s = "<134>2022-02-14T03:17:30-08:00 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("at"));
    assert!(!x.contains_key("ahost"));
    Ok(())
}

#[test]
fn test_only_human_datetime() -> Result<()> {
    let s =
        "<134>Feb 14 19:04:54 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("at"));
    assert!(!x.contains_key("ahost"));
    Ok(())
}

#[test]
fn test_ipv4_and_datetime() -> Result<()> {
    let s = "<134>2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("ahost"));
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_ipv4_and_human_datetime() -> Result<()> {
    let s = "<134>Feb 14 19:04:54 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    println!("{x:?}");
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "127.0.0.1"
    );
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_ipv6_and_datetime() -> Result<()> {
    let s = "<134>2022-02-14T03:17:30-08:00 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "127.0.0.1"
    );
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_ipv6_and_datetime_rfc5424() -> Result<()> {
    let s = "<134>1 2022-02-14T03:17:30-08:00 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "127.0.0.1"
    );
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_ipv6localhost_and_human_datetime() -> Result<()> {
    let s = "<134>Feb 14 19:04:54 ::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    println!("{x:?}");
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "::1"
    );
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_ipv6_and_human_datetime() -> Result<()> {
    let s = "<134>Feb 14 19:04:54 2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    println!("{x:?}");
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "2001:db8:3333:4444:5555:6666:7777:8888"
    );
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_ipv6_and_human_datetime_rfc5424() -> Result<()> {
    let s = "<134>1 Feb 14 19:04:54 2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    println!("{x:?}");
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "2001:db8:3333:4444:5555:6666:7777:8888"
    );
    assert!(x.contains_key("at"));
    Ok(())
}

#[test]
fn test_only_host() -> Result<()> {
    let s = "<134>TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(!x.contains_key("at"));
    assert!(x.contains_key("ahost"));
    Ok(())
}

#[test]
fn test_only_ipv4() -> Result<()> {
    let s = "<134>127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(!x.contains_key("at"));
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "127.0.0.1"
    );
    Ok(())
}

#[test]
fn test_only_ipv6localhost() -> Result<()> {
    let s = "<134>::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    println!("{x:?}");
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "::1"
    );
    assert!(!x.contains_key("at"));
    Ok(())
}

#[test]
fn test_only_ipv6() -> Result<()> {
    let s = "<134>2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    println!("{x:?}");
    assert!(x.contains_key("ahost"));
    assert_eq!(
        x.get("ahost")
            .ok_or_else::<E, _>(|| "ahost missing".into())?,
        "2001:db8:3333:4444:5555:6666:7777:8888"
    );
    assert!(!x.contains_key("at"));
    Ok(())
}

#[test]
fn test_equals_inside_value() -> Result<()> {
    let s = r"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|request=https://google.com&search\=rust";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("request"));
    assert_eq!(
        x.get("request")
            .ok_or_else::<E, _>(|| "request missing".into())?,
        "https://google.com&search=rust"
    );
    Ok(())
}

#[test]
fn test_cef_headers_exist() -> Result<()> {
    let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x?;
    assert!(x.contains_key("deviceVendor"));
    assert!(x.contains_key("deviceProduct"));
    assert!(x.contains_key("deviceVersion"));
    assert!(x.contains_key("signatureId"));
    assert!(x.contains_key("name"));
    assert!(x.contains_key("severity"));
    Ok(())
}

//
// Test that an empty string is rejected.
//
#[test]
fn test_empty_string_cef() -> Result<()> {
    let s = "";
    match s.to_hashmap(false) {
        Err(_) => Ok(()),
        Ok(_) => Err("Expected error for empty string.".into()),
    }
}

//
// Test that a message containing a potential injection attack is parsed safely.
//
#[test]
fn test_injection_attack_string() -> Result<()> {
    let malicious_part = "<script>alert('xss')</script>";
    let s = format!("CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|msg={malicious_part}");
    let hm = s.to_hashmap(false)?;
    match hm.get("msg") {
        Some(value) if value == malicious_part => Ok(()),
        Some(value) => Err(format!("Expected msg to be {malicious_part}, got {value}").into()),
        None => Err("Expected msg key in hashmap.".into()),
    }
}

//
// Test that properties missing a key/value separator (the '=') return an error.
//
#[test]
fn test_missing_key_value_separator() -> Result<()> {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|request";
    if s.to_hashmap(false).is_err() {
        Ok(())
    } else {
        Err("Expected error when property is missing '='.".into())
    }
}

//
// If an equal sign (=) is used in the extensions, it has to be escaped with a backslash (\).
//
#[test]
fn test_multiple_equals_in_property() -> Result<()> {
    let s = r"CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|data=val\=extra\=more";
    let hm = s.to_hashmap(false)?;
    match hm.get("data") {
        Some(value) if value == "val=extra=more" => Ok(()),
        Some(value) => {
            Err(format!("Expected 'val=extra=more' for key 'data', got: {value}").into())
        }
        None => Err("Key 'data' not found in hashmap.".into()),
    }
}

//
// Test that header fields support Unicode characters (including accented characters and emojis).
//
#[test]
fn test_unicode_characters_in_headers() -> Result<()> {
    let vendor = "Vendör";
    let product = "Prödüct";
    let name = "Tëst Event 🚀";
    let s = format!("CEF:0|{vendor}|{product}|20.0.560|600|{name}|3|");
    let hm = s.to_hashmap(false)?;

    match hm.get("deviceVendor") {
        Some(val) if val == vendor => (),
        Some(val) => return Err(format!("Expected deviceVendor {vendor}, got {val}").into()),
        None => return Err("deviceVendor key missing".into()),
    };

    match hm.get("deviceProduct") {
        Some(val) if val == product => (),
        Some(val) => return Err(format!("Expected deviceProduct {product}, got {val}").into()),
        None => return Err("deviceProduct key missing".into()),
    };

    match hm.get("name") {
        Some(val) if val == name => Ok(()),
        Some(val) => Err(format!("Expected name {name}, got {val}").into()),
        None => Err("name key missing".into()),
    }
}

//
// Test that if the CEF version is not "0" or "1", the parser returns an error.
//
#[test]
fn test_invalid_cef_version() -> Result<()> {
    let s = "CEF:2|Vendor|Product|20.0.560|600|User Signed In|3|";
    if s.to_hashmap(false).is_err() {
        Ok(())
    } else {
        Err("Expected error when CEF version is not '0' or '1'.".into())
    }
}

//
// Fuzz a number of invalid input strings to ensure that no panics occur.
//
#[test]
fn test_fuzz_invalid_inputs() {
    let fuzz_inputs = vec![
        "abcdefg",
        "1234567890",
        "!!!@@@###",
        "cef:0|",                            // missing proper header and fields
        "CEF:0|Vendor|",                     // insufficient header fields
        "CEF:0|Vendor|Product|20.0.560|600", // missing name, severity, and trailing separator
        "<134> CEF:0|Vendor|Product|20.0.560|600|User Signed In", // missing trailing pipe
        "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3", // no trailing separator
        "CEF:0|Vendor|Prod|uct|20.0.560|600|User Signed In|3|key=va|l", // pipe character inside a property value
    ];

    for input in fuzz_inputs {
        // The goal here is simply to ensure these inputs do not cause a panic.
        let _ = input.to_hashmap(false);
    }
}

//
// Test a very long but valid CEF message to check for performance or potential resource issues.
//
#[test]
fn test_extremely_long_cef_message() -> Result<()> {
    let long_field = "a".repeat(10_000);
    let s = format!("CEF:0|LongVendor|LongProduct|1.0|101|Long Event|3|msg={long_field}");
    let hm = s.to_hashmap(false)?;
    hm.get("msg").map_or_else(
        || Err("Expected msg key in hashmap.".into()),
        |val| {
            let expected_len = long_field.len();
            if val == &long_field {
                Ok(())
            } else {
                Err(format!(
                    "Expected msg field length {expected_len} but got {}",
                    val.len()
                )
                .into())
            }
        },
    )
}
//
// Test that extra whitespace around the CEF string does not upset the parser.
//
#[test]
fn test_cef_with_extra_whitespace() -> Result<()> {
    let s = "   CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|   ";
    let hm = s.to_hashmap(false)?;
    if hm.contains_key("deviceVendor") && hm.contains_key("deviceProduct") {
        Ok(())
    } else {
        Err("Expected deviceVendor and deviceProduct keys to be present.".into())
    }
}

//
// Test that escaped pipe characters (if supported) within a field are processed correctly.
//
#[test]
fn test_escaped_pipes_in_message() -> Result<()> {
    let s = r"CEF:0|Vendor|Product|20.0.560|600|User Signed In with escaped \| pipe|3|";
    let hm = s.to_hashmap(false)?;
    println!("{hm:#?}");
    match hm.get("name") {
        Some(val) if val.contains('|') => Ok(()),
        Some(val) => Err(format!("Expected name to contain '|' but got: {val}").into()),
        None => Err("Expected 'name' key in hashmap.".into()),
    }
}

//
// Test that a malformed syslog priority (inside the angle brackets) is handled correctly.
//
#[test]
fn test_invalid_syslog_priority_format() -> Result<()> {
    let s = "<ABC>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    if s.to_hashmap(false).is_err() {
        Ok(())
    } else {
        Err("Expected error when syslog priority is non-numeric.".into())
    }
}

//
// Test that a CEF message missing its final delimiter returns an error.
//
#[test]
fn test_cef_message_with_missing_delimiter() -> Result<()> {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3";
    if s.to_hashmap(false).is_err() {
        Ok(())
    } else {
        Err("Expected error when CEF message is missing the trailing separator.".into())
    }
}

//
// Test that if extra (unexpected) trailing data is present after the key/value pairs,
// it is captured (for example, in the rawEvent field) rather than causing a parser error.
//
#[test]
fn test_cef_message_with_trailing_extra_data() -> Result<()> {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 extra_text";
    let hm = s.to_hashmap(true)?;
    match hm.get("rawEvent") {
        Some(raw_event) if raw_event.contains("extra_text") => Ok(()),
        Some(raw_event) => Err(format!("rawEvent did not contain extra_text: {raw_event}").into()),
        None => Err("Expected rawEvent key in hashmap.".into()),
    }
}

//
// Test that malformed escape sequences do not lead to an invalid end result in a field.
//
#[test]
fn test_cef_with_malformed_escape_sequences() -> Result<()> {
    let s = r"CEF:0|Vendor|Product|20.0.560|600|User Signed In with \ escape|3|";
    let hm = s.to_hashmap(false)?;
    match hm.get("name") {
        Some(name) if !name.ends_with('\\') => Ok(()),
        Some(name) => {
            Err(format!("The 'name' field should not end with an escape backslash: {name}").into())
        }
        None => Err("Expected 'name' key in hashmap.".into()),
    }
}

#[test]
fn test_parse_cef_line_valid() {
    let line = "cef:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232";
    let event = parse_cef_line(line).expect("Failed to parse valid CEF line");

    macro_rules! assert_cef_header {
        ($( $key:tt => $value:expr ),* $(,)?) => {
            $(
            assert_eq!(
                event.cef_header.get(stringify!($key)).map(String::as_str),
                Some($value),
                stringify!($key),
            );
            )*
        }
    }

    assert_cef_header!(name => "worm successfully stopped");
    assert_cef_header!(deviceVendor => "Security");
    assert_cef_header!(deviceProduct => "threatmanager");
    assert_cef_header!(deviceVersion => "1.0");
    assert_cef_header!(signatureId => "100");
    assert_cef_header!(severity => "10");
}

// #[test]
// fn test_parse_cef_line_with_escaped_pipe() {
//     let line = r#"CEF:0|Sec\|urity|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1"#;
//     let event = parse_cef_line(line).expect("Failed to parse CEF line with escaped pipe");
//     assert_eq!(event.vendor, "Sec|urity");
// }

// #[test]
// fn test_parse_extensions_malformed() {
//     // Missing '=' in the key/value pair should produce an error.
//     let ext = "src10.0.0.1";
//     let result = parse_extensions(ext);
//     assert!(result.is_err());
// }

// #[test]
// fn test_unescape() {
//     let input = r#"abc\=def\\ghi"#;
//     let expected = "abc=def\\ghi";
//     assert_eq!(unescape(input), expected);
// }
