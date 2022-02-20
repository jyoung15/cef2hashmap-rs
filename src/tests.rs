use crate::CefToHashMap;

#[test]
fn test_non_cef_string() {
    let s = "this is not a cef string|key=value";
    assert!(s.to_hashmap(false).is_err())
}

#[test]
fn test_malformed_cef_string() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|src=127.0.0.1";
    assert!(s.to_hashmap(false).is_err())
}

#[test]
fn test_string_to_hashmap() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|".to_string();
    assert!(s.to_hashmap(false).is_ok())
}

#[test]
fn test_str_to_hashmap() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    assert!(s.to_hashmap(false).is_ok())
}

#[test]
fn test_with_raw_event() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(true);
    assert!(x.is_ok());
    assert!(x.unwrap().get("rawEvent").is_some())
}

#[test]
fn test_without_raw_event() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    assert!(x.unwrap().get("rawEvent").is_none())
}

#[test]
fn test_pri_facility() {
    let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("syslog_priority").is_some());
    assert!(x.get("syslog_facility").is_some());
}

#[test]
fn test_no_pri_facility() {
    let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("syslog_priority").is_none());
    assert!(x.get("syslog_facility").is_none());
}

#[test]
fn test_host_and_datetime() {
    let s = "<134>2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("ahost").is_some());
    assert!(x.get("at").is_some());
}

#[test]
fn test_host_and_human_datetime() {
    let s = "<134>Feb 14 19:04:54 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    println!("{:?}", x);
    assert!(x.get("ahost").is_some());
    assert!(x.get("at").is_some());
}

#[test]
fn test_only_datetime() {
    let s = "<134>2022-02-14T03:17:30-08:00 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("at").is_some());
    assert!(x.get("ahost").is_none());
}

#[test]
fn test_only_human_datetime() {
    let s =
        "<134>Feb 14 19:04:54 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("at").is_some());
    assert!(x.get("ahost").is_none());
}

#[test]
fn test_ipv4_and_datetime() {
    let s = "<134>2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("ahost").is_some());
    assert!(x.get("at").is_some());
}

#[test]
fn test_ipv4_and_human_datetime() {
    let s = "<134>Feb 14 19:04:54 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    println!("{:?}", x);
    assert!(x.get("ahost").is_some());
    assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
    assert!(x.get("at").is_some());
}

#[test]
fn test_ipv6_and_datetime() {
    let s = "<134>2022-02-14T03:17:30-08:00 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("ahost").is_some());
    assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
    assert!(x.get("at").is_some());
}

#[test]
fn test_ipv6localhost_and_human_datetime() {
    let s = "<134>Feb 14 19:04:54 ::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    println!("{:?}", x);
    assert!(x.get("ahost").is_some());
    assert_eq!(x.get("ahost").unwrap(), "::1");
    assert!(x.get("at").is_some());
}

#[test]
fn test_ipv6_and_human_datetime() {
    let s = "<134>Feb 14 19:04:54 2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    println!("{:?}", x);
    assert!(x.get("ahost").is_some());
    assert_eq!(
        x.get("ahost").unwrap(),
        "2001:db8:3333:4444:5555:6666:7777:8888"
    );
    assert!(x.get("at").is_some());
}

#[test]
fn test_only_host() {
    let s = "<134>TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("at").is_none());
    assert!(x.get("ahost").is_some());
}

#[test]
fn test_only_ipv4() {
    let s = "<134>127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("at").is_none());
    assert!(x.get("ahost").is_some());
    assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
}

#[test]
fn test_only_ipv6localhost() {
    let s = "<134>::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    println!("{:?}", x);
    assert!(x.get("ahost").is_some());
    assert_eq!(x.get("ahost").unwrap(), "::1");
    assert!(x.get("at").is_none());
}

#[test]
fn test_only_ipv6() {
    let s = "<134>2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    println!("{:?}", x);
    assert!(x.get("ahost").is_some());
    assert_eq!(
        x.get("ahost").unwrap(),
        "2001:db8:3333:4444:5555:6666:7777:8888"
    );
    assert!(x.get("at").is_none());
}

#[test]
fn test_cef_headers_exist() {
    let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    let x = s.to_hashmap(false);
    assert!(x.is_ok());
    let x = x.unwrap();
    assert!(x.get("deviceVendor").is_some());
    assert!(x.get("deviceProduct").is_some());
    assert!(x.get("deviceVersion").is_some());
    assert!(x.get("signatureId").is_some());
    assert!(x.get("name").is_some());
    assert!(x.get("severity").is_some());
}
