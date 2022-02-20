use crate::CefToHashMap;

#[test]
fn test_non_cef_string() {
    let s = "this is not a cef string|key=value";
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
    assert!(x.get("syslogPriority").is_some());
    assert!(x.get("syslogFacility").is_some());
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