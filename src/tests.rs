use crate::CefToHashMap;

#[test]
fn test_not_cef_string() {
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
