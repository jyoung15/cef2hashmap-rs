# CEF to HashMap

Convert a syslog CEF string or a regular CEF string to a HashMap object.

### Requirements
- Rust 1.56+ (2021 edition)

### Example Usage

```toml
[dependencies]
cef2hashmap = "0.1.1"
```

and then

```rust
use cef2hashmap::CefToHashMap;

fn main() {
    let example = "<134>2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 suser=Admin target=Admin msg=User signed in from 127.0.0.1 Tenant=Primary TenantId=0 act= cs1Label=Testing Label 1 Key cs1=Testing Label 1 String Value";
    println!("{:#?}", example.to_hashmap(true));
}
```
- pass `false` to `.to_hashmap(false)` if you don't want to preserve the original event

---
License: MIT
