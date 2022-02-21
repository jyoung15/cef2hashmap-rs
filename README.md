# CEF to HashMap
[![macOS](https://github.com/marirs/cef2hashmap-rs/actions/workflows/macos.yml/badge.svg)](https://github.com/marirs/cef2hashmap-rs/actions/workflows/macos.yml)
[![Linux Arm7](https://github.com/marirs/cef2hashmap-rs/actions/workflows/linux_arm.yml/badge.svg)](https://github.com/marirs/cef2hashmap-rs/actions/workflows/linux_arm.yml)
[![Linux x86_64](https://github.com/marirs/cef2hashmap-rs/actions/workflows/linux_x86_64.yml/badge.svg)](https://github.com/marirs/cef2hashmap-rs/actions/workflows/linux_x86_64.yml)
[![Windows](https://github.com/marirs/cef2hashmap-rs/actions/workflows/windows.yml/badge.svg)](https://github.com/marirs/cef2hashmap-rs/actions/workflows/windows.yml)

Convert a syslog CEF string or a regular CEF string to a HashMap object.

### Requirements
- Rust 1.56+ (2021 edition)

### Example Usage

```toml
[dependencies]
cef2hashmap = "0.1.3"
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
