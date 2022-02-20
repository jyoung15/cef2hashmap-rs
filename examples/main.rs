use cef2hashmap::CefToHashMap;

fn main() {
    let cef = "<134>2022-02-14T03:17:30-08:00 TEST CEF:0|Trend Micro|Deep Security Manager|20.0.560|600|User Signed In|3|src=135.181.193.110 suser=MasterAdmin target=MasterAdmin msg=User signed in from 135.181.193.110 TrendMicroDsTenant=Primary TrendMicroDsTenantId=0";
    println!("{:#?}", cef.to_hashmap());
}
