#![allow(unused_crate_dependencies, reason = "lint not needed for example")]

use cef2hashmap::CefToHashMap as _;

fn main() {
    let examples = include_str!("examples.txt").trim();
    for (i, eg) in examples.lines().enumerate() {
        println!("--- Example Line #{} ---", i + 1);
        println!("{:#?}", eg.to_hashmap(true));
        println!();
    }
}
