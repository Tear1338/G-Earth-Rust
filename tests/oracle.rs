use gearth_rust::{encoding,expression,packet::*};
use std::collections::BTreeMap;
#[test] fn compare_against_actual_beta29_java_api() {
    let Ok(path)=std::env::var("GEARTH_JAVA_ORACLE") else {eprintln!("Java oracle not configured; CI supplies the actual beta-29 JAR");return;};
    let input=std::fs::read_to_string(path).unwrap();
    let observed:BTreeMap<_,_>=input.lines().map(|line|{let(k,v)=line.split_once('=').unwrap();(k.to_owned(),expression::parse_hex(v).unwrap())}).collect();
    let mut expected=BTreeMap::<String,Vec<u8>>::new();
    expected.insert("basic".into(),expression::parse("{h:123}{i:42}{s:\"hello\"}{b:true}").unwrap().bytes().to_vec());
    let mut latin=Packet::new(255);latin.put_string("éÿ\0").unwrap();
    expected.insert("latin1".into(),latin.bytes().to_vec());
    expected.insert("numbers".into(),expression::parse("{h:1}{i:-2147483648}{l:9223372036854775807}{d:-2.5}").unwrap().bytes().to_vec());
    let mut binary=Packet::new(8);binary.append(&[0,9,128,255]).unwrap();binary.edited=false;
    expected.insert("message".into(),latin1_encode(&Message {packet:binary,direction:Direction::ToClient,index:42,blocked:true}.stringify()).unwrap());
    for n in [-1000000,-256,-4,-1,0,1,3,4,63,64,256,1000000,i32::MAX] {expected.insert(format!("vl64_{n}"),encoding::encode_vl64(n));}
    expected.insert("b64_123".into(),encoding::encode_b64(123,2).unwrap());
    assert_eq!(observed,expected,"Rust wire bytes differ from upstream Java API");
}
