use gearth_rust::{encoding, expression, packet::*};
use std::collections::BTreeMap;
#[test]
#[ignore = "requires the actual beta-29 Java API; executed by java-compatibility CI"]
fn compare_against_actual_beta29_java_api() {
    let Ok(path) = std::env::var("GEARTH_JAVA_ORACLE") else {
        eprintln!("Java oracle not configured; CI supplies the actual beta-29 JAR");
        return;
    };
    let input = std::fs::read_to_string(path).unwrap();
    let observed: BTreeMap<_, _> = input
        .lines()
        .map(|line| {
            let (k, v) = line.split_once('=').unwrap();
            (k.to_owned(), expression::parse_hex(v).unwrap())
        })
        .collect();
    let mut expected = BTreeMap::<String, Vec<u8>>::new();
    expected.insert(
        "basic".into(),
        expression::parse("{h:123}{i:42}{s:\"hello\"}{b:true}")
            .unwrap()
            .bytes()
            .to_vec(),
    );
    let mut latin = Packet::new(255);
    latin.put_string("éÿ\0").unwrap();
    expected.insert("latin1".into(), latin.bytes().to_vec());
    expected.insert(
        "numbers".into(),
        expression::parse("{h:1}{i:-2147483648}{l:9223372036854775807}{d:-2.5}")
            .unwrap()
            .bytes()
            .to_vec(),
    );
    let mut binary = Packet::new(8);
    binary.append(&[0, 9, 128, 255]).unwrap();
    binary.edited = false;
    expected.insert(
        "message".into(),
        latin1_encode(
            &Message {
                packet: binary,
                direction: Direction::ToClient,
                index: 42,
                blocked: true,
            }
            .stringify(),
        )
        .unwrap(),
    );
    for n in [
        -1000000,
        -256,
        -4,
        -1,
        0,
        1,
        3,
        4,
        63,
        64,
        256,
        1000000,
        i32::MAX,
    ] {
        expected.insert(format!("vl64_{n}"), encoding::encode_vl64(n));
    }
    expected.insert("b64_123".into(), encoding::encode_b64(123, 2).unwrap());
    for format in [PacketFormat::WedgieIncoming,PacketFormat::WedgieOutgoing] {
        let mut packet=Packet::new_with_format(format,123).unwrap();packet.put_i32(-256).unwrap().put_string("é").unwrap().put_bool(true).unwrap().put_u16(1000).unwrap();
        expected.insert(format!("shock_{}",format.id()),packet.bytes().to_vec());
        let direction=if format==PacketFormat::WedgieIncoming{Direction::ToClient}else{Direction::ToServer};
        expected.insert(format!("shock_message_{}",format.id()),latin1_encode(&Message {packet,direction,index:7,blocked:false}.stringify()).unwrap());
    }
    let mut a=gearth_rust::shockwave::BobbaCrypto::with_private(12345).unwrap();let b=gearth_rust::shockwave::BobbaCrypto::with_private(67890).unwrap();
    expected.insert("bobba_public_a".into(),a.public_key().into_bytes());expected.insert("bobba_public_b".into(),b.public_key().into_bytes());a.set_peer(&b.public_key()).unwrap();
    let keys=a.keys().unwrap();for (i,key) in [&keys.c2s_data,&keys.c2s_header,&keys.s2c_data,&keys.s2c_header].iter().enumerate(){expected.insert(format!("bobba_key_{i}"),key.key.to_vec());expected.insert(format!("bobba_nonce_{i}"),key.nonce.to_vec());}
    let keys=a.keys_mut().unwrap();for i in 0..2{let mut bytes=vec![1,2,3,4,5];keys.c2s_data.apply(&mut bytes);expected.insert(format!("bobba_cipher_{i}"),bytes);}let mut header=vec![1,64,64,100];keys.c2s_header.apply(&mut header);expected.insert("bobba_header".into(),header);
    assert_eq!(
        observed, expected,
        "Rust wire bytes differ from upstream Java API"
    );
}
