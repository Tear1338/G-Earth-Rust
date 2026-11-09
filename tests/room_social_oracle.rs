use gearth_rust::{
    expression,
    parsers::{
        entity::{HEntity, HEntityDetails, HPoint},
        social::{HFriend, HFriendChange},
    },
};

fn java_bytes(variable: &str) -> Vec<u8> {
    let path = std::env::var(variable).expect("Java oracle path required");
    let output = std::fs::read_to_string(path).unwrap();
    expression::parse_hex(output.trim()).unwrap()
}

#[test]
#[ignore = "requires vectors from the released beta-29 Java API"]
fn room_entity_constructor_matches_java() {
    let entity = HEntity {
        id: 17,
        name: "Bot".into(),
        motto: "hello".into(),
        figure_id: "figure".into(),
        index: 23,
        tile: HPoint::with_height(3, 4, 1.5),
        unknown: 5,
        details: HEntityDetails::OldBot,
        last_update: None,
    };
    let rust = HEntity::construct(&[entity.clone(), entity], 42).unwrap();
    assert_eq!(rust.bytes(), java_bytes("GEARTH_ENTITY_ORACLE"));
}

#[test]
#[ignore = "requires vectors from the released beta-29 Java API"]
fn friend_update_matches_a_packet_accepted_by_java() {
    let friend = HFriend {
        id: 8,
        name: "Bob".into(),
        male: true,
        online: true,
        following_allowed: false,
        figure: "hr".into(),
        category_id: 2,
        motto: "m".into(),
        real_name: String::new(),
        facebook_id: String::new(),
        persisted_message_user: false,
        vip_member: true,
        pocket_habbo_user: false,
        relationship_status: 1,
        category_name: Some("Friends".into()),
    };
    let changes = [
        HFriendChange::Upsert {
            change_type: 0,
            friend,
        },
        HFriendChange::Removed(99),
    ];
    let rust = HFriend::construct_update(&changes, 3).unwrap();
    assert_eq!(rust.bytes(), java_bytes("GEARTH_FRIEND_ORACLE"));
}

#[test]
#[ignore = "requires entity update vectors from the released beta-29 Java API"]
fn entity_update_actions_match_java() {
    use gearth_rust::{packet::Packet, parsers::entity::HEntityUpdate};
    let output =
        std::fs::read_to_string(std::env::var("GEARTH_ENTITY_UPDATE_ORACLE").unwrap()).unwrap();
    let expected: std::collections::BTreeMap<_, _> = output
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    let cases = [
        "sit ",
        "lay  ",
        "flatctrl ",
        "mv 1,2,",
        "mv 0x-1,2,3",
        "sign -+1",
        "mv +0x1,-02,3",
        "sit  /sign 1",
        "mv 1,2,3,",
        "sign 0x1",
        "mv --1,2,3",
    ];
    for (index, action) in cases.iter().enumerate() {
        let mut packet = Packet::new(1);
        packet
            .put_i32(1)
            .unwrap()
            .put_i32(7)
            .unwrap()
            .put_i32(2)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_string("1.0")
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_string(action)
            .unwrap();
        let actual = match HEntityUpdate::parse(&mut packet) {
            Ok(updates) => {
                let update = &updates[0];
                let action = update
                    .action
                    .map_or("null".to_string(), |a| format!("{a:?}"));
                let stance = update
                    .stance
                    .map_or("null".to_string(), |a| format!("{a:?}"));
                let sign = update.sign.map_or("null".to_string(), |a| {
                    [
                        "Zero",
                        "One",
                        "Two",
                        "Three",
                        "Four",
                        "Five",
                        "Six",
                        "Seven",
                        "Eight",
                        "Nine",
                        "Ten",
                        "Heart",
                        "Skull",
                        "Exclamation",
                        "Soccerball",
                        "Smiley",
                        "Redcard",
                        "Yellowcard",
                        "Invisible",
                    ][usize::from(a)]
                    .to_string()
                });
                let moving = update.moving_to.map_or("none".to_string(), |p| {
                    format!("{},{},{:.1}", p.x, p.y, p.z)
                });
                format!("{action};{stance};{sign};{};{moving}", update.is_controller)
            }
            Err(_) => "error".to_string(),
        };
        assert_eq!(
            actual,
            expected[format!("case_{index}").as_str()],
            "case {index}: {action:?}"
        );
    }
}

#[test]
#[ignore = "requires height vectors from the released beta-29 Java API"]
fn entity_update_heights_match_java() {
    use gearth_rust::{packet::Packet, parsers::entity::HEntityUpdate};
    let output =
        std::fs::read_to_string(std::env::var("GEARTH_ENTITY_UPDATE_ORACLE").unwrap()).unwrap();
    let expected: std::collections::BTreeMap<_, _> = output
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    let heights = [
        "1.25",
        " 1.25 ",
        "1.25f",
        "-0.0D",
        "+Infinity",
        "NaN",
        "nan",
        "inf",
        "0x1.8p1",
        "-0X1p-1074",
        "0x1.00000000000008p0",
        "0x1p1024",
        "0x1p-1075",
        "0x1.8p-1075",
        "0x1p0f",
        "0x1",
        "1_0",
        "1e309",
    ];
    for index in 0..3000 {
        let (height, bits) = expected[format!("random_{index}").as_str()]
            .split_once(',')
            .unwrap();
        let mut packet = Packet::new(1);
        packet
            .put_i32(1)
            .unwrap()
            .put_i32(7)
            .unwrap()
            .put_i32(2)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_string(height)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_string("")
            .unwrap();
        let actual = HEntityUpdate::parse(&mut packet).unwrap();
        assert_eq!(
            format!("{:x}", actual[0].tile.z.to_bits()),
            bits,
            "random {index}: {height}"
        );
    }
    for (index, height) in heights.iter().enumerate() {
        let mut packet = Packet::new(1);
        packet
            .put_i32(1)
            .unwrap()
            .put_i32(7)
            .unwrap()
            .put_i32(2)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_string(height)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_string("")
            .unwrap();
        let actual = match HEntityUpdate::parse(&mut packet) {
            Ok(updates) => format!("{:x}", updates[0].tile.z.to_bits()),
            Err(_) => "error".to_string(),
        };
        assert_eq!(
            actual,
            expected[format!("height_{index}").as_str()],
            "height {height:?}"
        );
    }
}

#[test]
#[ignore = "requires Double.toString output from Java"]
fn entity_height_format_matches_java_samples() {
    let output =
        std::fs::read_to_string(std::env::var("GEARTH_DOUBLE_FORMAT_ORACLE").unwrap()).unwrap();
    for line in output.lines() {
        let (bits, expected) = line.split_once('=').unwrap();
        let value = f64::from_bits(u64::from_str_radix(bits, 16).unwrap());
        let displayed = HPoint::with_height(0, 0, value).to_string();
        let actual = displayed
            .strip_prefix("(0,0,")
            .unwrap()
            .strip_suffix(')')
            .unwrap();
        assert_eq!(actual, expected, "bits {bits}");
    }
}

#[test]
#[ignore = "requires Java entity and floor item packet vectors"]
fn entity_and_furniture_height_packets_match_java() {
    use gearth_rust::{packet::Packet, parsers::furniture::HFloorItem};
    let output =
        std::fs::read_to_string(std::env::var("GEARTH_HEIGHT_PACKET_ORACLE").unwrap()).unwrap();
    for line in output.lines() {
        let (bits, fields) = line.split_once('=').unwrap();
        let fields: Vec<_> = fields.split(';').collect();
        let height = fields[0];
        let mut input = Packet::new(1);
        input
            .put_i32(17)
            .unwrap()
            .put_string("Bot")
            .unwrap()
            .put_string("hello")
            .unwrap()
            .put_string("figure")
            .unwrap()
            .put_i32(23)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_i32(4)
            .unwrap()
            .put_string(height)
            .unwrap()
            .put_i32(5)
            .unwrap()
            .put_i32(3)
            .unwrap();
        let entity = HEntity::read(&mut input).unwrap();
        let mut output = Packet::new(42);
        entity.append(&mut output).unwrap();
        assert_eq!(
            output.bytes(),
            expression::parse_hex(fields[1]).unwrap(),
            "entity {bits}"
        );
        let mut input = Packet::new(1);
        input
            .put_i32(17)
            .unwrap()
            .put_i32(4)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_i32(4)
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_string(height)
            .unwrap()
            .put_string("1")
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_string("0")
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(99)
            .unwrap();
        let item = HFloorItem::read(&mut input).unwrap();
        let mut output = Packet::new(42);
        item.append(&mut output).unwrap();
        assert_eq!(
            output.bytes(),
            expression::parse_hex(fields[2]).unwrap(),
            "furniture {bits}"
        );
    }
}
