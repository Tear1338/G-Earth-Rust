use gearth_rust::{
    expression,
    packet::Packet,
    parsers::stuffdata::{HighScoreEntry, StuffData, StuffValue},
};
use std::collections::BTreeMap;

#[test]
#[ignore = "requires the actual beta-29 Java API oracle"]
fn all_stuff_data_wire_formats_match_original_java() {
    let path = std::env::var("GEARTH_STUFF_ORACLE").expect("Java oracle path required");
    let text = std::fs::read_to_string(path).unwrap();
    let observed: BTreeMap<_, _> = text
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').unwrap();
            (key, expression::parse_hex(value).unwrap())
        })
        .collect();
    let values = [
        ("legacy", StuffValue::Legacy("1".into())),
        (
            "map",
            StuffValue::Map(BTreeMap::from([("state".into(), "2".into())])),
        ),
        ("strings", StuffValue::Strings(vec!["a".into()])),
        (
            "vote",
            StuffValue::Vote {
                state: "x".into(),
                result: 3,
            },
        ),
        ("empty", StuffValue::Empty),
        ("integers", StuffValue::Integers(vec![1, -2])),
        (
            "highscore",
            StuffValue::HighScore {
                state: "x".into(),
                score_type: 1,
                clear_type: 2,
                entries: vec![HighScoreEntry {
                    score: 7,
                    users: vec!["Alice".into()],
                }],
            },
        ),
        (
            "crackable",
            StuffValue::Crackable {
                state: "z".into(),
                hits: 4,
                target: 5,
            },
        ),
    ];
    for (name, value) in values {
        let serial = if matches!(value, StuffValue::HighScore { .. }) {
            None
        } else {
            Some((13, 20))
        };
        let expected = StuffData {
            flags: 256,
            serial,
            value,
        };
        let mut packet = Packet::new(1);
        expected.append(&mut packet).unwrap();
        assert_eq!(packet.bytes(), observed[name], "{name}");
        let mut from_java = Packet::from_bytes(observed[name].clone()).unwrap();
        assert_eq!(StuffData::read(&mut from_java).unwrap(), expected, "{name}");
    }
    use gearth_rust::parsers::entity::{HDirection, HPoint};
    use gearth_rust::parsers::furniture::{HFloorItem, HInventoryItem, HProductType, HWallItem};
    let floor = HFloorItem {
        id: 77,
        type_id: -5,
        tile: HPoint::with_height(3, 4, 1.5),
        facing: HDirection::East,
        size_z: "1.0".into(),
        extra: 9,
        stuff: StuffData {
            flags: 256,
            serial: Some((2, 100)),
            value: StuffValue::Legacy("3".into()),
        },
        seconds_to_expiration: -1,
        usage_policy: 2,
        owner_id: 42,
        owner_name: None,
        static_class: Some("static".into()),
    };
    let wall = HWallItem {
        id: 123,
        type_id: 456,
        location: ":w=1,2 l=3,4 r".into(),
        state: "hello".into(),
        seconds_to_expiration: -1,
        usage_policy: 2,
        owner_id: 42,
        owner_name: None,
    };
    let inventory = HInventoryItem {
        placement_id: 1,
        product_type: HProductType::FloorItem,
        id: 2,
        type_id: 3,
        special_type: 1,
        stuff: StuffData {
            flags: 0,
            serial: None,
            value: StuffValue::Empty,
        },
        recyclable: true,
        tradeable: true,
        groupable: false,
        sellable: true,
        seconds_to_expiration: -1,
        rent_period_started: false,
        room_id: 9,
        floor_details: Some(("slot".into(), 7)),
    };
    let mut packet = Packet::new(1);
    floor.append(&mut packet).unwrap();
    assert_eq!(packet.bytes(), observed["floor"]);
    assert_eq!(
        HFloorItem::read(&mut Packet::from_bytes(observed["floor"].clone()).unwrap()).unwrap(),
        floor
    );
    let mut packet = Packet::new(1);
    wall.append(&mut packet).unwrap();
    assert_eq!(packet.bytes(), observed["wall"]);
    assert_eq!(
        HWallItem::read(&mut Packet::from_bytes(observed["wall"].clone()).unwrap()).unwrap(),
        wall
    );
    let mut packet = Packet::new(1);
    inventory.append(&mut packet).unwrap();
    assert_eq!(packet.bytes(), observed["inventory"]);
    assert_eq!(
        HInventoryItem::read(&mut Packet::from_bytes(observed["inventory"].clone()).unwrap())
            .unwrap(),
        inventory
    );
    let friend = gearth_rust::parsers::social::HFriend {
        id: 8,
        name: "Bob".into(),
        male: true,
        online: true,
        following_allowed: false,
        figure: "hr".into(),
        category_id: 2,
        motto: "m".into(),
        real_name: "".into(),
        facebook_id: "".into(),
        persisted_message_user: false,
        vip_member: true,
        pocket_habbo_user: false,
        relationship_status: 1,
        category_name: None,
    };
    let mut packet = Packet::new(1);
    friend.append(&mut packet).unwrap();
    assert_eq!(packet.bytes(), observed["friend"]);
    assert_eq!(
        gearth_rust::parsers::social::HFriend::read(
            &mut Packet::from_bytes(observed["friend"].clone()).unwrap()
        )
        .unwrap(),
        friend
    );
    let index = gearth_rust::parsers::catalog::HCatalogIndex::read(
        &mut Packet::from_bytes(observed["catalog_index"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(index.root.offer_ids, vec![99]);
    assert!(index.new_additions_available);
    let page = gearth_rust::parsers::catalog::HCatalogPage::read(
        &mut Packet::from_bytes(observed["catalog_page"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        page.front_page_items[0].target,
        gearth_rust::parsers::catalog::HFrontPageTarget::Offer(25)
    );
}
