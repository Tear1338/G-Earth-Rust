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
