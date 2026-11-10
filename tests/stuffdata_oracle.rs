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
    let owners = [
        (17, None),
        (1, Some("Bob")),
        (17, Some("Final")),
        (2, Some("Carol")),
    ];
    let floor_items: Vec<_> = owners
        .iter()
        .map(|(id, name)| {
            let mut item = floor.clone();
            item.owner_id = *id;
            item.owner_name = name.map(str::to_owned);
            item
        })
        .collect();
    let wall_items: Vec<_> = owners
        .iter()
        .map(|(id, name)| {
            let mut item = wall.clone();
            item.owner_id = *id;
            item.owner_name = name.map(str::to_owned);
            item
        })
        .collect();
    let java_floors =
        HFloorItem::parse(&mut Packet::from_bytes(observed["floor_collection"].clone()).unwrap())
            .unwrap();
    let java_walls =
        HWallItem::parse(&mut Packet::from_bytes(observed["wall_collection"].clone()).unwrap())
            .unwrap();
    let mut rust_floors = HFloorItem::construct(&floor_items, 1).unwrap();
    let mut rust_walls = HWallItem::construct(&wall_items, 1).unwrap();
    assert_eq!(HFloorItem::parse(&mut rust_floors).unwrap(), java_floors);
    assert_eq!(HWallItem::parse(&mut rust_walls).unwrap(), java_walls);
    assert_eq!(java_floors[0].owner_name.as_deref(), Some("Final"));
    assert_eq!(java_walls[0].owner_name.as_deref(), Some("Final"));
    let missing_floor = HFloorItem::parse(
        &mut Packet::from_bytes(observed["floor_missing_owner"].clone()).unwrap(),
    )
    .unwrap();
    let missing_wall =
        HWallItem::parse(&mut Packet::from_bytes(observed["wall_missing_owner"].clone()).unwrap())
            .unwrap();
    assert_eq!(missing_floor[0].owner_name, None);
    assert_eq!(missing_wall[0].owner_name, None);
    assert!(HFloorItem::construct(&missing_floor, 1).is_err());
    assert!(HWallItem::construct(&missing_wall, 1).is_err());
    let mut packet = Packet::new(1);
    inventory.append(&mut packet).unwrap();
    assert_eq!(packet.bytes(), observed["inventory"]);
    assert_eq!(
        HInventoryItem::read(&mut Packet::from_bytes(observed["inventory"].clone()).unwrap())
            .unwrap(),
        inventory
    );
    for flags in 0..8 {
        let key = format!("profile_{flags}");
        let profile = gearth_rust::parsers::social::HUserProfile::read(
            &mut Packet::from_bytes(observed[key.as_str()].clone()).unwrap(),
        )
        .unwrap();
        assert_eq!(profile.username, "Alice");
        assert_eq!(profile.motto, "Salut é");
        assert_eq!(profile.groups.len(), flags % 3);
        assert_eq!(
            (
                profile.is_friend,
                profile.is_requested_friend,
                profile.is_online
            ),
            (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0)
        );
        let mut normalized = Packet::new(1);
        profile.append(&mut normalized).unwrap();
        let normalized_key = format!("profile_normalized_{flags}");
        assert_eq!(
            normalized.bytes(),
            observed[normalized_key.as_str()],
            "{key}"
        );
    }
    assert!(gearth_rust::parsers::social::HUserProfile::read(
        &mut Packet::from_bytes(observed["profile_negative_groups"].clone()).unwrap()
    )
    .is_err());
    for (code, product) in [
        ("I", HProductType::WallItem),
        ("S", HProductType::FloorItem),
        ("E", HProductType::Effect),
        ("B", HProductType::Badge),
        ("s", HProductType::FloorItem),
    ] {
        for special in 1..=23 {
            let mut expected = inventory.clone();
            expected.product_type = product;
            expected.special_type = special;
            expected.floor_details =
                (product == HProductType::FloorItem).then(|| ("slot".into(), 7));
            let key = format!("inventory_item_{code}_{special}");
            let bytes = &observed[key.as_str()];
            let mut packet = Packet::new(1);
            expected.append(&mut packet).unwrap();
            assert_eq!(packet.bytes(), bytes, "{key}");
            assert_eq!(
                HInventoryItem::read(&mut Packet::from_bytes(bytes.clone()).unwrap()).unwrap(),
                expected,
                "{key}"
            );
        }
    }
    for size in [0usize, 1, 599, 600, 601, 1200, 1201] {
        let items = vec![inventory.clone(); size];
        let pages = HInventoryItem::construct_java_packets(&items, 44).unwrap();
        assert_eq!(pages.len(), size.div_ceil(600));
        for (index, page) in pages.iter().enumerate() {
            let key = format!("inventory_page_{size}_{index}");
            assert_eq!(page.bytes(), observed[key.as_str()], "{key}");
            let mut java_page = Packet::from_bytes(observed[key.as_str()].clone()).unwrap();
            java_page.set_cursor(6).unwrap();
            let parsed = HInventoryItem::parse_java(&mut java_page).unwrap();
            let expected_count = if index + 1 == pages.len() {
                size % 600
            } else {
                600
            };
            assert_eq!(parsed, vec![inventory.clone(); expected_count], "{key}");
            let mut summary = Packet::new(1);
            summary
                .put_i32(parsed.len() as i32)
                .unwrap()
                .put_i32(java_page.cursor() as i32)
                .unwrap();
            let parse_key = format!("inventory_parse_{size}_{index}");
            assert_eq!(summary.bytes(), observed[parse_key.as_str()], "{parse_key}");
        }
    }
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
    use gearth_rust::parsers::social::{HFriend, HFriendChange, HFriendUpdate};
    let mut update_packet = Packet::from_bytes(observed["friend_update_mixed"].clone()).unwrap();
    update_packet.set_cursor(10).unwrap();
    let update = HFriendUpdate::parse_java(&mut update_packet).unwrap();
    let mut summary = Packet::new(1);
    let friends: Vec<_> = update
        .changes
        .iter()
        .filter_map(|change| match change {
            HFriendChange::Upsert { friend, .. } => Some(friend),
            HFriendChange::Removed(_) => None,
        })
        .collect();
    summary
        .put_i32(friends.len() as i32)
        .unwrap()
        .put_i32(update_packet.cursor() as i32)
        .unwrap();
    for item in &friends {
        summary
            .put_i32(item.id)
            .unwrap()
            .put_bool(item.category_name.is_some())
            .unwrap();
        if let Some(name) = &item.category_name {
            summary.put_string(name).unwrap();
        }
        summary
            .put_i32(item.java_relationship_status().map_or(-1, i32::from))
            .unwrap();
    }
    let removed: Vec<_> = update
        .changes
        .iter()
        .filter_map(|change| match change {
            HFriendChange::Removed(id) => Some(*id),
            _ => None,
        })
        .collect();
    summary.put_i32(removed.len() as i32).unwrap();
    for id in removed {
        summary.put_i32(id).unwrap();
    }
    summary.put_i32(update_packet.cursor() as i32).unwrap();
    assert_eq!(summary.bytes(), observed["friend_update_summary"]);
    assert!(friends[2].append(&mut Packet::new(1)).is_err());
    for key in ["friend_negative_categories", "friend_negative_updates"] {
        let mut packet = Packet::from_bytes(observed[key].clone()).unwrap();
        assert!(HFriendUpdate::parse_java(&mut packet)
            .unwrap()
            .changes
            .is_empty());
    }
    let mut categorized = friend.clone();
    categorized.category_name = Some("Friends".into());
    assert_eq!(
        HFriend::construct_java_update(&[categorized], 3)
            .unwrap()
            .bytes(),
        observed["friend_construct_java"]
    );
    for size in [0usize, 1, 99, 100, 101, 200, 201] {
        let items = vec![friend.clone(); size];
        let pages = HFriend::construct_java_fragments(&items, 44).unwrap();
        assert_eq!(pages.len(), size.div_ceil(100));
        for (index, page) in pages.iter().enumerate() {
            let key = format!("friend_fragment_{size}_{index}");
            assert_eq!(page.bytes(), observed[key.as_str()], "{key}");
            let mut java_page = Packet::from_bytes(observed[key.as_str()].clone()).unwrap();
            java_page.set_cursor(6).unwrap();
            let parsed = HFriend::parse_fragment_java(&mut java_page).unwrap();
            let expected = if index + 1 == pages.len() {
                size % 100
            } else {
                100
            };
            assert_eq!(parsed, vec![friend.clone(); expected], "{key}");
            let mut summary = Packet::new(1);
            summary
                .put_i32(parsed.len() as i32)
                .unwrap()
                .put_i32(java_page.cursor() as i32)
                .unwrap();
            let parse_key = format!("friend_fragment_parse_{size}_{index}");
            assert_eq!(summary.bytes(), observed[parse_key.as_str()], "{parse_key}");
        }
    }
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
    use gearth_rust::parsers::catalog::{HCatalogIndex, HCatalogPage, HFrontPageTarget};
    let full =
        HCatalogPage::read(&mut Packet::from_bytes(observed["catalog_full"].clone()).unwrap())
            .unwrap();
    assert_eq!(full.images, ["image1", "image2"]);
    assert_eq!(full.texts, ["texte é", "text2"]);
    assert_eq!(full.offers.len(), 2);
    assert_eq!(full.offers[0].products.len(), 4);
    assert_eq!(full.offers[0].products[0].limited, Some((500, 17)));
    assert_eq!(
        full.offers[0].products[1].product_type,
        HProductType::WallItem
    );
    assert_eq!(full.offers[0].products[2].product_type, HProductType::Badge);
    assert_eq!(full.offers[0].products[2].extra_param, "badge-code");
    assert_eq!(
        full.offers[0].products[3].product_type,
        HProductType::Effect
    );
    assert!(full.offers[1].products.is_empty());
    assert_eq!(
        full.front_page_items
            .iter()
            .map(|item| &item.target)
            .collect::<Vec<_>>(),
        vec![
            &HFrontPageTarget::Page("page.path".into()),
            &HFrontPageTarget::Offer(555),
            &HFrontPageTarget::Product("product-code".into()),
            &HFrontPageTarget::Other(99)
        ]
    );
    let negative = HCatalogPage::read(
        &mut Packet::from_bytes(observed["catalog_negative_lists"].clone()).unwrap(),
    )
    .unwrap();
    assert!(negative.offers.is_empty() && negative.front_page_items.is_empty());
    assert!(HCatalogPage::read(
        &mut Packet::from_bytes(observed["catalog_negative_images"].clone()).unwrap()
    )
    .is_err());
    let negative_index = HCatalogIndex::read(
        &mut Packet::from_bytes(observed["catalog_index_negative_lists"].clone()).unwrap(),
    )
    .unwrap();
    assert!(negative_index.root.offer_ids.is_empty() && negative_index.root.children.is_empty());
    let mut tree_packet = Packet::from_bytes(observed["catalog_tree"].clone()).unwrap();
    let tree = HCatalogIndex::read(&mut tree_packet).unwrap();
    let root = &tree.root;
    let first = &root.children[0];
    let grandchild = &first.children[0];
    let mut tree_summary = Packet::new(1);
    tree_summary
        .put_i32(tree_packet.cursor() as i32)
        .unwrap()
        .put_bool(root.visible)
        .unwrap()
        .put_i32(root.offer_ids.len() as i32)
        .unwrap()
        .put_i32(root.children.len() as i32)
        .unwrap()
        .put_bool(first.visible)
        .unwrap()
        .put_i32(first.page_id)
        .unwrap()
        .put_i32(first.offer_ids[0])
        .unwrap()
        .put_i32(grandchild.page_id)
        .unwrap()
        .put_string(&grandchild.page_name)
        .unwrap()
        .put_i32(grandchild.offer_ids[1])
        .unwrap()
        .put_i32(root.children[1].page_id)
        .unwrap();
    assert_eq!(tree_summary.bytes(), observed["catalog_tree_summary"]);
    let depth64 = HCatalogIndex::read(
        &mut Packet::from_bytes(observed["catalog_tree_depth_64"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(depth64.root.page_id, 164);
    assert!(HCatalogIndex::read(
        &mut Packet::from_bytes(observed["catalog_tree_depth_65"].clone()).unwrap()
    )
    .is_err());
    let mut original = Packet::from_bytes(observed["navigator"].clone()).unwrap();
    let navigation =
        gearth_rust::parsers::navigator::NavigatorSearchResult::read(&mut original).unwrap();
    assert_eq!(navigation.blocks[0].rooms[0].group.as_ref().unwrap().0, 7);
    let mut encoded = Packet::new(1);
    navigation.append(&mut encoded).unwrap();
    assert_eq!(encoded.bytes(), observed["navigator"]);
    use gearth_rust::parsers::navigator::{NavigatorRoom, NavigatorSearchResult};
    for mask in 0..64 {
        for variant in 0..4 {
            let input_key = format!("navigator_room_input_{mask}_{variant}");
            let output_key = format!("navigator_room_output_{mask}_{variant}");
            let room = NavigatorRoom::read(
                &mut Packet::from_bytes(observed[input_key.as_str()].clone()).unwrap(),
            )
            .unwrap();
            let mut output = Packet::new(1);
            room.append(&mut output).unwrap();
            assert_eq!(output.bytes(), observed[output_key.as_str()], "{input_key}");
        }
    }
    for kind in ["blocks", "rooms"] {
        let key = format!("navigator_negative_{kind}");
        let result = NavigatorSearchResult::read(
            &mut Packet::from_bytes(observed[key.as_str()].clone()).unwrap(),
        )
        .unwrap();
        let mut normalized = Packet::new(1);
        result.append(&mut normalized).unwrap();
        let normalized_key = format!("{key}_normalized");
        assert_eq!(
            normalized.bytes(),
            observed[normalized_key.as_str()],
            "{key}"
        );
    }
    assert!(NavigatorRoom::read(
        &mut Packet::from_bytes(observed["navigator_negative_tags"].clone()).unwrap()
    )
    .is_err());
    let comments = gearth_rust::parsers::forums::CommentOverview::read(
        &mut Packet::from_bytes(observed["comments"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        comments.comments[0].state,
        gearth_rust::parsers::forums::ThreadState::HiddenByAdmin
    );
    assert_eq!(comments.comments[0].author_post_count, 9);
    let mut encoded_comments = Packet::new(1);
    comments.append(&mut encoded_comments).unwrap();
    assert_eq!(encoded_comments.bytes(), observed["comments"]);
    use gearth_rust::parsers::forums::{
        CommentOverview, ForumOverview, ThreadOverview, ThreadState,
    };
    let threads =
        ThreadOverview::read(&mut Packet::from_bytes(observed["forum_threads"].clone()).unwrap())
            .unwrap();
    assert_eq!(
        (threads.guild_id, threads.start_index, threads.threads.len()),
        (42, 3, 5)
    );
    assert_eq!(
        threads.threads.iter().map(|t| t.state).collect::<Vec<_>>(),
        vec![
            ThreadState::Open,
            ThreadState::HiddenByAdmin,
            ThreadState::HiddenByStaff,
            ThreadState::Open,
            ThreadState::Open
        ]
    );
    assert!(threads.threads[0].pinned && !threads.threads[0].locked);
    assert!(!threads.threads[1].pinned && threads.threads[1].locked);
    let mut normalized_threads = Packet::new(1);
    threads.append(&mut normalized_threads).unwrap();
    assert_eq!(
        normalized_threads.bytes(),
        observed["forum_threads_normalized"]
    );
    assert!(ThreadOverview::read(
        &mut Packet::from_bytes(observed["forum_threads_negative"].clone()).unwrap()
    )
    .unwrap()
    .threads
    .is_empty());
    assert!(ForumOverview::read(
        &mut Packet::from_bytes(observed["forum_overview_negative"].clone()).unwrap()
    )
    .unwrap()
    .forums
    .is_empty());
    assert!(CommentOverview::read(
        &mut Packet::from_bytes(observed["forum_comments_negative"].clone()).unwrap()
    )
    .unwrap()
    .comments
    .is_empty());
    for mode in [0, 1, 2, 99] {
        let key = format!("forum_overview_{mode}");
        let overview =
            ForumOverview::read(&mut Packet::from_bytes(observed[key.as_str()].clone()).unwrap())
                .unwrap();
        assert_eq!(
            (overview.size, overview.start_index, overview.forums.len()),
            (100, 5, 3)
        );
        assert_eq!(overview.forums[1].guild_id, 21);
        assert_eq!(overview.forums[1].guild_description, "Description é1");
        let mut normalized = Packet::new(1);
        overview.append(&mut normalized).unwrap();
        let normalized_key = format!("forum_overview_normalized_{mode}");
        assert_eq!(
            normalized.bytes(),
            observed[normalized_key.as_str()],
            "{key}"
        );
    }
    let entities = gearth_rust::parsers::entity::HEntity::parse(
        &mut Packet::from_bytes(observed["entities"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(entities.len(), 4);
    assert!(matches!(
        entities[0].details,
        gearth_rust::parsers::entity::HEntityDetails::Habbo { .. }
    ));
    assert!(matches!(
        entities[1].details,
        gearth_rust::parsers::entity::HEntityDetails::Pet { .. }
    ));
    assert!(matches!(
        entities[3].details,
        gearth_rust::parsers::entity::HEntityDetails::Bot { .. }
    ));
    assert_eq!(entities[1].tile.z, 3.5);
    use gearth_rust::parsers::entity::{HEntity, HEntityDetails, HEntityUpdate};
    for kind in [0, -1, 5, i32::MAX] {
        let key = format!("entity_unknown_{kind}");
        let mut packet = Packet::from_bytes(observed[key.as_str()].clone()).unwrap();
        let entity = HEntity::read(&mut packet).unwrap();
        assert_eq!(entity.details, HEntityDetails::Unknown(kind));
        assert_eq!(packet.cursor(), packet.bytes().len());
        assert!(entity.append_java(&mut Packet::new(1)).is_err());
    }
    for i in 0..8 {
        let key = format!("entity_gender_input_{i}");
        let entity =
            HEntity::read(&mut Packet::from_bytes(observed[key.as_str()].clone()).unwrap())
                .unwrap();
        let mut output = Packet::new(1);
        if i < 6 {
            entity.append_java(&mut output).unwrap();
            let output_key = format!("entity_gender_output_{i}");
            assert_eq!(output.bytes(), observed[output_key.as_str()], "{key}");
            if i == 0 {
                assert_eq!(
                    HEntity::construct_java(std::slice::from_ref(&entity), 1)
                        .unwrap()
                        .bytes(),
                    observed["entity_habbo_construct"]
                );
            }
        } else {
            assert!(entity.append_java(&mut output).is_err(), "{key}");
        }
    }
    let bot = HEntity::read(
        &mut Packet::from_bytes(observed["entity_bot_negative_skills"].clone()).unwrap(),
    )
    .unwrap();
    assert!(matches!(&bot.details, HEntityDetails::Bot { skills, .. } if skills.is_empty()));
    let mut normalized_bot = Packet::new(1);
    bot.append_java(&mut normalized_bot).unwrap();
    assert_eq!(
        normalized_bot.bytes(),
        observed["entity_bot_negative_skills_normalized"]
    );
    assert!(HEntity::parse(
        &mut Packet::from_bytes(observed["entity_negative_count"].clone()).unwrap()
    )
    .is_err());
    assert!(HEntityUpdate::parse(
        &mut Packet::from_bytes(observed["entity_update_negative_count"].clone()).unwrap()
    )
    .is_err());
    for direction in [-1, 8] {
        let key = format!("entity_update_direction_{direction}");
        assert!(
            HEntityUpdate::parse(&mut Packet::from_bytes(observed[key.as_str()].clone()).unwrap())
                .is_err(),
            "{key}"
        );
    }
}
