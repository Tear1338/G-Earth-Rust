use gearth_rust::{packet::Direction, packet_info::PacketInfoManager};
#[test]
fn cache_preserves_direction_and_names_and_rejects_mismatched_or_truncated_data(){
    let mut random=[0;8];getrandom::fill(&mut random).unwrap();let path=std::env::temp_dir().join(format!("gearth-packet-cache-{}.bin",u64::from_ne_bytes(random)));
    let database=PacketInfoManager::from_json("TEST",br#"{"Incoming":[{"Id":77,"Name":"Same"}],"Outgoing":[{"Id":78,"Name":"Same"}]}"#).unwrap();database.save_cache(&path).unwrap();
    let copy=PacketInfoManager::load_cache(&path,"TEST").unwrap();assert_eq!(copy.entries(),database.entries());assert!(PacketInfoManager::load_cache(&path,"OTHER").is_err());
    let mut bytes=std::fs::read(&path).unwrap();bytes.pop();std::fs::write(&path,bytes).unwrap();assert!(PacketInfoManager::load_cache(&path,"TEST").is_err());database.save_cache(&path).unwrap();assert_eq!(PacketInfoManager::load_cache(&path,"TEST").unwrap().entries(),database.entries());std::fs::remove_file(path).unwrap();
}
#[test]
fn sulek_names_match_upstream_suffix_rules_and_directions() {
    let json=br#"{"messages":{"incoming":[{"id":42,"name":"UsersMessageEvent"},{"id":43,"name":"KeepEventInsideName"}],"outgoing":[{"id":77,"name":"ChatMessageComposer"},{"id":78,"name":"WaveComposer"}]}}"#;
    let db = PacketInfoManager::from_json("TEST", json).unwrap();
    assert_eq!(db.by_name(Direction::ToClient, "Users").unwrap().header, 42);
    assert_eq!(db.by_name(Direction::ToServer, "Chat").unwrap().header, 77);
    assert_eq!(db.by_name(Direction::ToServer, "Wave").unwrap().header, 78);
    assert!(db
        .by_name(Direction::ToClient, "KeepEventInsideName")
        .is_some());
    assert!(db.by_name(Direction::ToClient, "Chat").is_none());
}
#[test]
fn unity_names_are_preserved_and_malformed_database_is_rejected() {
    let db=PacketInfoManager::from_json("UNITY",br#"{"Incoming":[{"Id":77,"Name":"ChatEvent"}],"Outgoing":[{"Id":77,"Name":"ChatComposer"}]}"#).unwrap();
    assert_eq!(
        db.by_name(Direction::ToClient, "ChatEvent").unwrap().source,
        "G-Earth"
    );
    assert_eq!(
        db.by_name(Direction::ToServer, "ChatComposer")
            .unwrap()
            .header,
        77
    );
    for json in [
        r#"{"Incoming":[],"Outgoing":[{"Id":65536,"Name":"Invalid"}]}"#,
        r#"{"messages":{"incoming":[],"outgoing":[{"id":-1,"name":"Invalid"}]}}"#,
        r#"{"Incoming":[]}"#,
    ] {
        assert!(PacketInfoManager::from_json("TEST", json.as_bytes()).is_err());
    }
}
