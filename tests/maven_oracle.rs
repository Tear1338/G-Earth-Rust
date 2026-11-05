use gearth_rust::extension_store::compare_versions;
use std::cmp::Ordering;

#[test]
#[ignore = "requires oracle generated from the original Maven JAR"]
fn version_order_matches_original_maven() {
    let path = std::env::var("GEARTH_MAVEN_ORACLE").expect("oracle path");
    let vectors = std::fs::read_to_string(path).expect("read oracle");
    let mut count = 0;
    for line in vectors.lines() {
        let mut fields = line.split('\t');
        let a = fields.next().unwrap();
        let b = fields.next().unwrap();
        let expected = match fields.next().unwrap() {
            "-1" => Ordering::Less,
            "0" => Ordering::Equal,
            "1" => Ordering::Greater,
            other => panic!("invalid oracle value: {other}"),
        };
        assert_eq!(compare_versions(a, b), expected, "{a} versus {b}");
        count += 1;
    }
    assert!(count > 2000);
}
