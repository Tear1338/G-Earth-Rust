//! Canonical names generated from JDK 21's Character.getName/codePointOf.
use std::io::Read;
use std::sync::OnceLock;

struct Names {
    data: Vec<u8>,
    offsets: Vec<usize>,
}

fn names() -> &'static Names {
    static NAMES: OnceLock<Names> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(&include_bytes!("../resources/java21-character-names.gz")[..])
            .read_to_end(&mut data)
            .expect("embedded Java character names must decompress");
        let count = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
        let mut offsets = Vec::with_capacity(count);
        let mut at = 4;
        for _ in 0..count {
            offsets.push(at);
            let len = u16::from_be_bytes(data[at..at + 2].try_into().unwrap()) as usize;
            at += 2 + len + 4;
        }
        assert_eq!(at, data.len());
        Names { data, offsets }
    })
}

pub(crate) fn code_point_of(name: &str) -> Option<u32> {
    // Java String.trim removes only characters through U+0020.
    let name = name.trim_matches(|c| c <= '\u{20}').to_uppercase();
    let names = names();
    let found = names
        .offsets
        .binary_search_by(|offset| {
            let at = *offset;
            let len = u16::from_be_bytes(names.data[at..at + 2].try_into().unwrap()) as usize;
            names.data[at + 2..at + 2 + len].cmp(name.as_bytes())
        })
        .ok()?;
    let at = names.offsets[found];
    let len = u16::from_be_bytes(names.data[at..at + 2].try_into().unwrap()) as usize;
    Some(u32::from_be_bytes(
        names.data[at + 2 + len..at + 6 + len].try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn java_character_name_examples() {
        assert_eq!(names().offsets.len(), 288_767);
        assert_eq!(code_point_of(" latin capital letter a "), Some(65));
        assert_eq!(code_point_of("CJK UNIFIED IDEOGRAPHS 4E00"), Some(0x4e00));
        assert_eq!(code_point_of("HIGH SURROGATES D800"), Some(0xd800));
        assert_eq!(code_point_of("BYTE ORDER MARK"), None);
    }

    #[test]
    fn every_generated_name_is_sorted_and_resolves() {
        let names = names();
        let mut previous = "";
        for &at in &names.offsets {
            let len = u16::from_be_bytes(names.data[at..at + 2].try_into().unwrap()) as usize;
            let name = std::str::from_utf8(&names.data[at + 2..at + 2 + len]).unwrap();
            let value =
                u32::from_be_bytes(names.data[at + 2 + len..at + 6 + len].try_into().unwrap());
            assert!(previous < name);
            assert_eq!(code_point_of(name), Some(value), "{name}");
            previous = name;
        }
    }
}
