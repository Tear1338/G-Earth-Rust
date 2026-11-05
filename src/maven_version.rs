// Derived from Apache Maven ComparableVersion (Apache License 2.0).
// https://github.com/apache/maven/blob/maven-3.9.15/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java
use std::cmp::Ordering;

#[derive(Debug)]
enum Item {
    Number(String),
    Qualifier(String),
    List(usize),
}

struct Version {
    lists: Vec<Vec<Item>>,
}

fn qualifier(value: &str) -> (u8, &str) {
    match value {
        "alpha" => (0, ""),
        "beta" => (1, ""),
        "milestone" => (2, ""),
        "rc" | "cr" => (3, ""),
        "snapshot" => (4, ""),
        "" | "ga" | "final" | "release" => (5, ""),
        "sp" => (6, ""),
        other => (7, other),
    }
}

impl Version {
    fn parse(input: &str) -> Self {
        let input = input.to_lowercase();
        let mut version = Self {
            lists: vec![vec![]],
        };
        let mut current = 0;
        let mut start = 0;
        let mut numeric = false;
        for (i, ch) in input.char_indices() {
            if ch == '.' || ch == '-' {
                version.add(current, &input[start..i], numeric, false);
                start = i + ch.len_utf8();
                if ch == '-' {
                    current = version.nest(current);
                }
            } else if ch.is_ascii_digit() {
                if !numeric && i > start {
                    if !version.lists[current].is_empty() {
                        current = version.nest(current);
                    }
                    version.add(current, &input[start..i], false, true);
                    start = i;
                    current = version.nest(current);
                }
                numeric = true;
            } else {
                if numeric && i > start {
                    version.add(current, &input[start..i], true, false);
                    start = i;
                    current = version.nest(current);
                }
                numeric = false;
            }
        }
        if start < input.len() {
            if !numeric && !version.lists[current].is_empty() {
                current = version.nest(current);
            }
            version.add(current, &input[start..], numeric, false);
        }
        for index in (0..version.lists.len()).rev() {
            let mut cursor = version.lists[index].len();
            while cursor > 0 {
                cursor -= 1;
                let item = &version.lists[index][cursor];
                let null = match item {
                    Item::Number(n) => n == "0",
                    Item::Qualifier(q) => qualifier(q).0 == 5,
                    Item::List(i) => version.lists[*i].is_empty(),
                };
                if null {
                    version.lists[index].remove(cursor);
                } else if matches!(item, Item::List(_)) {
                    continue;
                } else {
                    break;
                }
            }
        }
        version
    }
    fn nest(&mut self, parent: usize) -> usize {
        let index = self.lists.len();
        self.lists.push(vec![]);
        self.lists[parent].push(Item::List(index));
        index
    }
    fn add(&mut self, list: usize, value: &str, numeric: bool, followed_by_digit: bool) {
        let item = if value.is_empty() || numeric {
            let number = value.trim_start_matches('0');
            Item::Number(if number.is_empty() { "0" } else { number }.into())
        } else {
            let value = if followed_by_digit {
                match value {
                    "a" => "alpha",
                    "b" => "beta",
                    "m" => "milestone",
                    _ => value,
                }
            } else {
                value
            };
            Item::Qualifier(value.into())
        };
        self.lists[list].push(item);
    }
    fn compare_item(&self, left: Option<&Item>, other: &Self, right: Option<&Item>) -> Ordering {
        match (left, right) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => other.compare_item(right, self, None).reverse(),
            (Some(Item::Number(a)), None) => (a != "0").cmp(&false),
            (Some(Item::Qualifier(a)), None) => qualifier(a).cmp(&qualifier("")),
            (Some(Item::List(a)), None) => self.compare_list(*a, other, None),
            (Some(Item::Number(a)), Some(Item::Number(b))) => a.len().cmp(&b.len()).then(a.cmp(b)),
            (Some(Item::Number(_)), Some(_)) => Ordering::Greater,
            (Some(Item::Qualifier(a)), Some(Item::Qualifier(b))) => qualifier(a).cmp(&qualifier(b)),
            (Some(Item::Qualifier(_)), Some(_)) => Ordering::Less,
            (Some(Item::List(_)), Some(Item::Number(_))) => Ordering::Less,
            (Some(Item::List(_)), Some(Item::Qualifier(_))) => Ordering::Greater,
            (Some(Item::List(a)), Some(Item::List(b))) => self.compare_list(*a, other, Some(*b)),
        }
    }
    fn compare_list(&self, left: usize, other: &Self, right: Option<usize>) -> Ordering {
        let a = &self.lists[left];
        let b = right
            .map(|index| other.lists[index].as_slice())
            .unwrap_or(&[]);
        for i in 0..a.len().max(b.len()) {
            let result = self.compare_item(a.get(i), other, b.get(i));
            if result != Ordering::Equal {
                return result;
            }
        }
        Ordering::Equal
    }
}

pub(crate) fn compare(a: &str, b: &str) -> Ordering {
    // Store metadata is bounded; prevent deeply nested untrusted version strings
    // from overflowing the stack in other callers such as the Python probe.
    if a.len() > 512 || b.len() > 512 {
        return a.cmp(b);
    }
    let left = Version::parse(a);
    let right = Version::parse(b);
    left.compare_list(0, &right, Some(0))
}
