//! Furniture state formats from the beta-29 extension API.
use crate::packet::{error, Packet, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighScoreEntry {
    pub score: i32,
    pub users: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StuffValue {
    Legacy(String),
    Map(BTreeMap<String, String>),
    Strings(Vec<String>),
    Vote {
        state: String,
        result: i32,
    },
    Empty,
    Integers(Vec<i32>),
    HighScore {
        state: String,
        score_type: i32,
        clear_type: i32,
        entries: Vec<HighScoreEntry>,
    },
    Crackable {
        state: String,
        hits: i32,
        target: i32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StuffData {
    pub flags: i32,
    pub serial: Option<(i32, i32)>,
    pub value: StuffValue,
}

fn count(packet: &mut Packet) -> Result<usize> {
    let n = usize::try_from(packet.read_i32()?).map_err(|_| error("negative stuff-data count"))?;
    if n > 65_536 {
        return Err(error("stuff-data count exceeds limit"));
    }
    Ok(n)
}

// Java collection loops simply skip negative counts; its arrays reject them.
fn collection_count(packet: &mut Packet) -> Result<usize> {
    let n = packet.read_i32()?.max(0) as usize;
    if n > 65_536 {
        return Err(error("stuff-data count exceeds limit"));
    }
    Ok(n)
}

fn size(n: usize) -> Result<i32> {
    if n > 65_536 {
        return Err(error("stuff-data count exceeds limit"));
    }
    Ok(n as i32)
}

impl StuffData {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let tag = packet.read_i32()?;
        let flags = tag & 0xff00;
        let value = match tag & 0xff {
            0 => StuffValue::Legacy(packet.read_string()?),
            1 => {
                let mut map = BTreeMap::new();
                for _ in 0..collection_count(packet)? {
                    map.insert(packet.read_string()?, packet.read_string()?);
                }
                StuffValue::Map(map)
            }
            2 => {
                let mut items = Vec::new();
                for _ in 0..collection_count(packet)? {
                    items.push(packet.read_string()?);
                }
                StuffValue::Strings(items)
            }
            3 => StuffValue::Vote {
                state: packet.read_string()?,
                result: packet.read_i32()?,
            },
            4 => StuffValue::Empty,
            5 => {
                let mut items = Vec::new();
                for _ in 0..collection_count(packet)? {
                    items.push(packet.read_i32()?);
                }
                StuffValue::Integers(items)
            }
            6 => {
                let state = packet.read_string()?;
                let score_type = packet.read_i32()?;
                let clear_type = packet.read_i32()?;
                let mut entries = Vec::new();
                for _ in 0..count(packet)? {
                    let score = packet.read_i32()?;
                    let mut users = Vec::new();
                    for _ in 0..count(packet)? {
                        users.push(packet.read_string()?);
                    }
                    entries.push(HighScoreEntry { score, users });
                }
                StuffValue::HighScore {
                    state,
                    score_type,
                    clear_type,
                    entries,
                }
            }
            7 => StuffValue::Crackable {
                state: packet.read_string()?,
                hits: packet.read_i32()?,
                target: packet.read_i32()?,
            },
            _ => return Err(error("unknown stuff-data type")),
        };
        // The upstream HighScore type does not call StuffDataBase.initialize.
        let serial = if flags & 256 != 0 && !matches!(value, StuffValue::HighScore { .. }) {
            Some((packet.read_i32()?, packet.read_i32()?))
        } else {
            None
        };
        Ok(Self {
            flags,
            serial,
            value,
        })
    }

    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        if self.flags & !0xff00 != 0 {
            return Err(error("invalid stuff-data flags"));
        }
        let tag = match &self.value {
            StuffValue::Legacy(_) => 0,
            StuffValue::Map(_) => 1,
            StuffValue::Strings(_) => 2,
            StuffValue::Vote { .. } => 3,
            StuffValue::Empty => 4,
            StuffValue::Integers(_) => 5,
            StuffValue::HighScore { .. } => 6,
            StuffValue::Crackable { .. } => 7,
        };
        let has_serial = self.flags & 256 != 0 && tag != 6;
        if has_serial != self.serial.is_some() {
            return Err(error("stuff-data serial does not match flags"));
        }
        packet.put_i32(tag | self.flags)?;
        match &self.value {
            StuffValue::Legacy(s) => {
                packet.put_string(s)?;
            }
            StuffValue::Map(m) => {
                packet.put_i32(size(m.len())?)?;
                for (k, v) in m {
                    packet.put_string(k)?.put_string(v)?;
                }
            }
            StuffValue::Strings(a) => {
                packet.put_i32(size(a.len())?)?;
                for s in a {
                    packet.put_string(s)?;
                }
            }
            StuffValue::Vote { state, result } => {
                packet.put_string(state)?.put_i32(*result)?;
            }
            StuffValue::Empty => {}
            StuffValue::Integers(a) => {
                packet.put_i32(size(a.len())?)?;
                for n in a {
                    packet.put_i32(*n)?;
                }
            }
            StuffValue::HighScore {
                state,
                score_type,
                clear_type,
                entries,
            } => {
                packet
                    .put_string(state)?
                    .put_i32(*score_type)?
                    .put_i32(*clear_type)?
                    .put_i32(size(entries.len())?)?;
                for e in entries {
                    packet.put_i32(e.score)?.put_i32(size(e.users.len())?)?;
                    for u in &e.users {
                        packet.put_string(u)?;
                    }
                }
            }
            StuffValue::Crackable {
                state,
                hits,
                target,
            } => {
                packet.put_string(state)?.put_i32(*hits)?.put_i32(*target)?;
            }
        }
        if let Some((number, total)) = self.serial {
            packet.put_i32(number)?.put_i32(total)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_upstream_variants_round_trip_including_serials() {
        let values = [
            StuffValue::Legacy("1".into()),
            StuffValue::Map(BTreeMap::from([("state".into(), "2".into())])),
            StuffValue::Strings(vec!["a".into()]),
            StuffValue::Vote {
                state: "x".into(),
                result: 3,
            },
            StuffValue::Empty,
            StuffValue::Integers(vec![1, -2]),
            StuffValue::HighScore {
                state: "x".into(),
                score_type: 1,
                clear_type: 2,
                entries: vec![HighScoreEntry {
                    score: 7,
                    users: vec!["Alice".into()],
                }],
            },
            StuffValue::Crackable {
                state: "z".into(),
                hits: 4,
                target: 5,
            },
        ];
        for value in values {
            let high = matches!(value, StuffValue::HighScore { .. });
            let expected = StuffData {
                flags: 256,
                serial: if high { None } else { Some((13, 20)) },
                value,
            };
            let mut packet = Packet::new(1);
            expected.append(&mut packet).unwrap();
            assert_eq!(StuffData::read(&mut packet).unwrap(), expected);
        }
    }
}
