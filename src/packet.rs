use std::borrow::Cow;
use std::fmt;
use std::io::{self, Read, Write};

// Java's UTF-8 decoder consumes a whole encoded surrogate as one malformed
// sequence; Rust's standard lossy decoder replaces its bytes separately.
fn java_utf8_lossy(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(valid) = std::str::from_utf8(bytes) {
        return Cow::Borrowed(valid);
    }
    let mut output = String::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                output.push_str(valid);
                break;
            }
            Err(error) => {
                let prefix = error.valid_up_to();
                output.push_str(std::str::from_utf8(&remaining[..prefix]).expect("UTF-8 prefix"));
                remaining = &remaining[prefix..];
                let consumed = if remaining.len() >= 2
                    && remaining[0] == 0xed
                    && (0xa0..=0xbf).contains(&remaining[1])
                {
                    if remaining.len() >= 3 && (0x80..=0xbf).contains(&remaining[2]) {
                        3
                    } else {
                        2
                    }
                } else {
                    error.error_len().unwrap_or(remaining.len())
                };
                output.push('\u{fffd}');
                remaining = &remaining[consumed..];
            }
        }
    }
    Cow::Owned(output)
}
// Java UTF-16BE replacement decoding consumes a high surrogate together with
// the following non-low code unit (or incomplete final byte) as one error.
fn decode_utf16be(bytes: &[u8], lossy: bool) -> Result<String> {
    decode_utf16(bytes, Utf16Encoding::BigEndian, lossy)
}

fn decode_utf16(bytes: &[u8], encoding: Utf16Encoding, lossy: bool) -> Result<String> {
    let mut output = String::new();
    let (little, mut offset) = match encoding {
        Utf16Encoding::BigEndian => (false, 0),
        Utf16Encoding::LittleEndian => (true, 0),
        Utf16Encoding::WithBom if bytes.starts_with(&[0xfe, 0xff]) => (false, 2),
        Utf16Encoding::WithBom if bytes.starts_with(&[0xff, 0xfe]) => (true, 2),
        Utf16Encoding::WithBom => (false, 0),
    };
    let read_unit = |offset: usize| {
        let bytes = [bytes[offset], bytes[offset + 1]];
        if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    while offset < bytes.len() {
        if bytes.len() - offset < 2 {
            if !lossy {
                return Err(error("invalid UTF-16"));
            }
            output.push('\u{fffd}');
            break;
        }
        let unit = read_unit(offset);
        offset += 2;
        if (0xd800..=0xdbff).contains(&unit) {
            if bytes.len() - offset < 2 {
                if !lossy {
                    return Err(error("invalid UTF-16"));
                }
                output.push('\u{fffd}');
                break;
            }
            let next = read_unit(offset);
            offset += 2;
            if (0xdc00..=0xdfff).contains(&next) {
                let value =
                    0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(next) - 0xdc00);
                output.push(char::from_u32(value).expect("valid surrogate pair"));
            } else if lossy {
                output.push('\u{fffd}');
            } else {
                return Err(error("invalid UTF-16"));
            }
        } else if (0xdc00..=0xdfff).contains(&unit) {
            if !lossy {
                return Err(error("invalid UTF-16"));
            }
            output.push('\u{fffd}');
        } else {
            output.push(char::from_u32(u32::from(unit)).expect("non-surrogate code unit"));
        }
    }
    Ok(output)
}

fn encode_utf16be(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// Java UTF-16 variants: explicit byte order or BOM-sensitive UTF-16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Utf16Encoding {
    BigEndian,
    LittleEndian,
    WithBom,
}

/// Encodings supported for Java strings supplied as UTF-16 code units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaStringEncoding {
    Latin1,
    Utf8,
    Utf16(Utf16Encoding),
}

// Java String may contain unpaired UTF-16 surrogates. Its encoders replace
// them with '?' for Latin-1/UTF-8 and U+FFFD for UTF-16 variants.
fn encode_java_units(units: &[u16], encoding: JavaStringEncoding, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if encoding == JavaStringEncoding::Utf16(Utf16Encoding::WithBom) && !units.is_empty() {
        bytes.extend_from_slice(&[0xfe, 0xff]);
    }
    for item in char::decode_utf16(units.iter().copied()) {
        let character = match item {
            Ok(value) => value,
            Err(_) if matches!(encoding, JavaStringEncoding::Utf16(_)) => '\u{fffd}',
            Err(_) => '?',
        };
        let mut buffer = [0u8; 4];
        let encoded: &[u8] = match encoding {
            JavaStringEncoding::Latin1 => {
                buffer[0] = u8::try_from(character as u32).unwrap_or(b'?');
                &buffer[..1]
            }
            JavaStringEncoding::Utf8 => character.encode_utf8(&mut buffer).as_bytes(),
            JavaStringEncoding::Utf16(order) => {
                let mut words = [0u16; 2];
                let words = character.encode_utf16(&mut words);
                let len = words.len() * 2;
                for (index, unit) in words.iter().enumerate() {
                    let pair = if order == Utf16Encoding::LittleEndian {
                        unit.to_le_bytes()
                    } else {
                        unit.to_be_bytes()
                    };
                    buffer[index * 2..index * 2 + 2].copy_from_slice(&pair);
                }
                &buffer[..len]
            }
        };
        if bytes
            .len()
            .checked_add(encoded.len())
            .is_none_or(|len| len > max)
        {
            return Err(error("encoded string too long"));
        }
        bytes.extend_from_slice(encoded);
    }
    Ok(bytes)
}

fn encode_utf16(value: &str, encoding: Utf16Encoding) -> Vec<u8> {
    let mut bytes = Vec::new();
    if encoding == Utf16Encoding::WithBom && !value.is_empty() {
        bytes.extend_from_slice(&[0xfe, 0xff]);
    }
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&if encoding == Utf16Encoding::LittleEndian {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        });
    }
    bytes
}

fn utf16_byte_len(value: &str, encoding: Utf16Encoding) -> Option<usize> {
    value
        .encode_utf16()
        .count()
        .checked_mul(2)?
        .checked_add(usize::from(encoding == Utf16Encoding::WithBom && !value.is_empty()) * 2)
}

pub const MAX_FRAME: usize = 16 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError(pub String);
impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PacketError {}
pub type Result<T> = std::result::Result<T, PacketError>;
pub fn error(message: &str) -> PacketError {
    PacketError(message.to_owned())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    ToServer,
    ToClient,
}
impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Self::ToServer => "TOSERVER",
            Self::ToClient => "TOCLIENT",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "TOSERVER" => Ok(Self::ToServer),
            "TOCLIENT" => Ok(Self::ToClient),
            _ => Err(error("invalid direction")),
        }
    }
}
/// Types accepted by beta-29 HPacket.appendObject for EVA packets.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketField<'a> {
    Byte(i8),
    Short(i16),
    Integer(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Boolean(bool),
    String(&'a str),
    /// Encode unmappable characters as `?`, as Java's default Latin-1 encoder does.
    StringJava(&'a str),
    /// Java String represented as UTF-16 units, including unpaired surrogates.
    StringUnits(&'a [u16], JavaStringEncoding),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketFormat {
    #[default]
    EvaWire,
    WedgieIncoming,
    WedgieOutgoing,
}
impl PacketFormat {
    pub fn id(self) -> i32 {
        match self {
            Self::EvaWire => 0,
            Self::WedgieIncoming => 1,
            Self::WedgieOutgoing => 2,
        }
    }
    pub fn from_id(id: i32) -> Result<Self> {
        match id {
            0 => Ok(Self::EvaWire),
            1 => Ok(Self::WedgieIncoming),
            2 => Ok(Self::WedgieOutgoing),
            _ => Err(error("unknown packet format")),
        }
    }
    pub fn body_offset(self) -> usize {
        if self == Self::EvaWire {
            6
        } else {
            2
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    format: PacketFormat,
    bytes: Vec<u8>,
    cursor: usize,
    pub edited: bool,
}
fn expand_literal_groups(
    replacement: &str,
    whole: &str,
    groups: &[String],
    names: &[Option<String>],
) -> Result<String> {
    let mut expanded = String::new();
    let mut chars = replacement.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => expanded.push(
                chars
                    .next()
                    .ok_or_else(|| error("invalid replacement escape"))?,
            ),
            '$' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut name = String::new();
                    loop {
                        match chars.next() {
                            Some('}') => break,
                            Some(c) if c.is_ascii_alphanumeric() => {
                                if name.len() == usize::from(u16::MAX) {
                                    return Err(error("replacement group name too long"));
                                }
                                name.push(c);
                            }
                            _ => return Err(error("invalid named replacement group")),
                        }
                    }
                    let index = names
                        .iter()
                        .position(|candidate| candidate.as_deref() == Some(name.as_str()))
                        .ok_or_else(|| error("unknown named replacement group"))?;
                    expanded.push_str(&groups[index]);
                    if expanded.len() > usize::from(u16::MAX) * 2 {
                        return Err(error("short string too long"));
                    }
                    continue;
                }
                let mut group = chars
                    .next()
                    .and_then(|c| c.to_digit(10))
                    .filter(|n| (*n as usize) <= groups.len())
                    .ok_or_else(|| error("invalid replacement group"))?
                    as usize;
                while let Some(next) = chars.peek().and_then(|c| c.to_digit(10)) {
                    let candidate = group * 10 + next as usize;
                    if candidate > groups.len() {
                        break;
                    }
                    group = candidate;
                    chars.next();
                }
                expanded.push_str(if group == 0 {
                    whole
                } else {
                    &groups[group - 1]
                });
            }
            _ => expanded.push(c),
        }
        if expanded.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
    }
    Ok(expanded)
}

enum FixedRegexAtom {
    Literal(u8),
    CaseInsensitive(u8),
    UnicodeCaseInsensitive(u8),
    Dot,
    DotUnix,
    DotAll,
    Start,
    StartLine,
    StartLineUnix,
    End,
    EndUnix,
    EndLine,
    EndLineUnix,
    EndStrict,
    WordBoundary,
    NonWordBoundary,
    UnicodeWordBoundary,
    UnicodeNonWordBoundary,
    Class(Box<[bool; 256]>),
}

fn unicode_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || byte == b'_'
        || matches!(byte, 0xaa | 0xb5 | 0xba | 0xc0..=0xd6 | 0xd8..=0xf6 | 0xf8..=0xff)
}

fn predefined_class(kind: char, unicode: bool) -> Option<Box<[bool; 256]>> {
    let (base, negated) = match kind {
        'd' => ('d', false),
        'D' => ('d', true),
        'w' => ('w', false),
        'W' => ('w', true),
        's' => ('s', false),
        'S' => ('s', true),
        _ => return None,
    };
    let mut class = Box::new([false; 256]);
    for byte in 0u8..=u8::MAX {
        let included = match base {
            'd' => byte.is_ascii_digit(),
            'w' => {
                if unicode {
                    unicode_word(byte)
                } else {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                }
            }
            's' => {
                matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
                    || (unicode && matches!(byte, 0x85 | 0xa0))
            }
            _ => unreachable!(),
        };
        class[usize::from(byte)] = included != negated;
    }
    Some(class)
}

fn control_escape(
    kind: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<Option<u8>> {
    let value = match kind {
        't' => b'\t',
        'n' => b'\n',
        'r' => b'\r',
        'f' => 0x0c,
        'a' => 0x07,
        'e' => 0x1b,
        'x' | 'u' => {
            let digits = if kind == 'x' { 2 } else { 4 };
            let mut value = 0u32;
            for _ in 0..digits {
                let digit = chars
                    .next()
                    .and_then(|c| c.to_digit(16))
                    .ok_or_else(|| error("invalid regex hex escape"))?;
                value = value * 16 + digit;
            }
            u8::try_from(value).map_err(|_| error("regex escape outside Latin-1"))?
        }
        _ => return Ok(None),
    };
    Ok(Some(value))
}

// Java COMMENTS mode skips ASCII whitespace and # comments while parsing,
// including inside character classes. Escaped and quoted characters stay literal.
fn regex_skip_layout(chars: &[char], mut at: usize, comments: bool, unix: bool) -> usize {
    if !comments {
        return at;
    }
    while at < chars.len() {
        if matches!(chars[at], ' ' | '\t' | '\n' | '\r' | '\u{0b}' | '\u{0c}') {
            at += 1;
        } else if chars[at] == '#' {
            at += 1;
            while at < chars.len()
                && !(chars[at] == '\n'
                    || (!unix && matches!(chars[at], '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')))
            {
                at += 1;
            }
        } else {
            break;
        }
    }
    at
}

fn normalize_regex_comments(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut output = String::with_capacity(pattern.len());
    let mut stack = Vec::new();
    let (mut comments, mut unix, mut in_class, mut quoted) = (false, false, false, false);
    let mut at = 0;
    while at < chars.len() {
        if !quoted {
            at = regex_skip_layout(&chars, at, comments, unix);
        }
        if at >= chars.len() {
            break;
        }
        let c = chars[at];
        if c == '\\' && at + 1 < chars.len() {
            let next = chars[at + 1];
            output.push(c);
            output.push(next);
            at += 2;
            if !in_class && next == 'Q' && !quoted {
                quoted = true;
            } else if quoted && next == 'E' {
                quoted = false;
            }
            continue;
        }
        if quoted {
            output.push(c);
            at += 1;
            continue;
        }
        // Java's counted-closure parser reads the first byte after '{' raw,
        // even in COMMENTS mode; preserving it prevents accepting invalid input.
        if c == '{' && comments && !in_class {
            output.push(c);
            at += 1;
            if at < chars.len() {
                output.push(chars[at]);
                at += 1;
            }
            continue;
        }
        if c == '[' && !in_class {
            in_class = true;
            output.push(c);
            at += 1;
            continue;
        }
        if c == ']' && in_class {
            in_class = false;
            output.push(c);
            at += 1;
            continue;
        }
        if c == '(' && !in_class {
            let question = regex_skip_layout(&chars, at + 1, comments, unix);
            if chars.get(question) == Some(&'?') {
                let (saved_comments, saved_unix) = (comments, unix);
                let (mut candidate_comments, mut candidate_unix, mut disable) =
                    (comments, unix, false);
                let mut flags = String::new();
                let mut cursor =
                    regex_skip_layout(&chars, question + 1, candidate_comments, candidate_unix);
                while let Some(&flag) = chars.get(cursor) {
                    if flag == '-' && !disable {
                        disable = true;
                    } else if matches!(flag, 'i' | 's' | 'm' | 'u' | 'U' | 'd' | 'x') {
                        if flag == 'x' {
                            candidate_comments = !disable;
                        }
                        if flag == 'd' {
                            candidate_unix = !disable;
                        }
                    } else {
                        break;
                    }
                    flags.push(flag);
                    cursor =
                        regex_skip_layout(&chars, cursor + 1, candidate_comments, candidate_unix);
                }
                if matches!(chars.get(cursor), Some(':') | Some(')'))
                    && (!flags.is_empty() || chars[cursor] == ':')
                {
                    output.push_str("(?");
                    output.push_str(&flags);
                    output.push(chars[cursor]);
                    if chars[cursor] == ':' {
                        stack.push((saved_comments, saved_unix));
                    }
                    comments = candidate_comments;
                    unix = candidate_unix;
                    at = cursor + 1;
                    continue;
                }
            }
            stack.push((comments, unix));
        } else if c == ')' && !in_class {
            if let Some((previous_comments, previous_unix)) = stack.pop() {
                comments = previous_comments;
                unix = previous_unix;
            }
        }
        output.push(c);
        at += 1;
    }
    output
}

enum CharacterClassElement {
    Literal(u8, bool),
    Predefined(Box<[bool; 256]>),
}

fn parse_character_class(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    case_insensitive: bool,
    unicode_case: bool,
    unicode_class: bool,
) -> Result<Box<[bool; 256]>> {
    let negated = if chars.peek() == Some(&'^') {
        chars.next();
        true
    } else {
        false
    };
    let mut elements = Vec::new();
    let mut closed = false;
    while let Some(c) = chars.next() {
        if c == ']' {
            closed = true;
            break;
        }
        if c == '\\' {
            let escaped = chars
                .next()
                .ok_or_else(|| error("unsupported character class escape"))?;
            if let Some(class) = predefined_class(escaped, unicode_class) {
                elements.push(CharacterClassElement::Predefined(class));
            } else if let Some(byte) = control_escape(escaped, chars)? {
                elements.push(CharacterClassElement::Literal(byte, true));
            } else if "[]^-\\.#".contains(escaped) || escaped.is_ascii_whitespace() {
                elements.push(CharacterClassElement::Literal(escaped as u8, true));
            } else {
                return Err(error("unsupported character class escape"));
            }
        } else {
            if c == '[' || c == '&' {
                return Err(error("unsupported character class construct"));
            }
            elements.push(CharacterClassElement::Literal(c as u8, false));
        }
    }
    if !closed || elements.is_empty() {
        return Err(error("invalid character class"));
    }
    let mut class = Box::new([false; 256]);
    let mut i = 0;
    while i < elements.len() {
        if matches!(elements[i], CharacterClassElement::Literal(b'-', false))
            && i != 0
            && i + 1 != elements.len()
            && !matches!(elements[i - 1], CharacterClassElement::Predefined(_))
        {
            return Err(error("ambiguous character class range"));
        }
        if i + 2 < elements.len()
            && matches!(elements[i], CharacterClassElement::Literal(_, _))
            && matches!(elements[i + 1], CharacterClassElement::Literal(b'-', false))
        {
            let (CharacterClassElement::Literal(start, _), CharacterClassElement::Literal(end, _)) =
                (&elements[i], &elements[i + 2])
            else {
                return Err(error("invalid character class range"));
            };
            if start > end {
                return Err(error("invalid character class range"));
            }
            for byte in *start..=*end {
                class[usize::from(byte)] = true;
            }
            i += 3;
        } else {
            match &elements[i] {
                CharacterClassElement::Literal(byte, _) => class[usize::from(*byte)] = true,
                CharacterClassElement::Predefined(set) => {
                    for (included, member) in class.iter_mut().zip(set.iter()) {
                        *included |= *member;
                    }
                }
            }
            i += 1;
        }
    }
    if case_insensitive {
        for lower in b'a'..=b'z' {
            let upper = lower.to_ascii_uppercase();
            let included = class[usize::from(lower)] || class[usize::from(upper)];
            class[usize::from(lower)] = included;
            class[usize::from(upper)] = included;
        }
        if unicode_case {
            for upper in (0xc0u8..=0xd6).chain(0xd8..=0xde) {
                let lower = upper + 0x20;
                let included = class[usize::from(lower)] || class[usize::from(upper)];
                class[usize::from(lower)] = included;
                class[usize::from(upper)] = included;
            }
        }
    }
    if negated {
        for included in class.iter_mut() {
            *included = !*included;
        }
    }
    Ok(class)
}

fn repetition_bounds(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<(usize, Option<usize>)> {
    fn number(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<Option<usize>> {
        let mut value = None;
        while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            let digit = chars.next().unwrap().to_digit(10).unwrap() as usize;
            value = Some(
                value
                    .unwrap_or(0usize)
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(digit))
                    .filter(|n| *n <= i32::MAX as usize)
                    .ok_or_else(|| error("regex repetition limit too large"))?,
            );
        }
        Ok(value)
    }
    let min = number(chars)?.ok_or_else(|| error("invalid regex repetition"))?;
    let max = if chars.peek() == Some(&',') {
        chars.next();
        number(chars)?
    } else {
        Some(min)
    };
    if chars.next() != Some('}') || max.is_some_and(|max| min > max) {
        return Err(error("invalid regex repetition"));
    }
    Ok((min, max))
}

enum RegexInstruction {
    Atom(usize),
    Repeat {
        start: usize,
        end: usize,
        min: usize,
        limit: Option<usize>,
        greedy: bool,
        group: bool,
    },
    Split {
        start: usize,
        end: usize,
        target: usize,
        greedy: bool,
    },
}

fn compile_optional_program(
    atom_count: usize,
    optional: &[(usize, usize, bool)],
    repeated: &[Option<(usize, Option<usize>, bool)>],
    group_repeat: Option<(usize, usize, usize, Option<usize>, bool)>,
) -> Vec<RegexInstruction> {
    let mut starts = vec![Vec::new(); atom_count];
    let mut ends = vec![Vec::new(); atom_count + 1];
    for (index, &(start, end, _)) in optional.iter().enumerate() {
        starts[start].push(index);
        ends[end].push(index);
    }
    let mut program = Vec::with_capacity(atom_count + optional.len());
    let mut split_locations = vec![0; optional.len()];
    for atom in 0..atom_count {
        if group_repeat.is_some_and(|(start, end, ..)| atom > start && atom < end) {
            continue;
        }
        starts[atom].sort_by_key(|&index| {
            (
                std::cmp::Reverse(optional[index].1),
                std::cmp::Reverse(index),
            )
        });
        for &index in &starts[atom] {
            let (start, end, greedy) = optional[index];
            split_locations[index] = program.len();
            program.push(RegexInstruction::Split {
                start,
                end,
                target: 0,
                greedy,
            });
        }
        if let Some((start, end, min, limit, greedy)) =
            group_repeat.filter(|(start, ..)| *start == atom)
        {
            program.push(RegexInstruction::Repeat {
                start,
                end,
                min,
                limit,
                greedy,
                group: true,
            });
        } else if let Some((min, limit, greedy)) = repeated[atom] {
            program.push(RegexInstruction::Repeat {
                start: atom,
                end: atom + 1,
                min,
                limit,
                greedy,
                group: false,
            });
        } else {
            program.push(RegexInstruction::Atom(atom));
        }
        let target = program.len();
        for &index in &ends[atom + 1] {
            if let RegexInstruction::Split { target: jump, .. } =
                &mut program[split_locations[index]]
            {
                *jump = target;
            }
        }
    }
    program
}

fn fold_latin1(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() || (0xc0..=0xd6).contains(&byte) || (0xd8..=0xde).contains(&byte) {
        byte + 0x20
    } else {
        byte
    }
}

fn literal_regex_atom(c: char, case_insensitive: bool, unicode_case: bool) -> FixedRegexAtom {
    let byte = c as u8;
    if case_insensitive && unicode_case {
        FixedRegexAtom::UnicodeCaseInsensitive(byte)
    } else if case_insensitive && byte.is_ascii_alphabetic() {
        FixedRegexAtom::CaseInsensitive(byte)
    } else {
        FixedRegexAtom::Literal(byte)
    }
}

fn atom_accepts(atom: &FixedRegexAtom, byte: u8) -> bool {
    match atom {
        FixedRegexAtom::Literal(expected) => *expected == byte,
        FixedRegexAtom::CaseInsensitive(expected) => expected.eq_ignore_ascii_case(&byte),
        FixedRegexAtom::UnicodeCaseInsensitive(expected) => {
            fold_latin1(*expected) == fold_latin1(byte)
        }
        FixedRegexAtom::Dot => !matches!(byte, b'\n' | b'\r' | 0x85),
        FixedRegexAtom::DotUnix => byte != b'\n',
        FixedRegexAtom::DotAll => true,
        FixedRegexAtom::Start
        | FixedRegexAtom::End
        | FixedRegexAtom::EndUnix
        | FixedRegexAtom::EndStrict
        | FixedRegexAtom::StartLine
        | FixedRegexAtom::StartLineUnix
        | FixedRegexAtom::EndLine
        | FixedRegexAtom::EndLineUnix
        | FixedRegexAtom::WordBoundary
        | FixedRegexAtom::NonWordBoundary
        | FixedRegexAtom::UnicodeWordBoundary
        | FixedRegexAtom::UnicodeNonWordBoundary => false,
        FixedRegexAtom::Class(class) => class[usize::from(byte)],
    }
}

fn atom_width(atom: &FixedRegexAtom, input: &[u8], position: usize) -> Option<usize> {
    match atom {
        FixedRegexAtom::Start => (position == 0).then_some(0),
        FixedRegexAtom::EndStrict => (position == input.len()).then_some(0),
        FixedRegexAtom::StartLine => {
            let after_terminator = position > 0
                && matches!(input[position - 1], b'\n' | b'\r' | 0x85)
                && !(input[position - 1] == b'\r' && input.get(position) == Some(&b'\n'));
            (position < input.len() && (position == 0 || after_terminator)).then_some(0)
        }
        FixedRegexAtom::EndLine => {
            let at_terminator = input
                .get(position)
                .is_some_and(|byte| matches!(*byte, b'\n' | b'\r' | 0x85))
                && !(input.get(position) == Some(&b'\n')
                    && position > 0
                    && input[position - 1] == b'\r');
            (position == input.len() || at_terminator).then_some(0)
        }
        FixedRegexAtom::StartLineUnix => {
            (position < input.len() && (position == 0 || input[position - 1] == b'\n')).then_some(0)
        }
        FixedRegexAtom::EndLineUnix => {
            (position == input.len() || input.get(position) == Some(&b'\n')).then_some(0)
        }
        FixedRegexAtom::EndUnix => (position == input.len()
            || (position + 1 == input.len() && input.get(position) == Some(&b'\n')))
        .then_some(0),
        FixedRegexAtom::WordBoundary
        | FixedRegexAtom::NonWordBoundary
        | FixedRegexAtom::UnicodeWordBoundary
        | FixedRegexAtom::UnicodeNonWordBoundary => {
            let unicode = matches!(
                atom,
                FixedRegexAtom::UnicodeWordBoundary | FixedRegexAtom::UnicodeNonWordBoundary
            );
            let word = |byte: u8| {
                if unicode {
                    unicode_word(byte)
                } else {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                }
            };
            let before = position
                .checked_sub(1)
                .and_then(|index| input.get(index))
                .is_some_and(|byte| word(*byte));
            let after = input.get(position).is_some_and(|byte| word(*byte));
            let boundary = before != after;
            (boundary
                == matches!(
                    atom,
                    FixedRegexAtom::WordBoundary | FixedRegexAtom::UnicodeWordBoundary
                ))
            .then_some(0)
        }
        FixedRegexAtom::End => {
            let final_terminator = position + 1 == input.len()
                && matches!(input[position], b'\n' | b'\r' | 0x85)
                && !(input[position] == b'\n' && position > 0 && input[position - 1] == b'\r');
            let final_crlf = position + 2 == input.len() && &input[position..] == b"\r\n";
            (position == input.len() || final_terminator || final_crlf).then_some(0)
        }
        _ => input
            .get(position)
            .filter(|byte| atom_accepts(atom, **byte))
            .map(|_| 1),
    }
}

fn consume_regex_budget(comparisons: &mut usize) -> Result<()> {
    *comparisons = comparisons
        .checked_add(1)
        .filter(|n| *n <= MAX_FRAME * 4)
        .ok_or_else(|| error("regex comparison limit exceeded"))?;
    Ok(())
}

fn repetition_unit_matches(
    input: &[u8],
    position: usize,
    atoms: &[FixedRegexAtom],
    start: usize,
    end: usize,
    comparisons: &mut usize,
) -> Result<bool> {
    for (offset, atom) in atoms[start..end].iter().enumerate() {
        consume_regex_budget(comparisons)?;
        if !input
            .get(position + offset)
            .is_some_and(|byte| atom_accepts(atom, *byte))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn match_fixed_at(
    input: &[u8],
    offset: usize,
    atoms: &[FixedRegexAtom],
    program: &[RegexInstruction],
    comparisons: &mut usize,
) -> Result<Option<Vec<usize>>> {
    // Each frame stores program counter, input position, next branch and repeat maximum.
    let mut frames = vec![(0usize, offset, 0usize, None)];
    let mut positions = vec![offset; atoms.len() + 1];
    while let Some((pc, position, choice, maximum)) = frames.last_mut() {
        if *pc == program.len() {
            return Ok(Some(positions));
        }
        if let RegexInstruction::Repeat {
            start,
            end,
            min,
            limit,
            greedy,
            ..
        } = &program[*pc]
        {
            if *greedy {
                if maximum.is_none() {
                    let mut length = 0;
                    let width = end - start;
                    while limit.is_none_or(|limit| length < limit) {
                        if !repetition_unit_matches(
                            input,
                            *position + length * width,
                            atoms,
                            *start,
                            *end,
                            comparisons,
                        )? {
                            break;
                        }
                        length += 1;
                    }
                    *maximum = Some(length);
                }
                if maximum.unwrap() < *min || *choice > maximum.unwrap() - min {
                    frames.pop();
                    continue;
                }
            } else {
                let length = min + *choice;
                if limit.is_some_and(|limit| length > limit) {
                    frames.pop();
                    continue;
                }
                let first = if *choice == 0 { 0 } else { length - 1 };
                let mut matched = true;
                let width = end - start;
                for step in first..length {
                    if !repetition_unit_matches(
                        input,
                        *position + step * width,
                        atoms,
                        *start,
                        *end,
                        comparisons,
                    )? {
                        matched = false;
                        break;
                    }
                }
                if !matched {
                    frames.pop();
                    continue;
                }
            }
        } else {
            let max_choices = if matches!(program[*pc], RegexInstruction::Split { .. }) {
                2
            } else {
                1
            };
            if *choice == max_choices {
                frames.pop();
                continue;
            }
        }
        consume_regex_budget(comparisons)?;
        let branch = *choice;
        *choice += 1;
        let pc = *pc;
        let position = *position;
        let maximum = *maximum;
        match &program[pc] {
            RegexInstruction::Split {
                start,
                end,
                target,
                greedy,
            } => {
                positions[*start] = position;
                if (branch == 0) != *greedy {
                    positions[start + 1..=*end].fill(position);
                    frames.push((*target, position, 0, None));
                } else {
                    frames.push((pc + 1, position, 0, None));
                }
            }
            RegexInstruction::Atom(index) => {
                if let Some(width) = atom_width(&atoms[*index], input, position) {
                    positions[*index] = position;
                    positions[*index + 1] = position + width;
                    frames.push((pc + 1, position + width, 0, None));
                }
            }
            RegexInstruction::Repeat {
                start,
                end,
                min,
                greedy,
                group,
                ..
            } => {
                let length = if *greedy {
                    maximum.unwrap() - branch
                } else {
                    min + branch
                };
                let width = end - start;
                if *group {
                    let group_start = if length == 0 {
                        position
                    } else {
                        position + (length - 1) * width
                    };
                    for (offset, boundary) in positions[*start..=*end].iter_mut().enumerate() {
                        *boundary = if length == 0 {
                            position
                        } else {
                            group_start + offset
                        };
                    }
                } else {
                    positions[*start] = position;
                    positions[*end] = position + length;
                }
                frames.push((pc + 1, position + length * width, 0, None));
            }
        }
    }
    Ok(None)
}

fn replace_fixed_pattern(
    text: &str,
    atoms: &[FixedRegexAtom],
    ranges: &[(usize, usize)],
    names: &[Option<String>],
    replacement: &str,
    comparisons: &mut usize,
    program: &[RegexInstruction],
) -> Result<String> {
    let input = latin1_encode(text)?;
    let mut output = Vec::new();
    let mut copied = 0;
    let mut offset = 0;
    while offset <= input.len() {
        let positions = match_fixed_at(&input, offset, atoms, program, comparisons)?;
        if let Some(positions) = positions {
            let end = *positions.last().unwrap();
            let groups = ranges
                .iter()
                .map(|&(start, end)| latin1_decode(&input[positions[start]..positions[end]]))
                .collect::<Vec<_>>();
            let whole = latin1_decode(&input[offset..end]);
            let expanded =
                latin1_encode(&expand_literal_groups(replacement, &whole, &groups, names)?)?;
            let prefix = offset - copied;
            if output
                .len()
                .checked_add(prefix)
                .and_then(|n| n.checked_add(expanded.len()))
                .is_none_or(|n| n > usize::from(u16::MAX))
            {
                return Err(error("short string too long"));
            }
            output.extend_from_slice(&input[copied..offset]);
            output.extend_from_slice(&expanded);
            copied = end;
            offset = if end == offset { offset + 1 } else { end };
        } else {
            offset += 1;
        }
    }
    if output
        .len()
        .checked_add(input.len() - copied)
        .is_none_or(|n| n > usize::from(u16::MAX))
    {
        return Err(error("short string too long"));
    }
    output.extend_from_slice(&input[copied..]);
    Ok(latin1_decode(&output))
}

struct CaptureRepeat<'a> {
    start: usize,
    end: usize,
    min: usize,
    limit: Option<usize>,
    greedy: bool,
    ranges: &'a [(usize, usize)],
    names: &'a [Option<String>],
}

fn match_atom_sequence(
    input: &[u8],
    atoms: &[FixedRegexAtom],
    mut position: usize,
    comparisons: &mut usize,
) -> Result<Option<usize>> {
    for atom in atoms {
        consume_regex_budget(comparisons)?;
        let Some(width) = atom_width(atom, input, position) else {
            return Ok(None);
        };
        position += width;
    }
    Ok(Some(position))
}

// Java's GroupCurly can retain captures from a complete iteration even if the
// current search start later fails. Matcher.search clears them only on the next find.
fn replace_capture_repeat(
    text: &str,
    atoms: &[FixedRegexAtom],
    plan: &CaptureRepeat<'_>,
    replacement: &str,
    comparisons: &mut usize,
) -> Result<String> {
    let input = latin1_encode(text)?;
    let mut output = Vec::new();
    let mut captures = vec![None; plan.ranges.len()];
    let mut copied = 0;
    let mut offset = 0;
    while offset <= input.len() {
        let mut matched_end = None;
        if let Some(mut position) =
            match_atom_sequence(&input, &atoms[..plan.start], offset, comparisons)?
        {
            let mut count = 0;
            if plan.greedy {
                while plan.limit.is_none_or(|limit| count < limit)
                    && repetition_unit_matches(
                        &input,
                        position,
                        atoms,
                        plan.start,
                        plan.end,
                        comparisons,
                    )?
                {
                    for (slot, &(start, end)) in captures.iter_mut().zip(plan.ranges) {
                        *slot = Some((position + start - plan.start, position + end - plan.start));
                    }
                    position += plan.end - plan.start;
                    count += 1;
                }
                while count >= plan.min {
                    if let Some(end) =
                        match_atom_sequence(&input, &atoms[plan.end..], position, comparisons)?
                    {
                        matched_end = Some(end);
                        break;
                    }
                    if count == plan.min {
                        break;
                    }
                    position -= plan.end - plan.start;
                    count -= 1;
                }
            } else {
                loop {
                    if count >= plan.min {
                        if let Some(end) =
                            match_atom_sequence(&input, &atoms[plan.end..], position, comparisons)?
                        {
                            matched_end = Some(end);
                            break;
                        }
                    }
                    if plan.limit.is_some_and(|limit| count >= limit)
                        || !repetition_unit_matches(
                            &input,
                            position,
                            atoms,
                            plan.start,
                            plan.end,
                            comparisons,
                        )?
                    {
                        break;
                    }
                    for (slot, &(start, end)) in captures.iter_mut().zip(plan.ranges) {
                        *slot = Some((position + start - plan.start, position + end - plan.start));
                    }
                    position += plan.end - plan.start;
                    count += 1;
                }
            }
        }
        if let Some(end) = matched_end {
            let whole = latin1_decode(&input[offset..end]);
            let groups = captures
                .iter()
                .map(|capture| {
                    capture.map_or_else(String::new, |(a, b)| latin1_decode(&input[a..b]))
                })
                .collect::<Vec<_>>();
            let expanded = latin1_encode(&expand_literal_groups(
                replacement,
                &whole,
                &groups,
                plan.names,
            )?)?;
            let prefix = offset - copied;
            if output
                .len()
                .checked_add(prefix)
                .and_then(|n| n.checked_add(expanded.len()))
                .is_none_or(|n| n > usize::from(u16::MAX))
            {
                return Err(error("short string too long"));
            }
            output.extend_from_slice(&input[copied..offset]);
            output.extend_from_slice(&expanded);
            copied = end;
            captures.fill(None);
            offset = if end == offset { offset + 1 } else { end };
        } else {
            offset += 1;
        }
    }
    if output
        .len()
        .checked_add(input.len() - copied)
        .is_none_or(|n| n > usize::from(u16::MAX))
    {
        return Err(error("short string too long"));
    }
    output.extend_from_slice(&input[copied..]);
    Ok(latin1_decode(&output))
}

struct RegexBranch {
    start: usize,
    end: usize,
    program: Vec<RegexInstruction>,
    groups: Vec<(usize, usize, usize)>,
}

// Alternation branches are evaluated in source order at every input offset, as in Java.
fn replace_alternatives(
    text: &str,
    atoms: &[FixedRegexAtom],
    branches: &[RegexBranch],
    names: &[Option<String>],
    replacement: &str,
    comparisons: &mut usize,
) -> Result<String> {
    let input = latin1_encode(text)?;
    let mut output = Vec::new();
    let mut copied = 0;
    let mut offset = 0;
    while offset <= input.len() {
        let mut matched = None;
        for branch in branches {
            if let Some(positions) = match_fixed_at(
                &input,
                offset,
                &atoms[branch.start..branch.end],
                &branch.program,
                comparisons,
            )? {
                matched = Some((branch, positions));
                break;
            }
        }
        if let Some((branch, positions)) = matched {
            let end = *positions.last().unwrap();
            let mut groups = vec![String::new(); names.len()];
            for &(index, start, end) in &branch.groups {
                groups[index] = latin1_decode(&input[positions[start]..positions[end]]);
            }
            let whole = latin1_decode(&input[offset..end]);
            let expanded =
                latin1_encode(&expand_literal_groups(replacement, &whole, &groups, names)?)?;
            let prefix = offset - copied;
            if output
                .len()
                .checked_add(prefix)
                .and_then(|n| n.checked_add(expanded.len()))
                .is_none_or(|n| n > usize::from(u16::MAX))
            {
                return Err(error("short string too long"));
            }
            output.extend_from_slice(&input[copied..offset]);
            output.extend_from_slice(&expanded);
            copied = end;
            offset = if end == offset { offset + 1 } else { end };
        } else {
            offset += 1;
        }
    }
    if output
        .len()
        .checked_add(input.len() - copied)
        .is_none_or(|n| n > usize::from(u16::MAX))
    {
        return Err(error("short string too long"));
    }
    output.extend_from_slice(&input[copied..]);
    Ok(latin1_decode(&output))
}

#[cfg(test)]
mod regex_budget_tests {
    use super::*;

    #[test]
    #[ignore = "requires Java 21 Unicode case-pair vectors"]
    fn unicode_latin1_case_pairs_match_java() {
        let path = std::env::var("GEARTH_MUTATION_ORACLE").unwrap();
        let oracle = std::fs::read_to_string(path).unwrap();
        let mut count = 0;
        for line in oracle.lines() {
            let Some(line) = line.strip_prefix("unicode_case_") else {
                continue;
            };
            let (first, hex) = line.split_once('=').unwrap();
            let first: u8 = first.parse().unwrap();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(bytes.len(), 32);
            for second in 0u8..=255 {
                let expected = bytes[usize::from(second) / 8] & (1 << (second % 8)) != 0;
                assert_eq!(
                    atom_accepts(&FixedRegexAtom::UnicodeCaseInsensitive(first), second),
                    expected,
                    "{first:02x} {second:02x}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 256);
    }

    #[test]
    #[ignore = "requires Java 21 Unicode class vectors"]
    fn unicode_latin1_classes_match_java() {
        let path = std::env::var("GEARTH_MUTATION_ORACLE").unwrap();
        let oracle = std::fs::read_to_string(path).unwrap();
        let mut count = 0;
        for line in oracle.lines() {
            let Some(line) = line.strip_prefix("unicode_class_") else {
                continue;
            };
            let (kind, hex) = line.split_once('=').unwrap();
            let kind = kind.chars().next().unwrap();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(bytes.len(), 32);
            for value in 0u8..=255 {
                let expected = bytes[usize::from(value) / 8] & (1 << (value % 8)) != 0;
                let actual = match kind {
                    'b' => atom_width(&FixedRegexAtom::UnicodeWordBoundary, &[value], 0).is_some(),
                    'B' => {
                        atom_width(&FixedRegexAtom::UnicodeNonWordBoundary, &[value], 0).is_some()
                    }
                    _ => predefined_class(kind, true).unwrap()[usize::from(value)],
                };
                assert_eq!(actual, expected, "{kind}: {value:02x}");
            }
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[test]
    fn java_greedy_repeat_retains_furthest_captures_after_backtracking() {
        let atoms = [
            FixedRegexAtom::Dot,
            FixedRegexAtom::Dot,
            FixedRegexAtom::Literal(b'a'),
            FixedRegexAtom::Literal(b'b'),
        ];
        let plan = CaptureRepeat {
            start: 0,
            end: 2,
            min: 1,
            limit: None,
            greedy: true,
            ranges: &[(0, 1), (1, 2)],
            names: &[None, None],
        };
        let mut comparisons = 0;
        assert_eq!(
            replace_capture_repeat("cdefab", &atoms, &plan, "$1/$2/$0", &mut comparisons).unwrap(),
            "a/b/cdefab"
        );
    }

    #[test]
    fn java_lazy_repeat_keeps_captures_from_failed_search_starts() {
        let atoms = [
            FixedRegexAtom::Literal(b'a'),
            FixedRegexAtom::Literal(b'b'),
            FixedRegexAtom::Literal(b'b'),
        ];
        let plan = CaptureRepeat {
            start: 0,
            end: 2,
            min: 0,
            limit: None,
            greedy: false,
            ranges: &[(0, 1)],
            names: &[None],
        };
        let mut comparisons = 0;
        assert_eq!(
            replace_capture_repeat("abab", &atoms, &plan, "$1/$0", &mut comparisons).unwrap(),
            "aa/baa/b"
        );
    }

    #[test]
    fn repeated_noncapturing_group_zero_iterations_do_not_reuse_capture() {
        let atoms = [
            FixedRegexAtom::Literal(b'a'),
            FixedRegexAtom::Literal(b'b'),
            FixedRegexAtom::Literal(b'b'),
        ];
        let program =
            compile_optional_program(3, &[], &[None, None, None], Some((0, 2, 0, None, false)));
        let mut comparisons = 0;
        let positions = match_fixed_at(b"abab", 1, &atoms, &program, &mut comparisons)
            .unwrap()
            .unwrap();
        assert_eq!(positions[0], positions[1]);
    }

    #[test]
    fn java_21_word_boundaries_handle_empty_and_latin1() {
        assert_eq!(atom_width(&FixedRegexAtom::WordBoundary, b"", 0), None);
        assert_eq!(
            atom_width(&FixedRegexAtom::NonWordBoundary, b"", 0),
            Some(0)
        );
        let input = [0xe9, b'a', b'_'];
        assert_eq!(
            atom_width(&FixedRegexAtom::WordBoundary, &input, 1),
            Some(0)
        );
        assert_eq!(
            atom_width(&FixedRegexAtom::NonWordBoundary, &input, 2),
            Some(0)
        );
        assert_eq!(
            atom_width(&FixedRegexAtom::WordBoundary, &input, 3),
            Some(0)
        );
    }

    #[test]
    fn java_unix_lines_anchors_and_dot_handle_crlf() {
        assert!(!atom_accepts(&FixedRegexAtom::DotUnix, b'\n'));
        assert!(atom_accepts(&FixedRegexAtom::DotUnix, b'\r'));
        assert!(atom_accepts(&FixedRegexAtom::DotUnix, 0x85));
        assert_eq!(atom_width(&FixedRegexAtom::StartLineUnix, b"", 0), None);
        assert_eq!(atom_width(&FixedRegexAtom::EndLineUnix, b"", 0), Some(0));
        let input = b"a\r\n";
        assert_eq!(atom_width(&FixedRegexAtom::EndUnix, input, 1), None);
        assert_eq!(atom_width(&FixedRegexAtom::EndUnix, input, 2), Some(0));
        assert_eq!(atom_width(&FixedRegexAtom::EndLineUnix, input, 2), Some(0));
        assert_eq!(atom_width(&FixedRegexAtom::StartLineUnix, input, 3), None);
    }

    #[test]
    fn java_multiline_anchors_handle_empty_and_crlf() {
        assert_eq!(atom_width(&FixedRegexAtom::StartLine, b"", 0), None);
        assert_eq!(atom_width(&FixedRegexAtom::EndLine, b"", 0), Some(0));
        let input = b"a\r\nb";
        assert_eq!(atom_width(&FixedRegexAtom::EndLine, input, 1), Some(0));
        assert_eq!(atom_width(&FixedRegexAtom::EndLine, input, 2), None);
        assert_eq!(atom_width(&FixedRegexAtom::StartLine, input, 2), None);
        assert_eq!(atom_width(&FixedRegexAtom::StartLine, input, 3), Some(0));
        assert_eq!(atom_width(&FixedRegexAtom::StartLine, b"a\n", 2), None);
    }

    #[test]
    fn java_end_anchor_handles_crlf_as_one_terminator() {
        let input = b"a\r\n";
        assert_eq!(atom_width(&FixedRegexAtom::End, input, 1), Some(0));
        assert_eq!(atom_width(&FixedRegexAtom::End, input, 2), None);
        assert_eq!(atom_width(&FixedRegexAtom::End, input, 3), Some(0));
        assert_eq!(atom_width(&FixedRegexAtom::EndStrict, input, 1), None);
        assert_eq!(atom_width(&FixedRegexAtom::EndStrict, input, 3), Some(0));
    }

    #[test]
    fn optional_backtracking_respects_shared_comparison_budget() {
        let atoms = [FixedRegexAtom::Literal(b'a'), FixedRegexAtom::Literal(b'b')];
        let mut comparisons = MAX_FRAME * 4 - 1;
        let program =
            compile_optional_program(2, &[(0, 1, true), (1, 2, true)], &[None, None], None);
        let error = match_fixed_at(b"ac", 0, &atoms, &program, &mut comparisons).unwrap_err();
        assert!(error.0.contains("comparison limit"));
    }

    #[test]
    fn bounded_nullable_repeat_caps_extreme_minimum() {
        let atoms = [FixedRegexAtom::Literal(b'a')];
        let program = compile_nested_repeat(
            1,
            (0, 1, i32::MAX as usize, None, true),
            &[(0, 1, Some(true), 1)],
            0,
            &[None],
            &[None],
        );
        let mut comparisons = 0;
        let error = match_nested_repeat(b"", 0, &atoms, &program, 2, &mut comparisons).unwrap_err();
        assert!(error.0.contains("state limit"));
    }

    #[test]
    fn nullable_nested_repeat_stops_and_retains_captures() {
        let atoms = [FixedRegexAtom::Literal(b'a'), FixedRegexAtom::Literal(b'b')];
        let program = compile_nested_repeat(
            2,
            (0, 2, 0, None, true),
            &[(0, 1, Some(true), 1), (1, 2, Some(true), 2)],
            0,
            &[None, None],
            &[None, None],
        );
        let mut comparisons = 0;
        let (end, captures) = match_nested_repeat(b"ab", 0, &atoms, &program, 3, &mut comparisons)
            .unwrap()
            .unwrap();
        assert_eq!(end, 2);
        assert_eq!(captures, ["", "a", "b"]);
        assert!(comparisons < 100);
    }

    #[test]
    fn required_nested_capture_overwrites_previous_value_with_empty() {
        let atoms = [FixedRegexAtom::Literal(b'a'), FixedRegexAtom::Literal(b'b')];
        let program = compile_nested_repeat(
            2,
            (0, 2, 0, None, true),
            &[(0, 1, None, 1)],
            0,
            &[None, None],
            &[Some(true), None],
        );
        let mut comparisons = 0;
        let (end, captures) = match_nested_repeat(b"abb", 0, &atoms, &program, 2, &mut comparisons)
            .unwrap()
            .unwrap();
        assert_eq!(end, 3);
        assert_eq!(captures, ["b", ""]);
    }

    #[test]
    fn repeated_optional_atom_retains_prior_nested_capture() {
        let atoms = [FixedRegexAtom::Literal(b'a'), FixedRegexAtom::Literal(b'b')];
        let program = compile_nested_repeat(
            2,
            (0, 2, 0, None, true),
            &[(0, 1, Some(true), 1)],
            0,
            &[None, None],
            &[None, Some(true)],
        );
        let mut comparisons = 0;
        let (end, captures) = match_nested_repeat(b"abb", 0, &atoms, &program, 2, &mut comparisons)
            .unwrap()
            .unwrap();
        assert_eq!(end, 3);
        assert_eq!(captures, ["", "a"]);
    }

    #[test]
    fn nested_repeat_retains_multiple_independent_captures() {
        let atoms = [
            FixedRegexAtom::Literal(b'a'),
            FixedRegexAtom::Literal(b'b'),
            FixedRegexAtom::Literal(b'c'),
        ];
        let program = compile_nested_repeat(
            3,
            (0, 3, 0, None, true),
            &[(0, 1, Some(true), 1), (1, 2, Some(true), 2)],
            0,
            &[None, None, None],
            &[None, None, None],
        );
        let mut comparisons = 0;
        let (end, captures) =
            match_nested_repeat(b"acbcc", 0, &atoms, &program, 3, &mut comparisons)
                .unwrap()
                .unwrap();
        assert_eq!(end, 5);
        assert_eq!(captures, ["c", "a", "b"]);
    }

    #[test]
    fn nested_repeat_retains_capture_and_caps_state() {
        let atoms = [FixedRegexAtom::Literal(b'a'), FixedRegexAtom::Literal(b'b')];
        let program = compile_nested_repeat(
            2,
            (0, 2, 0, None, true),
            &[(0, 1, Some(true), 1)],
            0,
            &[None, None],
            &[None, None],
        );
        let mut comparisons = 0;
        let (end, captures) = match_nested_repeat(b"abb", 0, &atoms, &program, 2, &mut comparisons)
            .unwrap()
            .unwrap();
        assert_eq!(end, 3);
        assert_eq!(captures, ["b", "a"]);
        let mut comparisons = 0;
        let error = match_nested_repeat(
            &vec![b'b'; 65_535],
            0,
            &atoms,
            &program,
            2,
            &mut comparisons,
        )
        .unwrap_err();
        assert!(error.0.contains("state limit"));
    }
}

#[derive(Default)]
struct AlternationNode {
    parent: Option<usize>,
    start: usize,
    end: usize,
    capture: Option<usize>,
    sticky_captures: Option<(usize, usize)>,
    repeat: Option<(usize, Option<usize>, bool, usize, bool)>,
    splits: Vec<usize>,
    // The branch index records ownership even for zero-width child groups.
    children: Vec<(usize, usize)>,
}

fn push_alternation_node(
    nodes: &mut Vec<AlternationNode>,
    stack: &mut Vec<usize>,
    start: usize,
) -> usize {
    let parent = *stack.last().unwrap();
    let branch = nodes[parent].splits.len();
    let id = nodes.len();
    nodes[parent].children.push((branch, id));
    nodes.push(AlternationNode {
        parent: Some(parent),
        start,
        ..AlternationNode::default()
    });
    stack.push(id);
    id
}

#[derive(Clone, Copy)]
enum NestedInstruction {
    Atom(usize),
    Repeat {
        index: usize,
        min: usize,
        limit: Option<usize>,
        greedy: bool,
    },
    Start(usize),
    End(usize),
    StickyCommit(usize, usize),
    Split(usize, usize),
    Jump(usize),
    Initial {
        body: usize,
        exit: usize,
        min: usize,
        limit: Option<usize>,
        greedy: bool,
    },
    Loop {
        body: usize,
        exit: usize,
        min: usize,
        limit: Option<usize>,
        greedy: bool,
        group: usize,
    },
}

fn emit_nested_atoms(
    program: &mut Vec<NestedInstruction>,
    range: std::ops::Range<usize>,
    repeated: &[Option<(usize, Option<usize>, bool)>],
    optional: &[Option<bool>],
) {
    for index in range {
        let split = optional[index].map(|_| {
            let pc = program.len();
            program.push(NestedInstruction::Split(0, 0));
            pc
        });
        let body = program.len();
        program.push(match repeated[index] {
            Some((min, limit, greedy)) => NestedInstruction::Repeat {
                index,
                min,
                limit,
                greedy,
            },
            None => NestedInstruction::Atom(index),
        });
        if let Some(pc) = split {
            let after = program.len();
            program[pc] = if optional[index].unwrap() {
                NestedInstruction::Split(body, after)
            } else {
                NestedInstruction::Split(after, body)
            };
        }
    }
}

fn emit_alternation_node(
    program: &mut Vec<NestedInstruction>,
    nodes: &[AlternationNode],
    id: usize,
    optional_nodes: &[Option<bool>],
    repeated: &[Option<(usize, Option<usize>, bool)>],
    optional_atoms: &[Option<bool>],
    depth: usize,
) -> Result<()> {
    if depth > 128 {
        return Err(error("regex group nesting limit exceeded"));
    }
    let node = &nodes[id];
    let optional_split = optional_nodes[id].map(|_| {
        let pc = program.len();
        program.push(NestedInstruction::Split(0, 0));
        pc
    });
    let initial = node.repeat.map(|_| {
        let pc = program.len();
        program.push(NestedInstruction::Split(0, 0));
        pc
    });
    let body = program.len();
    if let Some((_, _, _, group, true)) = node.repeat {
        program.push(NestedInstruction::Start(group));
    }
    if let Some(group) = node.capture {
        program.push(NestedInstruction::Start(group));
    }
    let mut boundaries = Vec::with_capacity(node.splits.len() + 2);
    boundaries.push(node.start);
    boundaries.extend_from_slice(&node.splits);
    boundaries.push(node.end);
    let mut exits = Vec::new();
    let mut children = node.children.iter().peekable();
    for (branch, pair) in boundaries.windows(2).enumerate() {
        let split = (branch + 1 < boundaries.len() - 1).then(|| {
            let pc = program.len();
            program.push(NestedInstruction::Split(0, 0));
            pc
        });
        let branch_start = program.len();
        let mut cursor = pair[0];
        while children.peek().is_some_and(|(owner, _)| *owner == branch) {
            let &(_, child) = children.next().unwrap();
            let child_node = &nodes[child];
            emit_nested_atoms(program, cursor..child_node.start, repeated, optional_atoms);
            emit_alternation_node(
                program,
                nodes,
                child,
                optional_nodes,
                repeated,
                optional_atoms,
                depth + 1,
            )?;
            cursor = child_node.end;
        }
        emit_nested_atoms(program, cursor..pair[1], repeated, optional_atoms);
        if let Some(split) = split {
            let jump = program.len();
            program.push(NestedInstruction::Jump(0));
            exits.push(jump);
            let next = program.len();
            program[split] = NestedInstruction::Split(branch_start, next);
        }
    }
    let branch_end = program.len();
    for pc in exits {
        program[pc] = NestedInstruction::Jump(branch_end);
    }
    if let Some(group) = node.capture {
        program.push(NestedInstruction::End(group));
    }
    if let Some((first, end)) = node.sticky_captures {
        program.push(NestedInstruction::StickyCommit(first, end));
    }
    if let Some((min, limit, greedy, group, hidden)) = node.repeat {
        if hidden {
            program.push(NestedInstruction::End(group));
        }
        let loop_pc = program.len();
        program.push(NestedInstruction::Split(0, 0));
        let exit = program.len();
        program[loop_pc] = NestedInstruction::Loop {
            body,
            exit,
            min,
            limit,
            greedy,
            group,
        };
        program[initial.unwrap()] = NestedInstruction::Initial {
            body,
            exit,
            min,
            limit,
            greedy,
        };
    }
    let after = program.len();
    if let Some(split) = optional_split {
        program[split] = if optional_nodes[id].unwrap() {
            NestedInstruction::Split(body, after)
        } else {
            NestedInstruction::Split(after, body)
        };
    }
    Ok(())
}

fn compile_nested_repeat(
    atoms: usize,
    outer: (usize, usize, usize, Option<usize>, bool),
    inners: &[(usize, usize, Option<bool>, usize)],
    outer_group: usize,
    repeated: &[Option<(usize, Option<usize>, bool)>],
    optional_atoms: &[Option<bool>],
) -> Vec<NestedInstruction> {
    let (start, end, min, limit, greedy) = outer;
    let mut program = Vec::new();
    emit_nested_atoms(&mut program, 0..start, repeated, optional_atoms);
    let initial = program.len();
    program.push(NestedInstruction::Split(0, 0));
    let body = program.len();
    program.push(NestedInstruction::Start(outer_group));
    let mut cursor = start;
    for &(inner_start, inner_end, inner_greedy, inner_group) in inners {
        emit_nested_atoms(&mut program, cursor..inner_start, repeated, optional_atoms);
        let split = inner_greedy.map(|_| {
            let pc = program.len();
            program.push(NestedInstruction::Split(0, 0));
            pc
        });
        let inner_body = program.len();
        program.push(NestedInstruction::Start(inner_group));
        emit_nested_atoms(
            &mut program,
            inner_start..inner_end,
            repeated,
            optional_atoms,
        );
        program.push(NestedInstruction::End(inner_group));
        if let Some(pc) = split {
            let after = program.len();
            program[pc] = if inner_greedy.unwrap() {
                NestedInstruction::Split(inner_body, after)
            } else {
                NestedInstruction::Split(after, inner_body)
            };
        }
        cursor = inner_end;
    }
    emit_nested_atoms(&mut program, cursor..end, repeated, optional_atoms);
    program.push(NestedInstruction::End(outer_group));
    let loop_split = program.len();
    program.push(NestedInstruction::Split(0, 0));
    let after_loop = program.len();
    program[loop_split] = NestedInstruction::Loop {
        body,
        exit: after_loop,
        min,
        limit,
        greedy,
        group: outer_group,
    };
    program[initial] = NestedInstruction::Initial {
        body,
        exit: after_loop,
        min,
        limit,
        greedy,
    };
    emit_nested_atoms(&mut program, end..atoms, repeated, optional_atoms);
    program
}

struct DeepCapturePlan<'a> {
    ranges: &'a [(usize, usize)],
    children: &'a [Vec<usize>],
    group_optional: &'a [Option<bool>],
    repeated: &'a [Option<(usize, Option<usize>, bool)>],
    atom_optional: &'a [Option<bool>],
}

fn emit_deep_capture(
    program: &mut Vec<NestedInstruction>,
    group: usize,
    plan: &DeepCapturePlan<'_>,
) {
    let (start, end) = plan.ranges[group];
    let mut cursor = start;
    for &child in &plan.children[group] {
        let (child_start, child_end) = plan.ranges[child];
        emit_nested_atoms(
            program,
            cursor..child_start,
            plan.repeated,
            plan.atom_optional,
        );
        let split = plan.group_optional[child].map(|_| {
            let pc = program.len();
            program.push(NestedInstruction::Split(0, 0));
            pc
        });
        let child_body = program.len();
        program.push(NestedInstruction::Start(child));
        emit_deep_capture(program, child, plan);
        program.push(NestedInstruction::End(child));
        if let Some(pc) = split {
            let after = program.len();
            program[pc] = if plan.group_optional[child].unwrap() {
                NestedInstruction::Split(child_body, after)
            } else {
                NestedInstruction::Split(after, child_body)
            };
        }
        cursor = child_end;
    }
    emit_nested_atoms(program, cursor..end, plan.repeated, plan.atom_optional);
}

fn compile_deep_nested_repeat(
    atoms: usize,
    outer: (usize, usize, usize, Option<usize>, bool),
    owner: usize,
    plan: &DeepCapturePlan<'_>,
) -> Vec<NestedInstruction> {
    let (start, end, min, limit, greedy) = outer;
    let mut program = Vec::new();
    emit_nested_atoms(&mut program, 0..start, plan.repeated, plan.atom_optional);
    let initial = program.len();
    program.push(NestedInstruction::Split(0, 0));
    let body = program.len();
    program.push(NestedInstruction::Start(owner));
    emit_deep_capture(&mut program, owner, plan);
    program.push(NestedInstruction::End(owner));
    let loop_pc = program.len();
    program.push(NestedInstruction::Split(0, 0));
    let after = program.len();
    program[loop_pc] = NestedInstruction::Loop {
        body,
        exit: after,
        min,
        limit,
        greedy,
        group: owner,
    };
    program[initial] = NestedInstruction::Initial {
        body,
        exit: after,
        min,
        limit,
        greedy,
    };
    emit_nested_atoms(&mut program, end..atoms, plan.repeated, plan.atom_optional);
    program
}

fn match_nested_repeat_with_sticky(
    input: &[u8],
    offset: usize,
    atoms: &[FixedRegexAtom],
    program: &[NestedInstruction],
    capture_count: usize,
    sticky: &mut [Option<(usize, usize)>],
    comparisons: &mut usize,
) -> Result<Option<(usize, Vec<String>)>> {
    const MAX_STATES: usize = 262_144;
    // Each frame retains the capture trail length before its parent instruction.
    // Immutable linked loop states let nested loops restore outer counts on backtracking.
    let mut loop_states: Vec<(usize, Option<usize>)> = Vec::new();
    let mut frames = vec![(0usize, offset, 0usize, 0usize, None::<usize>, None)];
    let mut captures: Vec<Option<(usize, usize)>> = vec![None; capture_count];
    let mut trail: Vec<(usize, Option<(usize, usize)>)> = Vec::new();
    while let Some((pc, position, choice, checkpoint, loop_state, maximum)) = frames.last_mut() {
        if *pc == program.len() {
            let groups = captures
                .iter()
                .enumerate()
                .map(|(index, capture)| {
                    sticky[index]
                        .or(*capture)
                        .map_or_else(String::new, |(start, end)| {
                            latin1_decode(&input[start..end])
                        })
                })
                .collect();
            return Ok(Some((*position, groups)));
        }
        let choices = match program[*pc] {
            NestedInstruction::Split(..) => 2,
            NestedInstruction::Initial { min, limit, .. } => {
                if min > 0 || limit == Some(0) {
                    1
                } else {
                    2
                }
            }
            NestedInstruction::Loop {
                group, min, limit, ..
            } => {
                let state = loop_state.ok_or_else(|| error("invalid regex loop state"))?;
                let completed = loop_states[state].0 + 1;
                let progressed = captures[group].is_some_and(|(start, end)| start != end);
                if completed < min
                    || limit.is_some_and(|limit| completed >= limit)
                    || (!progressed && limit.is_none())
                {
                    1
                } else {
                    2
                }
            }
            NestedInstruction::Repeat {
                index,
                min,
                limit,
                greedy,
            } => {
                if greedy {
                    if maximum.is_none() {
                        let mut length = 0;
                        while limit.is_none_or(|limit| length < limit) {
                            let Some(&byte) = input.get(*position + length) else {
                                break;
                            };
                            consume_regex_budget(comparisons)?;
                            if !atom_accepts(&atoms[index], byte) {
                                break;
                            }
                            length += 1;
                        }
                        *maximum = Some(length);
                    }
                    if maximum.unwrap() < min {
                        0
                    } else {
                        maximum.unwrap() - min + 1
                    }
                } else {
                    let length = min + *choice;
                    let mut matched = !limit.is_some_and(|limit| length > limit);
                    if matched {
                        let first = if *choice == 0 { 0 } else { length - 1 };
                        for step in first..length {
                            consume_regex_budget(comparisons)?;
                            if !input
                                .get(*position + step)
                                .is_some_and(|byte| atom_accepts(&atoms[index], *byte))
                            {
                                matched = false;
                                break;
                            }
                        }
                    }
                    if matched {
                        *choice + 1
                    } else {
                        *choice
                    }
                }
            }
            _ => 1,
        };
        if *choice == choices {
            let checkpoint = *checkpoint;
            frames.pop();
            while trail.len() > checkpoint {
                let (group, previous) = trail.pop().unwrap();
                captures[group] = previous;
            }
            continue;
        }
        consume_regex_budget(comparisons)?;
        let branch = *choice;
        *choice += 1;
        let (pc, position, loop_state, maximum) = (*pc, *position, *loop_state, *maximum);
        let checkpoint = trail.len();
        let next = match program[pc] {
            NestedInstruction::Atom(index) => {
                let Some(width) = atom_width(&atoms[index], input, position) else {
                    continue;
                };
                (pc + 1, position + width, loop_state)
            }
            NestedInstruction::Repeat { min, greedy, .. } => {
                let length = if greedy {
                    maximum.unwrap() - branch
                } else {
                    min + branch
                };
                (pc + 1, position + length, loop_state)
            }
            NestedInstruction::Start(group) => {
                trail.push((group, captures[group]));
                captures[group] = Some((position, position));
                (pc + 1, position, loop_state)
            }
            NestedInstruction::End(group) => {
                trail.push((group, captures[group]));
                let start = captures[group].map_or(position, |capture| capture.0);
                captures[group] = Some((start, position));
                (pc + 1, position, loop_state)
            }
            NestedInstruction::StickyCommit(first, end) => {
                for index in first..end {
                    if captures[index].is_some() {
                        sticky[index] = captures[index];
                    }
                }
                (pc + 1, position, loop_state)
            }
            NestedInstruction::Split(first, second) => (
                if branch == 0 { first } else { second },
                position,
                loop_state,
            ),
            NestedInstruction::Jump(target) => (target, position, loop_state),
            NestedInstruction::Initial {
                body,
                exit,
                min,
                limit,
                greedy,
            } => {
                let repeat = if min > 0 {
                    true
                } else if limit == Some(0) {
                    false
                } else {
                    (branch == 0) == greedy
                };
                let next_state = if repeat {
                    if loop_states.len() >= MAX_STATES {
                        return Err(error("regex state limit exceeded"));
                    }
                    let state = loop_states.len();
                    loop_states.push((0, loop_state));
                    Some(state)
                } else {
                    loop_state
                };
                (if repeat { body } else { exit }, position, next_state)
            }
            NestedInstruction::Loop {
                body,
                exit,
                min,
                limit,
                greedy,
                group,
            } => {
                let state = loop_state.ok_or_else(|| error("invalid regex loop state"))?;
                let (previous_count, parent) = loop_states[state];
                let completed = previous_count + 1;
                let progressed = captures[group].is_some_and(|(start, end)| start != end);
                let repeat = if completed < min {
                    true
                } else if limit.is_some_and(|limit| completed >= limit)
                    || (!progressed && limit.is_none())
                {
                    false
                } else {
                    (branch == 0) == greedy
                };
                let next_state = if repeat {
                    if loop_states.len() >= MAX_STATES {
                        return Err(error("regex state limit exceeded"));
                    }
                    let next = loop_states.len();
                    loop_states.push((completed, parent));
                    Some(next)
                } else {
                    parent
                };
                (if repeat { body } else { exit }, position, next_state)
            }
        };
        if frames.len() >= MAX_STATES || trail.len() >= MAX_STATES {
            return Err(error("regex state limit exceeded"));
        }
        frames.push((next.0, next.1, 0, checkpoint, next.2, None));
    }
    Ok(None)
}

#[cfg(test)]
fn match_nested_repeat(
    input: &[u8],
    offset: usize,
    atoms: &[FixedRegexAtom],
    program: &[NestedInstruction],
    capture_count: usize,
    comparisons: &mut usize,
) -> Result<Option<(usize, Vec<String>)>> {
    let mut sticky = vec![None; capture_count];
    match_nested_repeat_with_sticky(
        input,
        offset,
        atoms,
        program,
        capture_count,
        &mut sticky,
        comparisons,
    )
}

fn replace_nested_pattern(
    text: &str,
    atoms: &[FixedRegexAtom],
    program: &[NestedInstruction],
    names: &[Option<String>],
    capture_count: usize,
    replacement: &str,
    comparisons: &mut usize,
) -> Result<String> {
    let input = latin1_encode(text)?;
    let mut output = Vec::new();
    let mut copied = 0;
    let mut offset = 0;
    let mut sticky = vec![None; capture_count];
    while offset <= input.len() {
        if let Some((end, mut groups)) = match_nested_repeat_with_sticky(
            &input,
            offset,
            atoms,
            program,
            capture_count,
            &mut sticky,
            comparisons,
        )? {
            groups.truncate(names.len());
            let whole = latin1_decode(&input[offset..end]);
            let expanded =
                latin1_encode(&expand_literal_groups(replacement, &whole, &groups, names)?)?;
            let prefix = offset - copied;
            if output
                .len()
                .checked_add(prefix)
                .and_then(|n| n.checked_add(expanded.len()))
                .is_none_or(|n| n > usize::from(u16::MAX))
            {
                return Err(error("short string too long"));
            }
            output.extend_from_slice(&input[copied..offset]);
            output.extend_from_slice(&expanded);
            copied = end;
            sticky.fill(None);
            offset = if end == offset { offset + 1 } else { end };
        } else {
            offset += 1;
        }
    }
    if output
        .len()
        .checked_add(input.len() - copied)
        .is_none_or(|n| n > usize::from(u16::MAX))
    {
        return Err(error("short string too long"));
    }
    output.extend_from_slice(&input[copied..]);
    Ok(latin1_decode(&output))
}

impl Packet {
    pub fn new(header: u16) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0, 0, 0, 2]);
        bytes.extend_from_slice(&header.to_be_bytes());
        Self {
            format: PacketFormat::EvaWire,
            bytes,
            cursor: 6,
            edited: false,
        }
    }
    pub fn new_with_format(format: PacketFormat, header: u16) -> Result<Self> {
        if format == PacketFormat::EvaWire {
            return Ok(Self::new(header));
        }
        Ok(Self {
            format,
            bytes: crate::encoding::encode_b64(u32::from(header), 2)?,
            cursor: 2,
            edited: false,
        })
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes_with_format(PacketFormat::EvaWire, bytes)
    }
    pub fn from_bytes_with_format(format: PacketFormat, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < format.body_offset() || bytes.len() > MAX_FRAME + 4 {
            return Err(error("invalid packet size"));
        }
        if format == PacketFormat::EvaWire {
            if u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize != bytes.len() - 4 {
                return Err(error("packet length mismatch"));
            }
        } else {
            crate::encoding::decode_b64(&bytes[..2])?;
        }
        Ok(Self {
            format,
            bytes,
            cursor: format.body_offset(),
            edited: false,
        })
    }
    pub fn format(&self) -> PacketFormat {
        self.format
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn body(&self) -> &[u8] {
        &self.bytes[self.format.body_offset()..]
    }
    pub fn header(&self) -> u16 {
        if self.format == PacketFormat::EvaWire {
            u16::from_be_bytes(self.bytes[4..6].try_into().unwrap())
        } else {
            u16::from(self.bytes[0] - 64) * 64 + u16::from(self.bytes[1] - 64)
        }
    }
    pub fn cursor(&self) -> usize {
        self.cursor
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.cursor
    }
    /// Test whether an EVA structure describes the complete body, without
    /// moving the read cursor or modifying the packet.
    pub fn structure_equals(&self, structure: &str) -> bool {
        crate::structure_prediction::structure_matches(self, structure)
    }
    /// Advance through EVA fields using beta-29 HPacket's structure codes.
    /// Unknown characters are ignored; on failure previously read fields stay consumed.
    pub fn skip_structure(&mut self, structure: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        for code in structure.chars() {
            match code {
                'i' => {
                    self.read_bytes(4)?;
                }
                's' => {
                    self.read_short_bytes()?;
                }
                'b' | 'B' => {
                    self.read_bytes(1)?;
                }
                'u' => {
                    self.read_bytes(2)?;
                }
                'l' | 'd' => {
                    self.read_bytes(8)?;
                }
                _ => {}
            }
        }
        Ok(self)
    }
    pub fn reset(&mut self) {
        self.cursor = self.format.body_offset();
    }
    pub fn set_cursor(&mut self, cursor: usize) -> Result<()> {
        if !(self.format.body_offset()..=self.bytes.len()).contains(&cursor) {
            return Err(error("cursor outside body"));
        }
        self.cursor = cursor;
        Ok(())
    }
    /// Change the header without truncating Shockwave's 12-bit identifier.
    /// An out-of-range identifier leaves the packet unchanged.
    pub fn set_header(&mut self, header: u16) -> Result<()> {
        if self.format == PacketFormat::EvaWire {
            self.bytes[4..6].copy_from_slice(&header.to_be_bytes());
        } else {
            if header >= 4096 {
                return Err(error("WEDGIE header must be between 0 and 4095"));
            }
            self.bytes[0] = 64 + ((header >> 6) & 63) as u8;
            self.bytes[1] = 64 + (header & 63) as u8;
        }
        self.edited = true;
        Ok(())
    }
    pub fn read_bytes(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .cursor
            .checked_add(n)
            .ok_or_else(|| error("length overflow"))?;
        if end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        let start = self.cursor;
        self.cursor = end;
        Ok(&self.bytes[start..end])
    }
    /// Read at an absolute packet offset without moving the current cursor.
    pub fn read_bytes_at(&self, offset: usize, n: usize) -> Result<&[u8]> {
        let end = offset
            .checked_add(n)
            .ok_or_else(|| error("length overflow"))?;
        self.bytes
            .get(offset..end)
            .ok_or_else(|| error("truncated packet field"))
    }
    fn eva_bytes_at(&self, offset: usize, n: usize) -> Result<&[u8]> {
        self.ensure_eva()?;
        self.read_bytes_at(offset, n)
    }
    pub fn read_u8_at(&self, offset: usize) -> Result<u8> {
        Ok(self.read_bytes_at(offset, 1)?[0])
    }
    /// Read the signed byte used by Java's byte type, without moving the cursor.
    pub fn read_i8_at(&self, offset: usize) -> Result<i8> {
        Ok(self.read_u8_at(offset)? as i8)
    }
    pub fn read_bool_at(&self, offset: usize) -> Result<bool> {
        if self.format == PacketFormat::EvaWire {
            Ok(self.read_u8_at(offset)? != 0)
        } else {
            Ok(self.read_i32_at(offset)? == 1)
        }
    }
    pub fn read_u16_at(&self, offset: usize) -> Result<u16> {
        match self.format {
            PacketFormat::EvaWire => Ok(u16::from_be_bytes(
                self.read_bytes_at(offset, 2)?.try_into().unwrap(),
            )),
            PacketFormat::WedgieIncoming => u16::try_from(self.read_i32_at(offset)?)
                .map_err(|_| error("WEDGIE ushort outside range")),
            PacketFormat::WedgieOutgoing => {
                Ok(crate::encoding::decode_b64(self.read_bytes_at(offset, 2)?)? as u16)
            }
        }
    }
    /// Read a Java-compatible signed short at an absolute EVA offset.
    pub fn read_i16_at(&self, offset: usize) -> Result<i16> {
        Ok(i16::from_be_bytes(
            self.eva_bytes_at(offset, 2)?.try_into().unwrap(),
        ))
    }
    pub fn read_i32_at(&self, offset: usize) -> Result<i32> {
        if self.format == PacketFormat::EvaWire {
            Ok(i32::from_be_bytes(
                self.read_bytes_at(offset, 4)?.try_into().unwrap(),
            ))
        } else {
            let bytes = self
                .bytes
                .get(offset..)
                .ok_or_else(|| error("truncated packet field"))?;
            Ok(crate::encoding::decode_vl64(bytes)?.0)
        }
    }
    pub fn read_i64_at(&self, offset: usize) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.eva_bytes_at(offset, 8)?.try_into().unwrap(),
        ))
    }
    pub fn read_f32_at(&self, offset: usize) -> Result<f32> {
        self.ensure_eva()?;
        Ok(f32::from_bits(self.read_i32_at(offset)? as u32))
    }
    pub fn read_f64_at(&self, offset: usize) -> Result<f64> {
        Ok(f64::from_bits(self.read_i64_at(offset)? as u64))
    }
    pub fn read_string_at(&self, offset: usize) -> Result<String> {
        if self.format == PacketFormat::WedgieIncoming {
            let bytes = self
                .bytes
                .get(offset..)
                .ok_or_else(|| error("truncated packet field"))?;
            let length = bytes
                .iter()
                .position(|byte| *byte == 2)
                .ok_or_else(|| error("unterminated WEDGIE string"))?;
            return Ok(latin1_decode(&bytes[..length]));
        }
        let length = usize::from(self.read_u16_at(offset)?);
        let start = offset
            .checked_add(2)
            .ok_or_else(|| error("length overflow"))?;
        Ok(latin1_decode(self.read_bytes_at(start, length)?))
    }
    pub fn read_long_string_at(&self, offset: usize) -> Result<String> {
        self.ensure_eva()?;
        let length = usize::try_from(self.read_i32_at(offset)?)
            .map_err(|_| error("negative string length"))?;
        let start = offset
            .checked_add(4)
            .ok_or_else(|| error("length overflow"))?;
        Ok(latin1_decode(self.read_bytes_at(start, length)?))
    }
    /// Read an EVA short-length-prefixed byte field without changing the cursor.
    pub fn read_short_bytes_at(&self, offset: usize) -> Result<&[u8]> {
        self.ensure_eva()?;
        let length = usize::from(self.read_u16_at(offset)?);
        let start = offset
            .checked_add(2)
            .ok_or_else(|| error("length overflow"))?;
        self.read_bytes_at(start, length)
    }
    /// Read an EVA long-length-prefixed byte field without changing the cursor.
    pub fn read_long_bytes_at(&self, offset: usize) -> Result<&[u8]> {
        self.ensure_eva()?;
        let length = usize::try_from(self.read_i32_at(offset)?)
            .map_err(|_| error("negative string length"))?;
        let start = offset
            .checked_add(4)
            .ok_or_else(|| error("length overflow"))?;
        self.read_bytes_at(start, length)
    }
    /// Read strict UTF-8 from an EVA short-length-prefixed field at an offset.
    pub fn read_utf8_at(&self, offset: usize) -> Result<&str> {
        std::str::from_utf8(self.read_short_bytes_at(offset)?).map_err(|_| error("invalid UTF-8"))
    }
    /// Read strict UTF-8 from an EVA long-length-prefixed field at an offset.
    pub fn read_utf8_long_at(&self, offset: usize) -> Result<&str> {
        std::str::from_utf8(self.read_long_bytes_at(offset)?).map_err(|_| error("invalid UTF-8"))
    }
    /// Read UTF-8 at an EVA offset, replacing malformed sequences.
    pub fn read_utf8_lossy_at(&self, offset: usize) -> Result<std::borrow::Cow<'_, str>> {
        Ok(java_utf8_lossy(self.read_short_bytes_at(offset)?))
    }
    /// Read a long UTF-8 EVA field at an offset, replacing malformed sequences.
    pub fn read_utf8_long_lossy_at(&self, offset: usize) -> Result<std::borrow::Cow<'_, str>> {
        Ok(java_utf8_lossy(self.read_long_bytes_at(offset)?))
    }
    /// Read an EVA UTF-16BE field at an offset without changing the cursor.
    pub fn read_utf16be_at(&self, offset: usize, lossy: bool) -> Result<String> {
        decode_utf16be(self.read_short_bytes_at(offset)?, lossy)
    }
    pub fn read_utf16be_long_at(&self, offset: usize, lossy: bool) -> Result<String> {
        decode_utf16be(self.read_long_bytes_at(offset)?, lossy)
    }
    /// Read an EVA UTF-16BE field; strict decoding restores the cursor on error.
    pub fn read_utf16be(&mut self, lossy: bool) -> Result<String> {
        let start = self.cursor;
        let result = self
            .read_short_bytes()
            .and_then(|bytes| decode_utf16be(bytes, lossy));
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    pub fn read_utf16be_long(&mut self, lossy: bool) -> Result<String> {
        let start = self.cursor;
        let result = self
            .read_long_bytes()
            .and_then(|bytes| decode_utf16be(bytes, lossy));
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    /// Read a Java UTF-16 variant from short/long EVA fields, optionally replacing malformed input.
    pub fn read_utf16_at(
        &self,
        offset: usize,
        encoding: Utf16Encoding,
        lossy: bool,
    ) -> Result<String> {
        decode_utf16(self.read_short_bytes_at(offset)?, encoding, lossy)
    }
    pub fn read_utf16_long_at(
        &self,
        offset: usize,
        encoding: Utf16Encoding,
        lossy: bool,
    ) -> Result<String> {
        decode_utf16(self.read_long_bytes_at(offset)?, encoding, lossy)
    }
    pub fn read_utf16(&mut self, encoding: Utf16Encoding, lossy: bool) -> Result<String> {
        let start = self.cursor;
        let result = self
            .read_short_bytes()
            .and_then(|bytes| decode_utf16(bytes, encoding, lossy));
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    pub fn read_utf16_long(&mut self, encoding: Utf16Encoding, lossy: bool) -> Result<String> {
        let start = self.cursor;
        let result = self
            .read_long_bytes()
            .and_then(|bytes| decode_utf16(bytes, encoding, lossy));
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }
    pub fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }
    pub fn read_bool(&mut self) -> Result<bool> {
        if self.format == PacketFormat::EvaWire {
            Ok(self.read_u8()? != 0)
        } else {
            Ok(self.read_i32()? == 1)
        }
    }
    pub fn read_u16(&mut self) -> Result<u16> {
        let start = self.cursor;
        let result = (|| match self.format {
            PacketFormat::EvaWire => {
                Ok(u16::from_be_bytes(self.read_bytes(2)?.try_into().unwrap()))
            }
            PacketFormat::WedgieIncoming => {
                u16::try_from(self.read_i32()?).map_err(|_| error("WEDGIE ushort outside range"))
            }
            PacketFormat::WedgieOutgoing => {
                Ok(crate::encoding::decode_b64(self.read_bytes(2)?)? as u16)
            }
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    /// Read a signed EVA short, advancing the cursor only on success.
    pub fn read_i16(&mut self) -> Result<i16> {
        self.ensure_eva()?;
        Ok(i16::from_be_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }
    pub fn read_i32(&mut self) -> Result<i32> {
        if self.format == PacketFormat::EvaWire {
            Ok(i32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
        } else {
            let (value, n) = crate::encoding::decode_vl64(&self.bytes[self.cursor..])?;
            self.cursor += n;
            Ok(value)
        }
    }
    pub fn read_i64(&mut self) -> Result<i64> {
        self.ensure_eva()?;
        Ok(i64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }
    pub fn read_f32(&mut self) -> Result<f32> {
        self.ensure_eva()?;
        Ok(f32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }
    pub fn read_f64(&mut self) -> Result<f64> {
        self.ensure_eva()?;
        Ok(f64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }
    pub fn read_string(&mut self) -> Result<String> {
        let start = self.cursor;
        let result = (|| {
            if self.format == PacketFormat::WedgieIncoming {
                let n = self.bytes[self.cursor..]
                    .iter()
                    .position(|b| *b == 2)
                    .ok_or_else(|| error("unterminated WEDGIE string"))?;
                let value = latin1_decode(self.read_bytes(n)?);
                self.cursor += 1;
                return Ok(value);
            }
            let n = self.read_u16()? as usize;
            Ok(latin1_decode(self.read_bytes(n)?))
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    /// Read an EVA two-byte-length-prefixed field without copying its bytes.
    /// Invalid or truncated fields leave the cursor unchanged.
    pub fn read_short_bytes(&mut self) -> Result<&[u8]> {
        self.ensure_eva()?;
        let start = self.cursor;
        let prefix_end = start
            .checked_add(2)
            .ok_or_else(|| error("length overflow"))?;
        let prefix = self
            .bytes
            .get(start..prefix_end)
            .ok_or_else(|| error("truncated packet field"))?;
        let len = u16::from_be_bytes(prefix.try_into().unwrap()) as usize;
        let end = prefix_end
            .checked_add(len)
            .ok_or_else(|| error("length overflow"))?;
        if end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        self.cursor = end;
        Ok(&self.bytes[prefix_end..end])
    }
    /// Read an EVA short string encoded in UTF-8. Invalid text leaves the cursor unchanged.
    pub fn read_utf8(&mut self) -> Result<String> {
        self.ensure_eva()?;
        let start = self.cursor;
        let result = (|| {
            std::str::from_utf8(self.read_short_bytes()?)
                .map(str::to_owned)
                .map_err(|_| error("invalid UTF-8"))
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    /// Read an EVA UTF-8 field with replacement decoding for malformed bytes.
    pub fn read_utf8_lossy(&mut self) -> Result<String> {
        Ok(java_utf8_lossy(self.read_short_bytes()?).into_owned())
    }
    /// Read an EVA four-byte-length-prefixed field without copying its bytes.
    /// Invalid or truncated fields leave the cursor unchanged.
    pub fn read_long_bytes(&mut self) -> Result<&[u8]> {
        self.ensure_eva()?;
        let start = self.cursor;
        let prefix_end = start
            .checked_add(4)
            .ok_or_else(|| error("length overflow"))?;
        let prefix = self
            .bytes
            .get(start..prefix_end)
            .ok_or_else(|| error("truncated packet field"))?;
        let len = i32::from_be_bytes(prefix.try_into().unwrap());
        if len < 0 {
            return Err(error("negative string length"));
        }
        let end = prefix_end
            .checked_add(len as usize)
            .ok_or_else(|| error("length overflow"))?;
        if end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        self.cursor = end;
        Ok(&self.bytes[prefix_end..end])
    }
    pub fn read_long_string(&mut self) -> Result<String> {
        Ok(latin1_decode(self.read_long_bytes()?))
    }
    pub fn read_utf8_long(&mut self) -> Result<String> {
        self.ensure_eva()?;
        let start = self.cursor;
        let result = (|| {
            std::str::from_utf8(self.read_long_bytes()?)
                .map(str::to_owned)
                .map_err(|_| error("invalid UTF-8"))
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    /// Read a long EVA UTF-8 field with replacement decoding for malformed bytes.
    pub fn read_utf8_long_lossy(&mut self) -> Result<String> {
        Ok(java_utf8_lossy(self.read_long_bytes()?).into_owned())
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        let n = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| error("length overflow"))?;
        if n > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.extend_from_slice(bytes);
        self.fix_length();
        self.edited = true;
        Ok(self)
    }
    fn fix_length(&mut self) {
        if self.format == PacketFormat::EvaWire {
            let n = (self.bytes.len() - 4) as u32;
            self.bytes[..4].copy_from_slice(&n.to_be_bytes());
        }
    }
    /// Append typed fields in order. Like Java appendObjects, successful earlier
    /// fields remain appended if a later field cannot be encoded.
    pub fn append_fields(&mut self, fields: &[PacketField<'_>]) -> Result<&mut Self> {
        self.ensure_eva()?;
        for field in fields {
            match *field {
                PacketField::Byte(value) => {
                    self.put_i8(value)?;
                }
                PacketField::Short(value) => {
                    self.put_i16(value)?;
                }
                PacketField::Integer(value) => {
                    self.put_i32(value)?;
                }
                PacketField::Long(value) => {
                    self.put_i64(value)?;
                }
                PacketField::Float(value) => {
                    self.put_f32(value)?;
                }
                PacketField::Double(value) => {
                    self.put_f64(value)?;
                }
                PacketField::Boolean(value) => {
                    self.put_bool(value)?;
                }
                PacketField::String(value) => {
                    self.put_string(value)?;
                }
                PacketField::StringJava(value) => {
                    self.put_string_java(value)?;
                }
                PacketField::StringUnits(value, encoding) => {
                    self.put_java_units(value, encoding)?;
                }
            }
        }
        Ok(self)
    }

    pub fn put_u8(&mut self, v: u8) -> Result<&mut Self> {
        self.append(&[v])
    }
    pub fn put_i8(&mut self, v: i8) -> Result<&mut Self> {
        self.put_u8(v as u8)
    }
    pub fn put_bool(&mut self, v: bool) -> Result<&mut Self> {
        if self.format == PacketFormat::EvaWire {
            self.put_u8(u8::from(v))
        } else {
            self.put_i32(i32::from(v))
        }
    }
    pub fn put_u16(&mut self, v: u16) -> Result<&mut Self> {
        match self.format {
            PacketFormat::EvaWire => self.append(&v.to_be_bytes()),
            PacketFormat::WedgieIncoming => {
                self.append(&crate::encoding::encode_vl64(i32::from(v)))
            }
            PacketFormat::WedgieOutgoing => {
                self.append(&crate::encoding::encode_b64(u32::from(v), 2)?)
            }
        }
    }
    /// Append a Java-compatible signed EVA short.
    pub fn put_i16(&mut self, v: i16) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.append(&v.to_be_bytes())
    }
    pub fn put_i32(&mut self, v: i32) -> Result<&mut Self> {
        if self.format == PacketFormat::EvaWire {
            self.append(&v.to_be_bytes())
        } else {
            self.append(&crate::encoding::encode_vl64(v))
        }
    }
    pub fn put_i64(&mut self, v: i64) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.append(&v.to_be_bytes())
    }
    pub fn put_f32(&mut self, v: f32) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.append(&v.to_be_bytes())
    }
    pub fn put_f64(&mut self, v: f64) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.append(&v.to_be_bytes())
    }
    pub fn put_string(&mut self, s: &str) -> Result<&mut Self> {
        if self.format == PacketFormat::EvaWire && s.is_ascii() {
            let length = u16::try_from(s.len()).map_err(|_| error("short string too long"))?;
            if self.bytes.len() + 2 + s.len() > MAX_FRAME + 4 {
                return Err(error("packet too large"));
            }
            self.bytes.reserve(2 + s.len());
            self.bytes.extend_from_slice(&length.to_be_bytes());
            self.bytes.extend_from_slice(s.as_bytes());
            self.fix_length();
            self.edited = true;
            return Ok(self);
        }
        let bytes = latin1_encode(s)?;
        let mut field = match self.format {
            PacketFormat::EvaWire => u16::try_from(bytes.len())
                .map_err(|_| error("short string too long"))?
                .to_be_bytes()
                .to_vec(),
            PacketFormat::WedgieOutgoing => crate::encoding::encode_b64(
                u32::try_from(bytes.len()).map_err(|_| error("WEDGIE string too long"))?,
                2,
            )?,
            PacketFormat::WedgieIncoming => {
                if bytes.contains(&2) {
                    return Err(error("WEDGIE string contains terminator"));
                }
                Vec::new()
            }
        };
        field.extend(bytes);
        if self.format == PacketFormat::WedgieIncoming {
            field.push(2);
        }
        self.append(&field)
    }
    /// Append an EVA short string using Java's ISO-8859-1 replacement encoding.
    /// Rust strings cannot contain the unpaired UTF-16 surrogates Java permits.
    pub fn put_string_java(&mut self, s: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if s.chars().count() > usize::from(u16::MAX) {
            return Err(error("short string too long"));
        }
        self.put_short_bytes(&latin1_encode_java(s))
    }
    /// Append an EVA long string using Java's ISO-8859-1 replacement encoding.
    pub fn put_long_string_java(&mut self, s: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if s.chars().count() > MAX_FRAME {
            return Err(error("packet too large"));
        }
        self.put_long_bytes(&latin1_encode_java(s))
    }
    pub fn put_long_string(&mut self, s: &str) -> Result<&mut Self> {
        self.put_long_bytes(&latin1_encode(s)?)
    }
    /// Append bytes with an EVA two-byte byte-length prefix, for custom encodings.
    pub fn put_short_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let len = u16::try_from(bytes.len()).map_err(|_| error("short string too long"))?;
        let total = self
            .bytes
            .len()
            .checked_add(2)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or_else(|| error("length overflow"))?;
        if total > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.reserve(2 + bytes.len());
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(bytes);
        self.fix_length();
        self.edited = true;
        Ok(self)
    }
    /// Append an EVA UTF-8 string with a two-byte byte-length prefix.
    pub fn put_utf8(&mut self, s: &str) -> Result<&mut Self> {
        self.put_short_bytes(s.as_bytes())
    }
    /// Append an EVA UTF-8 string with a four-byte byte-length prefix.
    pub fn put_utf8_long(&mut self, s: &str) -> Result<&mut Self> {
        self.put_long_bytes(s.as_bytes())
    }
    /// Append UTF-16BE in an EVA short or long byte-length-prefixed field.
    pub fn put_utf16be(&mut self, value: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if value.encode_utf16().count() > usize::from(u16::MAX) / 2 {
            return Err(error("short string too long"));
        }
        self.put_short_bytes(&encode_utf16be(value))
    }
    pub fn put_utf16be_long(&mut self, value: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if value.encode_utf16().count() > MAX_FRAME / 2 {
            return Err(error("packet too large"));
        }
        self.put_long_bytes(&encode_utf16be(value))
    }
    /// Encode Java UTF-16 code units into an EVA short/long field using replacement semantics.
    pub fn put_java_units(
        &mut self,
        units: &[u16],
        encoding: JavaStringEncoding,
    ) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.put_short_bytes(&encode_java_units(units, encoding, usize::from(u16::MAX))?)
    }
    pub fn put_java_units_long(
        &mut self,
        units: &[u16],
        encoding: JavaStringEncoding,
    ) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.put_long_bytes(&encode_java_units(units, encoding, MAX_FRAME)?)
    }
    pub fn replace_java_units(
        &mut self,
        offset: usize,
        units: &[u16],
        encoding: JavaStringEncoding,
    ) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.replace_short_bytes(
            offset,
            &encode_java_units(units, encoding, usize::from(u16::MAX))?,
        )
    }

    /// Append a Java UTF-16 variant as a short/long EVA field.
    pub fn put_utf16(&mut self, value: &str, encoding: Utf16Encoding) -> Result<&mut Self> {
        self.ensure_eva()?;
        if utf16_byte_len(value, encoding).is_none_or(|length| length > usize::from(u16::MAX)) {
            return Err(error("short string too long"));
        }
        self.put_short_bytes(&encode_utf16(value, encoding))
    }
    pub fn put_utf16_long(&mut self, value: &str, encoding: Utf16Encoding) -> Result<&mut Self> {
        self.ensure_eva()?;
        if utf16_byte_len(value, encoding).is_none_or(|length| length > MAX_FRAME) {
            return Err(error("packet too large"));
        }
        self.put_long_bytes(&encode_utf16(value, encoding))
    }
    pub fn put_long_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let n = i32::try_from(bytes.len()).map_err(|_| error("string too long"))?;
        let total = self
            .bytes
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or_else(|| error("length overflow"))?;
        if total > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.reserve(4 + bytes.len());
        self.bytes.extend_from_slice(&n.to_be_bytes());
        self.bytes.extend_from_slice(bytes);
        self.fix_length();
        self.edited = true;
        Ok(self)
    }
    pub fn replace(&mut self, offset: usize, count: usize, replacement: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(count)
            .ok_or_else(|| error("offset overflow"))?;
        if offset < self.format.body_offset() || end > self.bytes.len() {
            return Err(error("replacement outside body"));
        }
        if self.bytes.len() - count + replacement.len() > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.splice(offset..end, replacement.iter().copied());
        self.fix_length();
        self.reset();
        self.edited = true;
        Ok(())
    }

    /// Replace a fixed-width EVA field at an absolute packet offset, preserving
    /// the read cursor. Header and length bytes are intentionally protected.
    fn replace_fixed(&mut self, offset: usize, replacement: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let end = offset
            .checked_add(replacement.len())
            .ok_or_else(|| error("offset overflow"))?;
        if offset < self.format.body_offset() || end > self.bytes.len() {
            return Err(error("replacement outside body"));
        }
        self.bytes[offset..end].copy_from_slice(replacement);
        self.edited = true;
        Ok(self)
    }

    pub fn replace_u8(&mut self, offset: usize, value: u8) -> Result<&mut Self> {
        self.replace_fixed(offset, &[value])
    }
    pub fn replace_i8(&mut self, offset: usize, value: i8) -> Result<&mut Self> {
        self.replace_u8(offset, value as u8)
    }
    /// Overwrite bytes at an absolute EVA body offset without changing the
    /// packet length or read cursor. An out-of-range write is rejected in full.
    pub fn replace_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<&mut Self> {
        self.replace_fixed(offset, bytes)
    }
    pub fn replace_bool(&mut self, offset: usize, value: bool) -> Result<&mut Self> {
        self.replace_u8(offset, u8::from(value))
    }
    pub fn replace_u16(&mut self, offset: usize, value: u16) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_i16(&mut self, offset: usize, value: i16) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_i32(&mut self, offset: usize, value: i32) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_i64(&mut self, offset: usize, value: i64) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_f32(&mut self, offset: usize, value: f32) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_f64(&mut self, offset: usize, value: f64) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }

    /// Replace one length-prefixed Latin-1 string. A cursor past the new end
    /// is clamped so subsequent reads remain safe after a shrinking edit.
    pub fn replace_string(&mut self, offset: usize, value: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if value.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
        self.replace_short_bytes(offset, &latin1_encode(value)?)
    }
    /// Replace an EVA short string using Java's ISO-8859-1 replacement encoding.
    pub fn replace_string_java(&mut self, offset: usize, value: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if value.chars().count() > usize::from(u16::MAX) {
            return Err(error("short string too long"));
        }
        self.replace_short_bytes(offset, &latin1_encode_java(value))
    }
    pub fn replace_utf16be(&mut self, offset: usize, value: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if value.encode_utf16().count() > usize::from(u16::MAX) / 2 {
            return Err(error("short string too long"));
        }
        self.replace_short_bytes(offset, &encode_utf16be(value))
    }
    pub fn replace_utf16(
        &mut self,
        offset: usize,
        value: &str,
        encoding: Utf16Encoding,
    ) -> Result<&mut Self> {
        self.ensure_eva()?;
        if utf16_byte_len(value, encoding).is_none_or(|length| length > usize::from(u16::MAX)) {
            return Err(error("short string too long"));
        }
        self.replace_short_bytes(offset, &encode_utf16(value, encoding))
    }
    /// Replace a two-byte-length-prefixed UTF-8 string at an absolute offset.
    pub fn replace_utf8(&mut self, offset: usize, value: &str) -> Result<&mut Self> {
        self.replace_short_bytes(offset, value.as_bytes())
    }
    /// Replace an EVA two-byte-length-prefixed field with caller-encoded bytes.
    pub fn replace_short_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let prefix_end = offset
            .checked_add(2)
            .ok_or_else(|| error("offset overflow"))?;
        if offset < self.format.body_offset() || prefix_end > self.bytes.len() {
            return Err(error("replacement outside body"));
        }
        let old_len =
            u16::from_be_bytes(self.bytes[offset..prefix_end].try_into().unwrap()) as usize;
        let old_end = prefix_end
            .checked_add(old_len)
            .ok_or_else(|| error("length overflow"))?;
        if old_end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        let len = u16::try_from(bytes.len()).map_err(|_| error("short string too long"))?;
        let mut field = Vec::with_capacity(2 + bytes.len());
        field.extend_from_slice(&len.to_be_bytes());
        field.extend_from_slice(bytes);
        let cursor = self.cursor;
        self.replace(offset, old_end - offset, &field)?;
        self.cursor = cursor.min(self.bytes.len());
        Ok(self)
    }

    /// Replace non-overlapping occurrences of a big-endian integer in the body.
    pub fn replace_all_i32(&mut self, old: i32, new: i32) -> Result<usize> {
        self.ensure_eva()?;
        let old = old.to_be_bytes();
        let new = new.to_be_bytes();
        let mut offset = self.format.body_offset();
        let mut count = 0;
        while offset + 4 <= self.bytes.len() {
            if self.bytes[offset..offset + 4] == old {
                self.bytes[offset..offset + 4].copy_from_slice(&new);
                self.edited = true;
                count += 1;
                offset += 4;
            } else {
                offset += 1;
            }
        }
        Ok(count)
    }

    /// Replace up to `limit` exact, length-prefixed Latin-1 strings anywhere in
    /// the EVA body; `None` replaces all. The packet is unchanged on failure.
    pub fn replace_strings(&mut self, old: &str, new: &str, limit: Option<usize>) -> Result<usize> {
        self.ensure_eva()?;
        if limit == Some(0) {
            return Ok(0);
        }
        if old.len() > usize::from(u16::MAX) * 2 || new.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
        let old = latin1_encode(old)?;
        let new = latin1_encode(new)?;
        let old_len = u16::try_from(old.len()).map_err(|_| error("short string too long"))?;
        let new_len = u16::try_from(new.len()).map_err(|_| error("short string too long"))?;
        let mut result = Vec::new();
        let mut offset = self.format.body_offset();
        let mut copied = 0;
        let mut count = 0;
        while offset + 2 + old.len() <= self.bytes.len() {
            if self.bytes[offset..offset + 2] == old_len.to_be_bytes()
                && self.bytes[offset + 2..offset + 2 + old.len()] == old
            {
                let end = offset + 2 + old.len();
                let needed = result
                    .len()
                    .checked_add(offset - copied)
                    .and_then(|n| n.checked_add(2 + new.len()))
                    .and_then(|n| n.checked_add(self.bytes.len() - end))
                    .ok_or_else(|| error("length overflow"))?;
                if needed > MAX_FRAME + 4 {
                    return Err(error("packet too large"));
                }
                result.extend_from_slice(&self.bytes[copied..offset]);
                result.extend_from_slice(&new_len.to_be_bytes());
                result.extend_from_slice(&new);
                copied = end;
                offset = end;
                count += 1;
                if limit == Some(count) {
                    break;
                }
            } else {
                offset += 1;
            }
        }
        if count != 0 {
            result.extend_from_slice(&self.bytes[copied..]);
            self.bytes = result;
            self.fix_length();
            self.cursor = self.cursor.min(self.bytes.len());
            self.edited = true;
        }
        Ok(count)
    }

    /// Replace literal substrings in length-prefixed Latin-1 fields, scanning
    /// from the end as beta-29 does. Java regex patterns and replacement groups
    /// are deliberately rejected until their semantics are implemented.
    pub fn replace_substrings_literal(
        &mut self,
        old: &str,
        new: &str,
        limit: Option<usize>,
    ) -> Result<usize> {
        self.ensure_eva()?;
        if limit == Some(0) {
            return Ok(0);
        }
        if old.is_empty()
            || old.chars().any(|c| ".^$|?*+()[]{}\\".contains(c))
            || new.contains(['$', '\\'])
        {
            return Err(error(
                "empty or regex substring replacement is not supported",
            ));
        }
        self.replace_substrings_literal_inner(old, old, new, limit)
    }

    /// Java replacement-template handling for a nonempty literal pattern.
    /// Regex metacharacters in the pattern and capturing groups other than $0
    /// are not yet supported; no replacement is attempted for those patterns.
    pub fn replace_substrings_java_literal(
        &mut self,
        old: &str,
        replacement: &str,
        limit: Option<usize>,
    ) -> Result<usize> {
        self.ensure_eva()?;
        if limit == Some(0) {
            return Ok(0);
        }
        if old.is_empty() || old.chars().any(|c| ".^$|?*+()[]{}\\".contains(c)) {
            return Err(error("empty or regex substring pattern is not supported"));
        }
        // Java parses the replacement only after it finds a candidate field.
        let mut probe = self.clone();
        if probe.replace_substrings_literal_inner(old, old, old, limit)? == 0 {
            return Ok(0);
        }
        let mut expanded = String::new();
        let mut chars = replacement.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' => expanded.push(
                    chars
                        .next()
                        .ok_or_else(|| error("invalid replacement escape"))?,
                ),
                '$' => {
                    if chars.next() != Some('0') {
                        return Err(error("invalid replacement group"));
                    }
                    while chars.peek() == Some(&'0') {
                        chars.next();
                    }
                    expanded.push_str(old);
                }
                _ => expanded.push(c),
            }
            if expanded.len() > usize::from(u16::MAX) * 2 {
                return Err(error("short string too long"));
            }
        }
        self.replace_substrings_literal_inner(old, old, &expanded, limit)
    }

    /// Java substring replacement for a single nonempty literal capture group,
    /// for example `(cat)`. Other regex constructs remain unsupported.
    pub fn replace_substrings_java_group(
        &mut self,
        pattern: &str,
        replacement: &str,
        limit: Option<usize>,
    ) -> Result<usize> {
        self.ensure_eva()?;
        if limit == Some(0) {
            return Ok(0);
        }
        pattern
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .filter(|s| !s.is_empty() && !s.chars().any(|c| ".^$|?*+()[]{}\\".contains(c)))
            .ok_or_else(|| error("only one nonempty literal capture group is supported"))?;
        self.replace_substrings_java_groups(pattern, replacement, limit)
    }

    /// Bounded Java regex replacement, including patterns without capture groups.
    pub fn replace_substrings_java(
        &mut self,
        pattern: &str,
        replacement: &str,
        limit: Option<usize>,
    ) -> Result<usize> {
        self.replace_substrings_java_groups(pattern, replacement, limit)
    }

    /// Bounded Java regex replacement with capture groups, optional and repeated
    /// atoms, the dot wildcard, and a subset of classes and escapes. Other regex
    /// constructs remain unsupported.
    pub fn replace_substrings_java_groups(
        &mut self,
        pattern: &str,
        replacement: &str,
        limit: Option<usize>,
    ) -> Result<usize> {
        self.ensure_eva()?;
        if limit == Some(0) {
            return Ok(0);
        }
        if pattern.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
        let pattern_bytes = latin1_encode(pattern)?;
        let normalized_pattern = normalize_regex_comments(pattern);
        let mut pattern_source = normalized_pattern.as_str();
        let mut case_insensitive = false;
        let mut dot_all = false;
        let mut multiline = false;
        let mut unix_lines = false;
        let mut unicode_case = false;
        let mut unicode_class = false;
        while let Some(flags) = pattern_source
            .strip_prefix("(?")
            .and_then(|source| source.split_once(')'))
        {
            if flags.0.is_empty()
                || !flags
                    .0
                    .chars()
                    .all(|flag| matches!(flag, 'i' | 's' | 'm' | 'u' | 'U' | 'd' | 'x'))
            {
                break;
            }
            case_insensitive |= flags.0.contains('i');
            dot_all |= flags.0.contains('s');
            multiline |= flags.0.contains('m');
            unix_lines |= flags.0.contains('d');
            unicode_case |= flags.0.contains('u') || flags.0.contains('U');
            unicode_class |= flags.0.contains('U');
            pattern_source = flags.1;
        }
        let mut literal = String::new();
        let mut groups: Vec<String> = Vec::new();
        let mut parents: Vec<Option<usize>> = Vec::new();
        let mut names: Vec<Option<String>> = Vec::new();
        let mut atoms: Vec<FixedRegexAtom> = Vec::new();
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut dynamic = case_insensitive;
        let mut alternatives = Vec::new();
        let mut group_branches = Vec::new();
        let mut group_nodes = Vec::new();
        let mut alternative_nodes = vec![AlternationNode::default()];
        let mut node_stack = vec![0usize];
        let mut optional_node_entries = Vec::new();
        let mut optional = Vec::new();
        let mut optional_group_owners = Vec::new();
        let mut repeated = Vec::new();
        let mut group_repeat = None;
        let mut repeated_group_owner = None;
        let mut group_repeats = Vec::new();
        let mut quantifiable = false;
        let mut last_closed_group = None;
        let mut open: Vec<usize> = Vec::new();
        // Restore flags when leaving any group, including ordinary captures.
        type Flags = (bool, bool, bool, bool, bool, bool);
        let mut group_frames: Vec<(Option<usize>, usize, Flags, usize)> = Vec::new();
        let mut last_noncapturing = None;
        let mut chars = pattern_source.chars().peekable();
        let mut quoted = false;
        while let Some(mut c) = chars.next() {
            let prior_noncapturing = last_noncapturing.take();
            if quoted {
                if c == '\\' && chars.peek() == Some(&'E') {
                    chars.next();
                    quoted = false;
                    continue;
                }
                literal.push(c);
                atoms.push(literal_regex_atom(c, case_insensitive, unicode_case));
                quantifiable = true;
                last_closed_group = None;
                for &index in &open {
                    groups[index].push(c);
                }
                continue;
            }
            match c {
                '(' => {
                    if chars.peek() == Some(&'?') {
                        let mut lookahead = chars.clone();
                        lookahead.next();
                        let mut flags = Vec::new();
                        while lookahead.peek().is_some_and(|c| {
                            matches!(c, 'i' | 's' | 'm' | 'u' | 'U' | 'd' | 'x' | '-')
                        }) {
                            flags.push(lookahead.next().unwrap());
                        }
                        let scoped = lookahead.peek() == Some(&':');
                        let embedded = lookahead.peek() == Some(&')') && !flags.is_empty();
                        if scoped || embedded {
                            let saved = (
                                case_insensitive,
                                dot_all,
                                multiline,
                                unix_lines,
                                unicode_case,
                                unicode_class,
                            );
                            let mut disable = false;
                            for flag in flags {
                                if flag == '-' {
                                    if disable {
                                        return Err(error("invalid regex flags"));
                                    }
                                    disable = true;
                                    continue;
                                }
                                match flag {
                                    'i' => case_insensitive = !disable,
                                    's' => dot_all = !disable,
                                    'm' => multiline = !disable,
                                    'd' => unix_lines = !disable,
                                    'x' => {}
                                    'u' => unicode_case = !disable,
                                    'U' => {
                                        unicode_class = !disable;
                                        unicode_case = !disable;
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            lookahead.next();
                            chars = lookahead;
                            if scoped {
                                let node = push_alternation_node(
                                    &mut alternative_nodes,
                                    &mut node_stack,
                                    atoms.len(),
                                );
                                group_frames.push((None, atoms.len(), saved, node));
                            }
                            dynamic = true;
                            quantifiable = false;
                            last_closed_group = None;
                            continue;
                        }
                    }
                    if groups.len() == 99 {
                        return Err(error("too many capture groups"));
                    }
                    let name = if chars.peek() == Some(&'?') {
                        chars.next();
                        if chars.next() != Some('<') {
                            return Err(error("unsupported regex group"));
                        }
                        let mut name = String::new();
                        loop {
                            match chars.next() {
                                Some('>') => break,
                                Some(c) if c.is_ascii_alphanumeric() => name.push(c),
                                _ => return Err(error("invalid capture group name")),
                            }
                        }
                        if !name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                            || names
                                .iter()
                                .any(|candidate| candidate.as_deref() == Some(name.as_str()))
                        {
                            return Err(error("invalid capture group name"));
                        }
                        Some(name)
                    } else {
                        None
                    };
                    quantifiable = false;
                    last_closed_group = None;
                    parents.push(open.last().copied());
                    group_branches.push(alternatives.len());
                    open.push(groups.len());
                    let node =
                        push_alternation_node(&mut alternative_nodes, &mut node_stack, atoms.len());
                    alternative_nodes[node].capture = Some(groups.len());
                    group_nodes.push(node);
                    group_frames.push((
                        Some(groups.len()),
                        atoms.len(),
                        (
                            case_insensitive,
                            dot_all,
                            multiline,
                            unix_lines,
                            unicode_case,
                            unicode_class,
                        ),
                        node,
                    ));
                    groups.push(String::new());
                    names.push(name);
                    ranges.push((atoms.len(), atoms.len()));
                    continue;
                }
                ')' => {
                    let (frame, start, flags, node) = group_frames
                        .pop()
                        .ok_or_else(|| error("unbalanced capture group"))?;
                    alternative_nodes[node].end = atoms.len();
                    let popped_node = node_stack.pop();
                    debug_assert_eq!(popped_node, Some(node));
                    if let Some(group) = frame {
                        let popped = open.pop();
                        debug_assert_eq!(popped, Some(group));
                        ranges[group].1 = atoms.len();
                        last_closed_group = Some(group);
                    } else {
                        last_closed_group = None;
                        last_noncapturing = Some((start, atoms.len(), node));
                    }
                    (
                        case_insensitive,
                        dot_all,
                        multiline,
                        unix_lines,
                        unicode_case,
                        unicode_class,
                    ) = flags;
                    quantifiable = false;
                    continue;
                }
                '\\' => {
                    c = chars
                        .next()
                        .ok_or_else(|| error("unsupported regex escape"))?;
                    if c == 'Q' {
                        quoted = true;
                        continue;
                    }
                    if matches!(c, 'A' | 'z' | 'Z' | 'b' | 'B') {
                        atoms.push(match c {
                            'A' => FixedRegexAtom::Start,
                            'z' => FixedRegexAtom::EndStrict,
                            'Z' if unix_lines => FixedRegexAtom::EndUnix,
                            'b' if unicode_class => FixedRegexAtom::UnicodeWordBoundary,
                            'B' if unicode_class => FixedRegexAtom::UnicodeNonWordBoundary,
                            'b' => FixedRegexAtom::WordBoundary,
                            'B' => FixedRegexAtom::NonWordBoundary,
                            _ => FixedRegexAtom::End,
                        });
                        dynamic = true;
                        quantifiable = false;
                        last_closed_group = None;
                        continue;
                    }
                    if let Some(class) = predefined_class(c, unicode_class) {
                        atoms.push(FixedRegexAtom::Class(class));
                        dynamic = true;
                        quantifiable = true;
                        last_closed_group = None;
                        continue;
                    }
                    if let Some(byte) = control_escape(c, &mut chars)? {
                        c = char::from(byte);
                    } else if !".^$|?*+()[]{}\\#".contains(c) && !c.is_ascii_whitespace() {
                        return Err(error("unsupported regex escape"));
                    }
                }
                '^' | '$' => {
                    atoms.push(match (c, multiline, unix_lines) {
                        ('^', true, true) => FixedRegexAtom::StartLineUnix,
                        ('^', true, false) => FixedRegexAtom::StartLine,
                        ('^', false, _) => FixedRegexAtom::Start,
                        (_, true, true) => FixedRegexAtom::EndLineUnix,
                        (_, true, false) => FixedRegexAtom::EndLine,
                        (_, false, true) => FixedRegexAtom::EndUnix,
                        _ => FixedRegexAtom::End,
                    });
                    dynamic = true;
                    quantifiable = false;
                    last_closed_group = None;
                    continue;
                }
                '.' => {
                    atoms.push(if dot_all {
                        FixedRegexAtom::DotAll
                    } else if unix_lines {
                        FixedRegexAtom::DotUnix
                    } else {
                        FixedRegexAtom::Dot
                    });
                    dynamic = true;
                    quantifiable = true;
                    last_closed_group = None;
                    continue;
                }
                '[' => {
                    atoms.push(FixedRegexAtom::Class(parse_character_class(
                        &mut chars,
                        case_insensitive,
                        unicode_case,
                        unicode_class,
                    )?));
                    dynamic = true;
                    quantifiable = true;
                    last_closed_group = None;
                    continue;
                }
                '?' => {
                    if !quantifiable && last_closed_group.is_none() && prior_noncapturing.is_none()
                    {
                        return Err(error("unsupported optional quantifier"));
                    }
                    let greedy = if chars.peek() == Some(&'?') {
                        chars.next();
                        false
                    } else {
                        true
                    };
                    if chars.peek() == Some(&'+') {
                        return Err(error("unsupported possessive quantifier"));
                    }
                    let (start, end) = if quantifiable {
                        (atoms.len() - 1, atoms.len())
                    } else if let Some(group) = last_closed_group {
                        ranges[group]
                    } else {
                        let (start, end, _) = prior_noncapturing.unwrap();
                        (start, end)
                    };
                    if start != end {
                        if !quantifiable {
                            let node = if let Some(group) = last_closed_group {
                                group_nodes[group]
                            } else {
                                let (_, _, node) = prior_noncapturing.unwrap();
                                node
                            };
                            optional_node_entries.push((optional.len(), node, greedy));
                        }
                        optional.push((start, end, greedy));
                        optional_group_owners.push(if quantifiable {
                            None
                        } else {
                            last_closed_group
                        });
                    }
                    dynamic = true;
                    quantifiable = false;
                    last_closed_group = None;
                    continue;
                }
                '*' | '+' => {
                    if !quantifiable && last_closed_group.is_none() && prior_noncapturing.is_none()
                    {
                        return Err(error("unsupported repetition quantifier"));
                    }
                    let min = usize::from(c == '+');
                    let greedy = if chars.peek() == Some(&'?') {
                        chars.next();
                        false
                    } else {
                        true
                    };
                    if chars.peek() == Some(&'+') {
                        return Err(error("unsupported possessive quantifier"));
                    }
                    if quantifiable {
                        repeated.push((atoms.len() - 1, min, None, greedy));
                    } else {
                        let ancestor = last_closed_group.is_none() && !open.is_empty();
                        let (start, end, node) = if let Some(owner) = last_closed_group {
                            let (start, end) = ranges[owner];
                            (start, end, group_nodes[owner])
                        } else {
                            prior_noncapturing.unwrap()
                        };
                        group_repeats.push((start, end, min, None, greedy, node, ancestor));
                        if group_repeat.is_none() {
                            group_repeat = Some((start, end, min, None, greedy));
                            repeated_group_owner = last_closed_group;
                        }
                    }
                    dynamic = true;
                    quantifiable = false;
                    last_closed_group = None;
                    continue;
                }
                '{' => {
                    if !quantifiable && last_closed_group.is_none() && prior_noncapturing.is_none()
                    {
                        return Err(error("unsupported repetition quantifier"));
                    }
                    let (min, limit) = repetition_bounds(&mut chars)?;
                    let greedy = if chars.peek() == Some(&'?') {
                        chars.next();
                        false
                    } else {
                        true
                    };
                    if chars.peek() == Some(&'+') {
                        return Err(error("unsupported possessive quantifier"));
                    }
                    if quantifiable {
                        repeated.push((atoms.len() - 1, min, limit, greedy));
                    } else {
                        let ancestor = last_closed_group.is_none() && !open.is_empty();
                        let (start, end, node) = if let Some(owner) = last_closed_group {
                            let (start, end) = ranges[owner];
                            (start, end, group_nodes[owner])
                        } else {
                            prior_noncapturing.unwrap()
                        };
                        group_repeats.push((start, end, min, limit, greedy, node, ancestor));
                        if group_repeat.is_none() {
                            group_repeat = Some((start, end, min, limit, greedy));
                            repeated_group_owner = last_closed_group;
                        }
                    }
                    dynamic = true;
                    quantifiable = false;
                    last_closed_group = None;
                    continue;
                }
                '|' => {
                    let node = *node_stack.last().unwrap();
                    alternative_nodes[node].splits.push(atoms.len());
                    if node == 0 {
                        alternatives.push(atoms.len());
                    }
                    dynamic = true;
                    quantifiable = false;
                    last_closed_group = None;
                    continue;
                }
                ']' | '}' => {
                    return Err(error("unsupported regex construct"));
                }
                _ => {}
            }
            literal.push(c);
            atoms.push(literal_regex_atom(c, case_insensitive, unicode_case));
            quantifiable = true;
            last_closed_group = None;
            for &index in &open {
                groups[index].push(c);
            }
        }
        if !group_frames.is_empty() {
            return Err(error("invalid capture pattern"));
        }
        alternative_nodes[0].end = atoms.len();
        let has_nested_alternation = alternative_nodes
            .iter()
            .skip(1)
            .any(|node| !node.splits.is_empty());
        let use_tree_vm = has_nested_alternation
            || group_repeats.len() > 1
            || group_repeats.iter().any(|entry| entry.6)
            || (repeated_group_owner.is_none()
                && group_repeats.iter().any(|&(start, end, ..)| {
                    optional.iter().any(|&(a, b, _)| a >= start && b <= end)
                        || repeated.iter().any(|&(a, ..)| a >= start && a < end)
                }));
        if use_tree_vm && group_repeats.len() > 128 {
            return Err(error("regex repeated group limit exceeded"));
        }
        if use_tree_vm {
            for &(_, _, _, _, _, node, _) in &group_repeats {
                let mut parent = alternative_nodes[node].parent;
                let mut depth = 0;
                while let Some(index) = parent {
                    depth += 1;
                    if depth > 128 {
                        return Err(error("regex group nesting limit exceeded"));
                    }
                    parent = alternative_nodes[index].parent;
                }
            }
        }
        if use_tree_vm && !has_nested_alternation {
            // Nodes are created in preorder; each subtree is a contiguous index range.
            let mut subtree_end: Vec<usize> = (1..=alternative_nodes.len()).collect();
            for child in (1..alternative_nodes.len()).rev() {
                if let Some(parent) = alternative_nodes[child].parent {
                    subtree_end[parent] = subtree_end[parent].max(subtree_end[child]);
                }
            }
            let mut optional_node_owners = vec![None; optional.len()];
            for &(index, node, _) in &optional_node_entries {
                optional_node_owners[index] = Some(node);
                let mut parent = alternative_nodes[node].parent;
                let mut depth = 0;
                while let Some(ancestor) = parent {
                    depth += 1;
                    if depth > 128 {
                        return Err(error("regex group nesting limit exceeded"));
                    }
                    parent = alternative_nodes[ancestor].parent;
                }
            }
            for &(start, end, _, _, _, node, _) in &group_repeats {
                let mut descendants = Vec::new();
                for (group, &capture_node) in group_nodes.iter().enumerate() {
                    if capture_node == node {
                        continue;
                    }
                    let mut parent = alternative_nodes[capture_node].parent;
                    let mut depth = 0;
                    while let Some(index) = parent {
                        depth += 1;
                        if depth > 128 {
                            return Err(error("regex group nesting limit exceeded"));
                        }
                        if index == node {
                            descendants.push(group);
                            break;
                        }
                        parent = alternative_nodes[index].parent;
                    }
                }
                if !descendants.is_empty() {
                    let nested_repeat = group_repeats.iter().any(|&(_, _, _, _, _, other, _)| {
                        other > node && other < subtree_end[node]
                    });
                    if nested_repeat {
                        return Err(error(
                            "nested GroupCurly loops require Java capture validation",
                        ));
                    }
                    let optional_inside = optional.iter().enumerate().any(|(index, &(a, b, _))| {
                        if let Some(owner) = optional_node_owners[index] {
                            owner > node && owner < subtree_end[node]
                        } else {
                            a >= start && b <= end
                        }
                    });
                    let variable_atom = repeated
                        .iter()
                        .any(|&(a, min, limit, _)| a >= start && a < end && limit != Some(min));
                    if optional_inside || variable_atom {
                        // Java uses Loop rather than GroupCurly for non-deterministic bodies.
                        continue;
                    }
                    if repeated.iter().any(|&(a, ..)| a >= start && a < end) {
                        return Err(error(
                            "fixed-count nested captures require Java capture validation",
                        ));
                    }
                    let first = descendants[0];
                    let end = descendants[descendants.len() - 1] + 1;
                    if end - first != descendants.len() {
                        return Err(error("non-contiguous repeated captures are unsupported"));
                    }
                    alternative_nodes[node].sticky_captures = Some((first, end));
                }
            }
        }
        let needle = latin1_encode(&literal)?;
        let mut repeated_atoms = vec![None; atoms.len()];
        for &(index, min, limit, greedy) in &repeated {
            repeated_atoms[index] = Some((min, limit, greedy));
        }
        let mut nested_program = None;
        if let Some((start, end, _, _, _)) =
            group_repeat.filter(|_| repeated_group_owner.is_none() && !use_tree_vm)
        {
            if (!groups.is_empty() && !alternatives.is_empty())
                || ranges
                    .iter()
                    .any(|&(group_start, group_end)| group_start < start || group_end > end)
                || start == end
                || !optional.is_empty()
                || !repeated.is_empty()
                || atoms[start..end].iter().any(|atom| {
                    matches!(
                        atom,
                        FixedRegexAtom::Start
                            | FixedRegexAtom::StartLine
                            | FixedRegexAtom::StartLineUnix
                            | FixedRegexAtom::End
                            | FixedRegexAtom::EndUnix
                            | FixedRegexAtom::EndLine
                            | FixedRegexAtom::EndLineUnix
                            | FixedRegexAtom::EndStrict
                            | FixedRegexAtom::WordBoundary
                            | FixedRegexAtom::NonWordBoundary
                            | FixedRegexAtom::UnicodeWordBoundary
                            | FixedRegexAtom::UnicodeNonWordBoundary
                    )
                })
            {
                return Err(error("unsupported noncapturing repetition structure"));
            }
        }
        if let Some((start, end, min, limit, greedy)) =
            group_repeat.filter(|_| repeated_group_owner.is_some() && !use_tree_vm)
        {
            let owner = repeated_group_owner.unwrap();
            let descendants_only = (0..groups.len()).all(|group| {
                let mut current = Some(group);
                while let Some(index) = current {
                    if index == owner {
                        return true;
                    }
                    current = parents[index];
                }
                false
            });
            if !descendants_only
                || start == end
                || atoms[start..end].iter().any(|atom| {
                    matches!(
                        atom,
                        FixedRegexAtom::Start
                            | FixedRegexAtom::StartLine
                            | FixedRegexAtom::StartLineUnix
                            | FixedRegexAtom::End
                            | FixedRegexAtom::EndUnix
                            | FixedRegexAtom::EndLine
                            | FixedRegexAtom::EndLineUnix
                            | FixedRegexAtom::EndStrict
                            | FixedRegexAtom::WordBoundary
                            | FixedRegexAtom::NonWordBoundary
                            | FixedRegexAtom::UnicodeWordBoundary
                            | FixedRegexAtom::UnicodeNonWordBoundary
                    )
                })
                || repeated
                    .iter()
                    .any(|(index, ..)| *index < start || *index >= end)
            {
                return Err(error("unsupported repeated capture structure"));
            }
            if !optional.is_empty() || !repeated.is_empty() {
                if owner != 0 {
                    return Err(error("unsupported nested repeated capture"));
                }
                let mut group_optional = vec![None; groups.len()];
                let mut atom_optional = vec![None; atoms.len()];
                for (&(inner_start, inner_end, inner_greedy), &group) in
                    optional.iter().zip(&optional_group_owners)
                {
                    if inner_start < start || inner_end > end {
                        return Err(error("unsupported nested repeated capture"));
                    }
                    if let Some(group) = group {
                        if group == owner
                            || group_optional[group].is_some()
                            || (inner_start, inner_end) != ranges[group]
                        {
                            return Err(error("unsupported nested repeated capture"));
                        }
                        group_optional[group] = Some(inner_greedy);
                    } else {
                        if inner_end - inner_start != 1 || atom_optional[inner_start].is_some() {
                            return Err(error("unsupported nested optional atom"));
                        }
                        atom_optional[inner_start] = Some(inner_greedy);
                    }
                }
                let deeper = (1..groups.len()).any(|group| parents[group] != Some(owner));
                if deeper {
                    let mut children = vec![Vec::new(); groups.len()];
                    for (group, parent) in parents.iter().enumerate().skip(1) {
                        let parent = parent.ok_or_else(|| error("invalid capture hierarchy"))?;
                        children[parent].push(group);
                    }
                    for (parent, siblings) in children.iter_mut().enumerate() {
                        siblings.sort_by_key(|group| (ranges[*group].0, *group));
                        let mut cursor = ranges[parent].0;
                        for &child in siblings.iter() {
                            let (child_start, child_end) = ranges[child];
                            if child_start < cursor || child_end > ranges[parent].1 {
                                return Err(error("overlapping nested captures are not supported"));
                            }
                            cursor = child_end;
                        }
                    }
                    let plan = DeepCapturePlan {
                        ranges: &ranges,
                        children: &children,
                        group_optional: &group_optional,
                        repeated: &repeated_atoms,
                        atom_optional: &atom_optional,
                    };
                    nested_program = Some(compile_deep_nested_repeat(
                        atoms.len(),
                        (start, end, min, limit, greedy),
                        owner,
                        &plan,
                    ));
                } else {
                    let mut inner_specs = (1..groups.len())
                        .map(|group| {
                            let (inner_start, inner_end) = ranges[group];
                            (inner_start, inner_end, group_optional[group], group)
                        })
                        .collect::<Vec<_>>();
                    inner_specs.sort_by_key(|spec| (spec.0, spec.1));
                    let mut cursor = start;
                    for &(inner_start, inner_end, _, _) in &inner_specs {
                        if inner_start < cursor || inner_end > end {
                            return Err(error("overlapping nested captures are not supported"));
                        }
                        cursor = inner_end;
                    }
                    nested_program = Some(compile_nested_repeat(
                        atoms.len(),
                        (start, end, min, limit, greedy),
                        &inner_specs,
                        owner,
                        &repeated_atoms,
                        &atom_optional,
                    ));
                }
            }
        }
        let mut nested_capture_count = names.len();
        if use_tree_vm {
            for &(start, end, min, limit, greedy, node, _) in &group_repeats {
                let mut parent = alternative_nodes[node].parent;
                let mut depth = 0;
                while let Some(index) = parent {
                    depth += 1;
                    if depth > 128 {
                        return Err(error("regex group nesting limit exceeded"));
                    }
                    parent = alternative_nodes[index].parent;
                }
                if alternative_nodes[node].start != start || alternative_nodes[node].end != end {
                    return Err(error("invalid repeated group range"));
                }
                let hidden = alternative_nodes[node].capture.is_none();
                let progress = if let Some(group) = alternative_nodes[node].capture {
                    group
                } else {
                    let group = nested_capture_count;
                    nested_capture_count += 1;
                    group
                };
                alternative_nodes[node].repeat = Some((min, limit, greedy, progress, hidden));
            }
            let mut node_optional = vec![None; alternative_nodes.len()];
            let mut optional_owners = vec![None; optional.len()];
            for &(index, node, greedy) in &optional_node_entries {
                optional_owners[index] = Some(node);
                if node_optional[node].replace(greedy).is_some() {
                    return Err(error("multiple optional quantifiers on a group"));
                }
            }
            let mut atom_optional = vec![None; atoms.len()];
            for (index, &(start, end, greedy)) in optional.iter().enumerate() {
                if optional_owners[index].is_some() {
                    continue;
                }
                if end != start + 1 || atom_optional[start].replace(greedy).is_some() {
                    return Err(error("unsupported optional alternation structure"));
                }
            }
            let mut compiled = Vec::new();
            emit_alternation_node(
                &mut compiled,
                &alternative_nodes,
                0,
                &node_optional,
                &repeated_atoms,
                &atom_optional,
                0,
            )?;
            nested_program = Some(compiled);
        }
        let mut branch_programs = Vec::new();
        if !alternatives.is_empty() && !use_tree_vm {
            if !groups.is_empty() && group_repeat.is_some() {
                return Err(error("repeated capturing alternation is not supported"));
            }
            let mut boundaries = Vec::with_capacity(alternatives.len() + 2);
            boundaries.push(0);
            boundaries.extend(alternatives);
            boundaries.push(atoms.len());
            for (branch_index, pair) in boundaries.windows(2).enumerate() {
                let (start, end) = (pair[0], pair[1]);
                let mut branch_groups = Vec::new();
                for (group, &(group_start, group_end)) in ranges.iter().enumerate() {
                    if group_branches[group] != branch_index {
                        continue;
                    }
                    if group_start < start || group_end > end {
                        return Err(error("capture spans multiple alternatives"));
                    }
                    branch_groups.push((group, group_start - start, group_end - start));
                }
                let branch_optional = optional
                    .iter()
                    .filter(|(a, b, _)| *a >= start && *b <= end)
                    .map(|(a, b, greedy)| (a - start, b - start, *greedy))
                    .collect::<Vec<_>>();
                let branch_repeat = group_repeat.and_then(|(a, b, min, limit, greedy)| {
                    (a >= start && b <= end).then(|| (a - start, b - start, min, limit, greedy))
                });
                let program = compile_optional_program(
                    end - start,
                    &branch_optional,
                    &repeated_atoms[start..end],
                    branch_repeat,
                );
                branch_programs.push(RegexBranch {
                    start,
                    end,
                    program,
                    groups: branch_groups,
                });
            }
        }
        let capture_repeat = group_repeat.and_then(|(start, end, min, limit, greedy)| {
            (!use_tree_vm && !groups.is_empty() && repeated_group_owner.is_none()).then_some(
                CaptureRepeat {
                    start,
                    end,
                    min,
                    limit,
                    greedy,
                    ranges: &ranges,
                    names: &names,
                },
            )
        });
        let program = if nested_program.is_some() {
            Vec::new()
        } else {
            compile_optional_program(atoms.len(), &optional, &repeated_atoms, group_repeat)
        };
        let mut candidate = self.clone();
        let mut offset = candidate.bytes.len() as isize - 2 - pattern_bytes.len() as isize;
        let mut max = candidate.bytes.len();
        let mut count = 0;
        let mut scanned_bytes = 0usize;
        let mut comparisons = 0usize;
        while offset >= candidate.format.body_offset() as isize {
            let i = offset as usize;
            if i + 2 <= candidate.bytes.len() {
                let length =
                    u16::from_be_bytes([candidate.bytes[i], candidate.bytes[i + 1]]) as usize;
                let end = i + 2 + length;
                if end <= candidate.bytes.len() && end <= max {
                    scanned_bytes = scanned_bytes
                        .checked_add(length)
                        .filter(|n| *n <= MAX_FRAME)
                        .ok_or_else(|| error("substring scan limit exceeded"))?;
                    let text = latin1_decode(&candidate.bytes[i + 2..end]);
                    if text.contains(pattern) {
                        let result = if let Some(plan) = &capture_repeat {
                            replace_capture_repeat(
                                &text,
                                &atoms,
                                plan,
                                replacement,
                                &mut comparisons,
                            )?
                        } else if !branch_programs.is_empty() {
                            replace_alternatives(
                                &text,
                                &atoms,
                                &branch_programs,
                                &names,
                                replacement,
                                &mut comparisons,
                            )?
                        } else if let Some(nested_program) = &nested_program {
                            replace_nested_pattern(
                                &text,
                                &atoms,
                                nested_program,
                                &names,
                                nested_capture_count,
                                replacement,
                                &mut comparisons,
                            )?
                        } else if dynamic {
                            replace_fixed_pattern(
                                &text,
                                &atoms,
                                &ranges,
                                &names,
                                replacement,
                                &mut comparisons,
                                &program,
                            )?
                        } else if !text.contains(&literal) {
                            text
                        } else {
                            let occurrences = text.matches(&literal).count();
                            let expanded =
                                expand_literal_groups(replacement, &literal, &groups, &names)?;
                            let expanded_bytes = latin1_encode(&expanded)?;
                            let result_len = length
                                .checked_sub(occurrences * needle.len())
                                .and_then(|n| {
                                    occurrences
                                        .checked_mul(expanded_bytes.len())
                                        .and_then(|size| n.checked_add(size))
                                })
                                .filter(|n| *n <= usize::from(u16::MAX))
                                .ok_or_else(|| error("short string too long"))?;
                            if candidate.bytes.len() - length + result_len > MAX_FRAME + 4 {
                                return Err(error("packet too large"));
                            }
                            text.replace(&literal, &expanded)
                        };
                        if candidate.bytes.len() - length + latin1_encode(&result)?.len()
                            > MAX_FRAME + 4
                        {
                            return Err(error("packet too large"));
                        }
                        candidate.replace_string(i, &result)?;
                        count += 1;
                        offset -= 1 + pattern_bytes.len() as isize;
                        if limit == Some(count) {
                            break;
                        }
                        if offset < 0 {
                            break;
                        }
                        max = offset as usize;
                    }
                }
            }
            offset -= 1;
        }
        *self = candidate;
        Ok(count)
    }

    fn replace_substrings_literal_inner(
        &mut self,
        old: &str,
        needle: &str,
        new: &str,
        limit: Option<usize>,
    ) -> Result<usize> {
        if old.len() > usize::from(u16::MAX) * 2 || new.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
        let old_bytes = latin1_encode(old)?;
        let new_bytes = latin1_encode(new)?;
        let needle_bytes = latin1_encode(needle)?;
        let mut candidate = self.clone();
        let mut offset = candidate.bytes.len() as isize - 2 - old_bytes.len() as isize;
        let mut max = candidate.bytes.len();
        let mut count = 0;
        let mut scanned_bytes = 0usize;
        while offset >= candidate.format.body_offset() as isize {
            let i = offset as usize;
            if i + 2 <= candidate.bytes.len() {
                let length =
                    u16::from_be_bytes([candidate.bytes[i], candidate.bytes[i + 1]]) as usize;
                let end = i + 2 + length;
                if end <= candidate.bytes.len() && end <= max {
                    scanned_bytes = scanned_bytes
                        .checked_add(length)
                        .filter(|n| *n <= MAX_FRAME)
                        .ok_or_else(|| error("substring scan limit exceeded"))?;
                    let text = latin1_decode(&candidate.bytes[i + 2..end]);
                    if text.contains(old) {
                        let occurrences = text.matches(needle).count();
                        let result_len = length
                            .checked_sub(occurrences * needle_bytes.len())
                            .and_then(|n| {
                                occurrences
                                    .checked_mul(new_bytes.len())
                                    .and_then(|growth| n.checked_add(growth))
                            })
                            .filter(|n| *n <= usize::from(u16::MAX))
                            .ok_or_else(|| error("short string too long"))?;
                        if candidate.bytes.len() - length + result_len > MAX_FRAME + 4 {
                            return Err(error("packet too large"));
                        }
                        let replacement = text.replace(needle, new);
                        candidate.replace_string(i, &replacement)?;
                        count += 1;
                        offset -= 1 + old_bytes.len() as isize;
                        if limit == Some(count) {
                            break;
                        }
                        if offset < 0 {
                            break;
                        }
                        max = offset as usize;
                    }
                }
            }
            offset -= 1;
        }
        *self = candidate;
        Ok(count)
    }
    pub fn stringify(&self) -> String {
        format!(
            "{}{}",
            if self.edited { '1' } else { '0' },
            latin1_decode(&self.bytes)
        )
    }
    pub fn from_stringified(s: &str) -> Result<Self> {
        Self::from_stringified_with_format(s, PacketFormat::EvaWire)
    }
    pub fn from_stringified_with_format(s: &str, format: PacketFormat) -> Result<Self> {
        let flag = *s
            .as_bytes()
            .first()
            .ok_or_else(|| error("empty serialized packet"))?;
        if flag != b'0' && flag != b'1' {
            return Err(error("invalid edited flag"));
        }
        let mut p = Self::from_bytes_with_format(format, latin1_encode(&s[1..])?)?;
        p.edited = flag == b'1';
        Ok(p)
    }
    fn ensure_eva(&self) -> Result<()> {
        if self.format == PacketFormat::EvaWire {
            Ok(())
        } else {
            Err(error("field is not supported by WEDGIE packets"))
        }
    }
}
#[derive(Debug, Clone)]
pub struct Message {
    pub packet: Packet,
    pub direction: Direction,
    pub index: i32,
    pub blocked: bool,
}
impl Message {
    pub fn stringify(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            u8::from(self.blocked),
            self.index,
            self.direction.name(),
            self.packet.stringify()
        )
    }
    pub fn parse(s: &str) -> Result<Self> {
        Self::parse_with_format(s, PacketFormat::EvaWire)
    }
    pub fn parse_with_format(s: &str, format: PacketFormat) -> Result<Self> {
        let mut fields = s.splitn(4, '\t');
        let blocked = match fields.next() {
            Some("1") => true,
            Some("0") => false,
            _ => return Err(error("invalid blocked flag")),
        };
        let index = fields
            .next()
            .ok_or_else(|| error("missing index"))?
            .parse()
            .map_err(|_| error("invalid index"))?;
        let direction = Direction::parse(fields.next().ok_or_else(|| error("missing direction"))?)?;
        let packet = Packet::from_stringified_with_format(
            fields.next().ok_or_else(|| error("missing packet"))?,
            format,
        )?;
        Ok(Self {
            packet,
            direction,
            index,
            blocked,
        })
    }
}
pub fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}
/// Java ISO-8859-1 encoder replacement for valid Rust Unicode scalar values.
pub fn latin1_encode_java(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| u8::try_from(c as u32).unwrap_or(b'?'))
        .collect()
}
pub fn latin1_encode(s: &str) -> Result<Vec<u8>> {
    s.chars()
        .map(|c| u8::try_from(c as u32).map_err(|_| error("character outside ISO-8859-1")))
        .collect()
}

/// Incremental decoder with bounded buffering and no drain/copy of retained frames.
#[derive(Default)]
pub struct FrameDecoder {
    bytes: Vec<u8>,
    start: usize,
}
impl FrameDecoder {
    /// Number of bytes retained for an incomplete or not-yet-consumed frame.
    pub fn pending_bytes(&self) -> usize {
        self.bytes.len() - self.start
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        // Leave room for a transport read containing the tail of a maximum-size
        // frame followed by the start of the next frame.
        if self.bytes.len() - self.start + bytes.len() > MAX_FRAME + 4 + 65536 {
            return Err(error("frame buffer limit exceeded"));
        }
        if self.start != 0 {
            self.bytes.drain(..self.start);
            self.start = 0;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        let available = &self.bytes[self.start..];
        if available.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes(available[..4].try_into().unwrap()) as usize;
        if !(2..=MAX_FRAME).contains(&n) {
            return Err(error("invalid frame length"));
        }
        if available.len() < n + 4 {
            return Ok(None);
        }
        let p = Packet::from_bytes(available[..n + 4].to_vec())?;
        self.start += n + 4;
        if self.start == self.bytes.len() {
            self.bytes.clear();
            self.start = 0;
        }
        Ok(Some(p))
    }
}
pub fn read_frame(reader: &mut impl Read) -> io::Result<Packet> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let n = u32::from_be_bytes(prefix) as usize;
    if !(2..=MAX_FRAME).contains(&n) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut bytes = vec![0; n + 4];
    bytes[..4].copy_from_slice(&prefix);
    reader.read_exact(&mut bytes[4..])?;
    Packet::from_bytes(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
pub fn write_frame(writer: &mut impl Write, packet: &Packet) -> io::Result<()> {
    writer.write_all(packet.bytes())
}
