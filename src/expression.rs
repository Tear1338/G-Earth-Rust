use crate::{packet::{error,latin1_encode,Packet,Result,Direction,PacketFormat,MAX_FRAME},packet_info::PacketInfoManager};

/// Parse EVA_WIRE expressions or G-Earth's lossless [byte] display notation.
pub fn parse(expression:&str)->Result<Packet> {parse_inner(expression,PacketFormat::EvaWire,None)}
pub fn parse_with_info(expression:&str,direction:Direction,database:&PacketInfoManager)->Result<Packet> {
    parse_inner(expression,PacketFormat::EvaWire,Some((direction,database)))
}
pub fn parse_with_format(expression:&str,format:PacketFormat,context:Option<(Direction,&PacketInfoManager)>)->Result<Packet>{parse_inner(expression,format,context)}
fn parse_inner(expression:&str,format:PacketFormat,context:Option<(Direction,&PacketInfoManager)>)->Result<Packet> {
    let mut rest=expression;let mut bytes=Vec::new();let mut implicit_length=false;
    while !rest.is_empty() {
        if rest.starts_with('{') {
            let mut quoted=false;let mut escaped=false;let mut end=None;
            for (i,c) in rest.char_indices().skip(1) {
                if escaped {escaped=false;continue;}
                if c=='\\'&&quoted {escaped=true;continue;}
                if c=='"' {quoted=!quoted;}
                if c=='}'&&!quoted {end=Some(i);break;}
            }
            let end=end.ok_or_else(||error("unterminated expression field"))?;
            let (kind,value)=rest[1..end].split_once(':').ok_or_else(||error("missing ':'"))?;
            let value=value.trim();
            if bytes.is_empty()&&matches!(kind,"h"|"in"|"out") {
                implicit_length=format==PacketFormat::EvaWire;
                let header=if kind=="h" {
                    let n:i32=value.parse().map_err(|_|error("invalid header"))?;
                    if !(-32768..=65535).contains(&n){return Err(error("header outside 16-bit range"));}
                    n as u16
                }else{
                    let (direction,database)=context.ok_or_else(||error("load the packet identifier database before using named headers"))?;
                    let expected=if kind=="in"{Direction::ToClient}else{Direction::ToServer};
                    if direction!=expected{return Err(error("named packet direction differs from selected destination"));}
                    database.by_name(direction,value).ok_or_else(||error("packet identifier not found"))?.header
                };
                bytes.extend_from_slice(Packet::new_with_format(format,header)?.bytes());
            }else{
                let mut field=Packet::new_with_format(format,0)?;append_field(&mut field,kind,value)?;bytes.extend_from_slice(field.body());
            }
            rest=&rest[end+1..];
        }else if rest.starts_with('['){
            let end=rest.find(']').ok_or_else(||error("unterminated [byte]"))?;
            let byte:u8=rest[1..end].parse().map_err(|_|error("invalid [byte]"))?;bytes.push(byte);rest=&rest[end+1..];
        }else{
            let c=rest.chars().next().unwrap();
            if c=='}'{return Err(error("unexpected '}'"));}
            bytes.push(u8::try_from(c as u32).map_err(|_|error("character outside ISO-8859-1"))?);rest=&rest[c.len_utf8()..];
        }
        if bytes.len()>MAX_FRAME+4{return Err(error("packet too large"));}
    }
    if implicit_length {let length=u32::try_from(bytes.len()-4).map_err(|_|error("packet too large"))?;bytes[..4].copy_from_slice(&length.to_be_bytes());}
    Packet::from_bytes_with_format(format,bytes)
}
fn append_field(p:&mut Packet,kind:&str,value:&str)->Result<()> {
    match kind {
        "h"|"u"=>{p.put_u16(value.parse().map_err(|_|error("invalid unsigned short"))?)?;}
        "i"=>{p.put_i32(value.parse().map_err(|_|error("invalid integer"))?)?;}
        "l"=>{p.put_i64(value.parse().map_err(|_|error("invalid long"))?)?;}
        "b"=>{if value.eq_ignore_ascii_case("true"){p.put_bool(true)?;}else if value.eq_ignore_ascii_case("false"){p.put_bool(false)?;}else{p.put_u8(value.parse().map_err(|_|error("invalid byte"))?)?;}}
        "d"=>{p.put_f64(value.parse().map_err(|_|error("invalid double"))?)?;}
        "f"=>{p.put_f32(value.parse().map_err(|_|error("invalid float"))?)?;}
        "s"=>{p.put_string(&unquote(value)?)?;}
        "ls"=>{p.put_long_string(&unquote(value)?)?;}
        "hex"=>{p.append(&parse_hex(value)?)?;}
        _=>return Err(error("unsupported expression field")),
    }
    Ok(())
}
fn unquote(value:&str)->Result<String> {
    if !value.starts_with('"')||!value.ends_with('"')||value.len()<2{return Err(error("string must use double quotes"));}
    let mut result=String::new();let mut chars=value[1..value.len()-1].chars();
    while let Some(c)=chars.next(){
        if c=='\\'{result.push(match chars.next(){Some('n')=>'\n',Some('r')=>'\r',Some('t')=>'\t',Some('0')=>'\0',Some('"')=>'"',Some('\\')=>'\\',_=>return Err(error("invalid string escape"))});}
        else{result.push(c);}
    }
    latin1_encode(&result)?;Ok(result)
}
pub fn parse_hex(s:&str)->Result<Vec<u8>> {
    let compact:String=s.chars().filter(|c|!c.is_whitespace()).collect();
    if !compact.len().is_multiple_of(2)||!compact.is_ascii(){return Err(error("hex requires pairs of ASCII digits"));}
    (0..compact.len()).step_by(2).map(|i|u8::from_str_radix(&compact[i..i+2],16).map_err(|_|error("invalid hex"))).collect()
}
pub fn hex(bytes:&[u8])->String {bytes.iter().map(|b|format!("{b:02X}")).collect::<Vec<_>>().join(" ")}
pub fn to_lossless_expression(p:&Packet)->String {format!("{{h:{}}}{{hex:{}}}",p.header(),hex(p.body()))}
pub fn wire_display(bytes:&[u8])->String {
    let mut s=String::new();for &b in bytes {if b<32||(127..160).contains(&b)||matches!(b,b'['|b']'|b'{'|b'}'){s.push_str(&format!("[{b}]"));}else{s.push(char::from(b));}}s
}
