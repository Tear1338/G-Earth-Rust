//! Original beta-29 language resources, with Java .properties decoding.
use std::collections::HashMap;
pub const LANGUAGES:&[(&str,&str)]=&[("en","English"),("fr","Français"),("de","Deutsch"),("es","Español"),("fi","Suomi"),("it","Italiano"),("nl","Nederlands"),("pt","Português"),("tr","Türkçe")];
const BUNDLES:&[(&str,&str)]=&[
    ("en",include_str!("../locales/messages_en.properties")),("fr",include_str!("../locales/messages_fr.properties")),("de",include_str!("../locales/messages_de.properties")),("es",include_str!("../locales/messages_es.properties")),("fi",include_str!("../locales/messages_fi.properties")),("it",include_str!("../locales/messages_it.properties")),("nl",include_str!("../locales/messages_nl.properties")),("pt",include_str!("../locales/messages_pt.properties")),("tr",include_str!("../locales/messages_tr.properties")),
];
#[derive(Clone)]
pub struct I18n {values:HashMap<String,String>}
impl I18n {
    pub fn new(language:&str)->Self {let mut values=parse_properties(BUNDLES[0].1);if let Some((_,s))=BUNDLES.iter().find(|(l,_)|*l==language){values.extend(parse_properties(s));}Self {values}}
    pub fn text(&self,key:&str)->String {self.values.get(key).cloned().unwrap_or_else(||key.to_owned())}
}
pub fn parse_properties(source:&str)->HashMap<String,String> {
    let mut values=HashMap::new();let mut combined=String::new();
    for raw in source.lines() {
        let raw=raw.trim_start();combined.push_str(raw);
        if combined.chars().rev().take_while(|c|*c=='\\').count()%2==1 {combined.pop();continue;}
        let line=std::mem::take(&mut combined);if line.is_empty()||line.starts_with(['#','!']){continue;}
        let mut escaped=false;let mut separator=None;
        for (i,c) in line.char_indices(){if escaped{escaped=false;continue;}if c=='\\'{escaped=true;continue;}if c=='='||c==':'||c.is_whitespace(){separator=Some(i);break;}}
        let (key,value)=match separator {Some(i)=>{let mut rest=line[i..].trim_start();if rest.starts_with(['=',':']){rest=rest[1..].trim_start();}(&line[..i],rest)},None=>(line.as_str(),"")};
        values.insert(unescape(key),unescape(value));
    }
    values
}
fn unescape(s:&str)->String {
    let mut output=Vec::new();let mut chars=s.chars();
    while let Some(c)=chars.next(){let c=if c=='\\'{match chars.next(){Some('u')=>{let hex:String=chars.by_ref().take(4).collect();if let Ok(n)=u16::from_str_radix(&hex,16){output.push(n);}else{output.push(0xfffd);}continue;},Some('n')=>'\n',Some('r')=>'\r',Some('t')=>'\t',Some('f')=>'\x0c',Some(c)=>c,None=>'\\'}}else{c};let mut temp=[0;2];output.extend_from_slice(c.encode_utf16(&mut temp));}
    String::from_utf16_lossy(&output)
}
