//! SOCKS5 CONNECT, with optional RFC 1929 username/password authentication.
use std::{io::{self,Read,Write},net::{IpAddr,TcpStream,ToSocketAddrs},time::Duration};
#[derive(Clone,Debug)]
pub struct SocksConfig {pub proxy:String,pub credentials:Option<(String,String)>}
impl SocksConfig {
    pub fn connect(&self,target:&str)->io::Result<TcpStream> {
        let addresses:Vec<_>=self.proxy.to_socket_addrs()?.collect();
        let mut stream=addresses.iter().find_map(|a|TcpStream::connect_timeout(a,Duration::from_secs(2)).ok()).ok_or_else(||io::Error::new(io::ErrorKind::ConnectionRefused,"SOCKS proxy unreachable"))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let (host,port)=target.rsplit_once(':').ok_or_else(||io::Error::new(io::ErrorKind::InvalidInput,"target requires host:port"))?;
        let port:u16=port.parse().map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,"invalid target port"))?;let host=host.trim_start_matches('[').trim_end_matches(']');
        let greeting=if self.credentials.is_some(){vec![5,1,2]}else{vec![5,1,0]};stream.write_all(&greeting)?;
        let mut selected=[0;2];stream.read_exact(&mut selected)?;
        if selected[0]!=5||selected[1]!=greeting[2]{return Err(io::Error::new(io::ErrorKind::PermissionDenied,"SOCKS authentication method rejected"));}
        if let Some((user,password))=&self.credentials {
            let u=u8::try_from(user.len()).ok().filter(|n|*n>0).ok_or_else(||io::Error::new(io::ErrorKind::InvalidInput,"SOCKS username must be 1..255 bytes"))?;
            let p=u8::try_from(password.len()).ok().filter(|n|*n>0).ok_or_else(||io::Error::new(io::ErrorKind::InvalidInput,"SOCKS password must be 1..255 bytes"))?;
            let mut auth=vec![1,u];auth.extend_from_slice(user.as_bytes());auth.push(p);auth.extend_from_slice(password.as_bytes());stream.write_all(&auth)?;
            stream.read_exact(&mut selected)?;if selected!=[1,0]{return Err(io::Error::new(io::ErrorKind::PermissionDenied,"SOCKS credentials rejected"));}
        }
        let mut request=vec![5,1,0];
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip))=>{request.push(1);request.extend_from_slice(&ip.octets());},
            Ok(IpAddr::V6(ip))=>{request.push(4);request.extend_from_slice(&ip.octets());},
            Err(_)=>{let n=u8::try_from(host.len()).ok().filter(|n|*n>0).ok_or_else(||io::Error::new(io::ErrorKind::InvalidInput,"SOCKS hostname must be 1..255 bytes"))?;request.extend_from_slice(&[3,n]);request.extend_from_slice(host.as_bytes());},
        }
        request.extend_from_slice(&port.to_be_bytes());stream.write_all(&request)?;
        let mut reply=[0;4];stream.read_exact(&mut reply)?;
        if reply[0]!=5||reply[1]!=0||reply[2]!=0{return Err(io::Error::new(io::ErrorKind::ConnectionRefused,format!("SOCKS CONNECT failed ({})",reply[1])));}
        let n=match reply[3]{1=>4,4=>16,3=>{let mut n=[0];stream.read_exact(&mut n)?;n[0] as usize},_=>return Err(io::Error::new(io::ErrorKind::InvalidData,"invalid SOCKS address type"))};
        let mut bound=vec![0;n+2];stream.read_exact(&mut bound)?;stream.set_read_timeout(None)?;stream.set_write_timeout(None)?;Ok(stream)
    }
}
