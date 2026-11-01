use gearth_rust::{gpython::{self,PythonConsole},extension_host::{ExtensionHost,ConnectionDetails},packet::{Direction,Packet,Message},packet_info::{PacketInfo,PacketInfoManager}};
use std::{path::Path,process::Command,time::{Duration,Instant}};
#[test] #[ignore="requires the pinned G-Python package and Jupyter kernel; executed in gpython CI"]
fn original_gpython_kernel_authenticates_and_injects_through_the_rust_host(){
    let python=Path::new("python");let report=gpython::probe(python).unwrap();assert!(report.missing().is_empty(),"{:?}",report.missing());
    let (host,_)=ExtensionHost::start("127.0.0.1:0".parse().unwrap(),Vec::new()).unwrap();host.start_connection(ConnectionDetails {host:"fixture.invalid".into(),port:1234,version:"TEST".into(),identifier:"fixture".into(),client_type:"FLASH".into(),packets:PacketInfoManager::new("TEST",vec![(77,"TestOutgoing",Direction::ToServer),(78,"TestIncoming",Direction::ToClient),(91,"TestInjection",Direction::ToServer)].into_iter().map(|(header,name,direction)|PacketInfo {header,name:Some(name.into()),hash:None,structure:Some("i".into()),direction,source:"fixture".into()}).collect())}).unwrap();
    let mut console=PythonConsole::launch_fixture(python,&host,include_str!("gpython_kernel_fixture.py")).unwrap();
    let deadline=Instant::now()+Duration::from_secs(50);let mut injected_server=false;let mut injected_client=false;let mut finished=false;let mut ready=false;
    loop {
        for line in console.poll(){assert!(!line.starts_with("GEARTH_PYTHON_ERROR"),"{line}");}ready|=console.ready;
        for (direction,mut packet) in host.take_injections(){
            match packet.header() {
                91=>{
                    assert!(!injected_server);assert_eq!(direction,Direction::ToServer);assert_eq!(packet.read_i32().unwrap(),17);injected_server=true;
                    for (header,value,direction) in [(77,5,Direction::ToServer),(77,13,Direction::ToServer),(78,7,Direction::ToClient)] {
                        let mut packet=Packet::new(header);packet.put_i32(value).unwrap();let mut message=Message {packet,direction,index:value,blocked:false};
                        host.intercept(&mut message).unwrap();assert_eq!(message.blocked,value==13);
                        if !message.blocked {assert_eq!(message.packet.read_i32().unwrap(),value+100);}
                    }
                },
                92=>{assert_eq!(direction,Direction::ToClient);assert_eq!(packet.read_i32().unwrap(),18);injected_client=true;},
                93=>{assert_eq!(packet.read_i32().unwrap(),3);finished=true;},
                header=>panic!("Unexpected Python injection {header}")
            }
        }
        if let Some(status)=console.exited().unwrap(){assert!(status.success(),"Python kernel fixture failed: {status}");break;}
        assert!(Instant::now()<deadline,"Python kernel fixture timed out");std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ready&&injected_server&&injected_client&&finished);console.stop();host.stop();
}

#[test] #[ignore="requires Python/Jupyter/psutil; executed in gpython CI on Linux and Windows"]
fn stopping_a_console_terminates_its_kernel() {
    let python=Path::new("python");
    let (host,events)=ExtensionHost::start("127.0.0.1:0".parse().unwrap(),Vec::new()).unwrap();
    let mut console=PythonConsole::launch_fixture(python,&host,"import os, time\nwrite_to_console('kernel-pid=' + str(os.getpid()))\ntime.sleep(60)\n").unwrap();
    let deadline=Instant::now()+Duration::from_secs(40);
    // The real kernel reports its PID through authenticated extension IPC.
    let pid=loop {
        for line in console.poll(){assert!(!line.starts_with("GEARTH_PYTHON_ERROR"),"{line}");}
        let found=events.try_iter().find_map(|event|match event {
            gearth_rust::extension_host::HostEvent::Console {text,..}=>text.split_once("kernel-pid=").and_then(|(_,pid)|pid.parse::<u32>().ok()),
            _=>None
        });
        if let Some(pid)=found{break pid;}
        assert!(Instant::now()<deadline,"kernel did not start");std::thread::sleep(Duration::from_millis(10));
    };
    console.stop();host.stop();
    let check="import sys,time,psutil\npid=int(sys.argv[1])\nend=time.monotonic()+12\nwhile time.monotonic()<end:\n try:\n  p=psutil.Process(pid)\n  if not p.is_running() or p.status()==psutil.STATUS_ZOMBIE: break\n except psutil.NoSuchProcess: break\n time.sleep(.1)\nelse: raise SystemExit('kernel survived console shutdown')\n";
    assert!(Command::new(python).args(["-c",check,&pid.to_string()]).status().unwrap().success());
}
