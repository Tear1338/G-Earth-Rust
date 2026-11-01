use gearth_rust::extension_host::{ExtensionHost, HostEvent};
use std::{
    path::Path,
    process::Child,
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
#[ignore = "requires the original beta-29 Java API and compiled fixture"]
fn store_command_expands_bound_credentials_and_authenticates_the_original_java_extension() {
    let classpath =
        std::env::var("GEARTH_EXTENSION_CLASSPATH").expect("Java fixture classpath required");
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let words = [
        "java",
        "-cp",
        &classpath,
        "JavaExtensionFixture",
        "-p",
        "{port}",
        "-f",
        "{filename}",
        "-c",
        "{cookie}",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let _process = Process(
        host.launch_command(
            &words,
            &std::env::current_dir().unwrap(),
            "extension-fixture",
            "Store fixture",
            Path::new("java"),
        )
        .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !matches!(
        events.recv_timeout(Duration::from_millis(100)),
        Ok(HostEvent::Connected { .. })
    ) {
        assert!(
            Instant::now() < deadline,
            "store-launched Java extension did not authenticate"
        );
    }
    host.stop();
}
