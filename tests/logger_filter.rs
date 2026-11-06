use gearth_rust::{
    logger_filter::{AntiSpam, LoggerFilter},
    packet::{Direction, Message, Packet},
};
use std::time::{Duration, Instant};

fn message(header: u16, direction: Direction) -> Message {
    Message {
        packet: Packet::new(header),
        direction,
        index: 0,
        blocked: false,
    }
}

#[test]
fn original_thresholds_and_five_second_window_apply_per_header() {
    let now = Instant::now();
    for (mode, threshold) in [
        (AntiSpam::Low, 15),
        (AntiSpam::Medium, 9),
        (AntiSpam::High, 4),
        (AntiSpam::Ultra, 2),
    ] {
        let mut filter = LoggerFilter::default();
        filter.set_mode(mode);
        let packet = message(42, Direction::ToClient);
        for i in 1..=threshold {
            assert_eq!(filter.suppress(&packet, now), i == threshold);
        }
        assert!(!filter.suppress(&message(43, Direction::ToClient), now));
        assert!(filter.suppress(&packet, now + Duration::from_secs(5)));
        assert!(!filter.suppress(&packet, now + Duration::from_secs(11)));
    }
}

#[test]
fn outgoing_blocked_and_replaced_packets_do_not_enter_the_filter() {
    let now = Instant::now();
    let mut filter = LoggerFilter::default();
    filter.set_mode(AntiSpam::Ultra);
    let mut packet = message(42, Direction::ToClient);
    packet.blocked = true;
    assert!(!filter.suppress(&packet, now));
    packet.blocked = false;
    packet.packet.edited = true;
    assert!(!filter.suppress(&packet, now));
    packet.packet.edited = false;
    packet.direction = Direction::ToServer;
    assert!(!filter.suppress(&packet, now));
    packet.direction = Direction::ToClient;
    assert!(!filter.suppress(&packet, now));
    assert!(filter.suppress(&packet, now));
}

#[test]
fn mode_changes_clear_old_history_and_none_never_suppresses() {
    let now = Instant::now();
    let packet = message(7, Direction::ToClient);
    let mut filter = LoggerFilter::default();
    for _ in 0..100 {
        assert!(!filter.suppress(&packet, now));
    }
    filter.set_mode(AntiSpam::Ultra);
    assert!(!filter.suppress(&packet, now));
    assert!(filter.suppress(&packet, now));
    filter.set_mode(AntiSpam::None);
    filter.set_mode(AntiSpam::Ultra);
    assert!(!filter.suppress(&packet, now));
    for mode in [
        AntiSpam::None,
        AntiSpam::Low,
        AntiSpam::Medium,
        AntiSpam::High,
        AntiSpam::Ultra,
    ] {
        assert_eq!(AntiSpam::from_setting(mode.name()), mode);
    }
}
