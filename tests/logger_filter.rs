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
fn disabled_mode_keeps_bounded_history_without_suppressing_packets() {
    let now = Instant::now();
    let packet = message(7, Direction::ToClient);
    let mut filter = LoggerFilter::default();
    for _ in 0..100 {
        assert!(!filter.suppress(&packet, now));
    }
    filter.set_mode(AntiSpam::Ultra);
    assert!(filter.suppress(&packet, now));
    filter.set_mode(AntiSpam::None);
    filter.set_mode(AntiSpam::Ultra);
    assert!(filter.suppress(&packet, now));
    assert!(!filter.suppress(&packet, now + Duration::from_secs(6)));
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

#[test]
fn explicit_reset_discards_frequencies_without_disabling_filter() {
    let now = Instant::now();
    let packet = message(42, Direction::ToClient);
    let mut filter = LoggerFilter::default();
    filter.set_mode(AntiSpam::Ultra);
    assert!(!filter.suppress(&packet, now));
    assert!(filter.suppress(&packet, now));
    filter.reset();
    assert!(!filter.suppress(&packet, now + Duration::from_millis(10)));
    assert!(filter.suppress(&packet, now + Duration::from_millis(20)));
}

#[test]
fn history_remains_active_over_a_quick_reconnect_until_window_expires() {
    let now = Instant::now();
    let packet = message(42, Direction::ToClient);
    let mut filter = LoggerFilter::default();
    filter.set_mode(AntiSpam::Ultra);
    assert!(!filter.suppress(&packet, now));
    assert!(filter.suppress(&packet, now + Duration::from_millis(10)));
    assert!(filter.suppress(&packet, now + Duration::from_millis(100)));
    assert!(!filter.suppress(&packet, now + Duration::from_secs(6)));
}

#[test]
fn switching_active_levels_preserves_recent_incoming_history() {
    let now = Instant::now();
    let packet = message(42, Direction::ToClient);
    let mut filter = LoggerFilter::default();
    filter.set_mode(AntiSpam::Low);
    for _ in 0..4 {
        assert!(!filter.suppress(&packet, now));
    }
    filter.set_mode(AntiSpam::High);
    assert!(filter.suppress(&packet, now + Duration::from_millis(1)));
    filter.set_mode(AntiSpam::Low);
    assert!(!filter.suppress(&packet, now + Duration::from_millis(2)));
    filter.set_mode(AntiSpam::None);
    filter.set_mode(AntiSpam::Ultra);
    assert!(filter.suppress(&packet, now + Duration::from_millis(3)));
}

#[test]
fn active_level_switches_match_upstream_queue_for_bounded_samples() {
    use std::collections::VecDeque;
    let now = Instant::now();
    let packet = message(42, Direction::ToClient);
    let mut rust = LoggerFilter::default();
    let mut java_history = VecDeque::<u64>::new();
    let samples: [(AntiSpam, u64); 12] = [
        (AntiSpam::None, 0),
        (AntiSpam::None, 0),
        (AntiSpam::Low, 0),
        (AntiSpam::Low, 10),
        (AntiSpam::Low, 20),
        (AntiSpam::High, 30),
        (AntiSpam::High, 40),
        (AntiSpam::Low, 50),
        (AntiSpam::Ultra, 60),
        (AntiSpam::Medium, 5001),
        (AntiSpam::Medium, 5020),
        (AntiSpam::Medium, 7000),
    ];
    for (mode, millis) in samples {
        let threshold = match mode {
            AntiSpam::Low => 15,
            AntiSpam::Medium => 9,
            AntiSpam::High => 4,
            AntiSpam::Ultra => 2,
            AntiSpam::None => 100_000_000,
        };
        while java_history
            .front()
            .is_some_and(|time| millis.saturating_sub(*time) > 5000)
        {
            java_history.pop_front();
        }
        if java_history.len() == threshold {
            java_history.pop_front();
        }
        java_history.push_back(millis);
        let expected = java_history.len() >= threshold;
        rust.set_mode(mode);
        assert_eq!(
            rust.suppress(&packet, now + Duration::from_millis(millis)),
            expected,
            "{mode:?} at {millis} ms"
        );
    }
}
