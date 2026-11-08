//! Incoming packet anti-spam behavior from the beta-29 packet logger.
use crate::packet::{Direction, Message};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AntiSpam {
    #[default]
    None,
    Low,
    Medium,
    High,
    Ultra,
}

impl AntiSpam {
    pub fn translation_key(self) -> &'static str {
        match self {
            Self::None => "ext.logger.menu.packets.antispam.none",
            Self::Low => "ext.logger.menu.packets.antispam.low",
            Self::Medium => "ext.logger.menu.packets.antispam.med",
            Self::High => "ext.logger.menu.packets.antispam.high",
            Self::Ultra => "ext.logger.menu.packets.antispam.ultra",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Ultra => "Ultra",
        }
    }
    pub fn from_setting(value: &str) -> Self {
        match value {
            "Low" => Self::Low,
            "Medium" => Self::Medium,
            "High" => Self::High,
            "Ultra" => Self::Ultra,
            _ => Self::None,
        }
    }
    fn threshold(self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Low => Some(15),
            Self::Medium => Some(9),
            Self::High => Some(4),
            Self::Ultra => Some(2),
        }
    }
}

#[derive(Default)]
pub struct LoggerFilter {
    mode: AntiSpam,
    timestamps: HashMap<u16, VecDeque<Instant>>,
    last_cleanup: Option<Instant>,
}

impl LoggerFilter {
    /// Clear the accumulated packet frequencies without changing the selected mode.
    pub fn reset(&mut self) {
        self.timestamps.clear();
        self.last_cleanup = None;
    }

    pub fn set_mode(&mut self, mode: AntiSpam) {
        if self.mode != mode {
            // Retain recent history when changing between active levels, as Java does.
            // Disabled filtering deliberately retains no history to bound memory.
            if self.mode == AntiSpam::None || mode == AntiSpam::None {
                self.reset();
            }
            self.mode = mode;
        }
    }

    /// Return true when this message should be omitted from the display.
    pub fn suppress(&mut self, message: &Message, now: Instant) -> bool {
        let Some(threshold) = self.mode.threshold() else {
            return false;
        };
        if message.direction != Direction::ToClient || message.blocked || message.packet.edited {
            return false;
        }
        let window = Duration::from_secs(5);
        if self
            .last_cleanup
            .is_none_or(|last| now.saturating_duration_since(last) >= window)
        {
            self.timestamps.retain(|_, values| {
                values
                    .back()
                    .is_some_and(|last| now.saturating_duration_since(*last) <= window)
            });
            self.last_cleanup = Some(now);
        }
        let timestamps = self.timestamps.entry(message.packet.header()).or_default();
        while timestamps
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) > window)
        {
            timestamps.pop_front();
        }
        if timestamps.len() == threshold || timestamps.len() >= 15 {
            timestamps.pop_front();
        }
        timestamps.push_back(now);
        timestamps.len() >= threshold
    }
}
