use crate::packet::{error, Direction, Packet, Result};
use std::time::{Duration, Instant};
pub struct Job {
    pub packet: Packet,
    pub direction: Direction,
    pub interval: Duration,
    pub next: Instant,
    pub remaining: Option<u32>,
}
#[derive(Default)]
pub struct Scheduler {
    pub jobs: Vec<Job>,
}
impl Scheduler {
    pub fn add(
        &mut self,
        packet: Packet,
        direction: Direction,
        interval: Duration,
        repeat: Option<u32>,
        now: Instant,
    ) -> Result<()> {
        if interval < Duration::from_millis(1)
            || repeat == Some(0)
            || now.checked_add(interval).is_none()
        {
            return Err(error("invalid schedule interval/repeat"));
        }
        self.jobs.push(Job {
            packet,
            direction,
            interval,
            next: now,
            remaining: repeat,
        });
        Ok(())
    }
    /// At most one emission per job per tick; missed deadlines never create bursts.
    pub fn tick(&mut self, now: Instant) -> Vec<(Direction, Packet)> {
        let mut due = Vec::new();
        for job in &mut self.jobs {
            if job.next <= now && job.remaining != Some(0) {
                due.push((job.direction, job.packet.clone()));
                if let Some(count) = &mut job.remaining {
                    *count -= 1;
                }
                if let Some(next) = now.checked_add(job.interval) {
                    job.next = next;
                } else {
                    job.remaining = Some(0);
                }
            }
        }
        self.jobs.retain(|j| j.remaining != Some(0));
        due
    }
}
