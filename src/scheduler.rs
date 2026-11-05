use crate::packet::{error, Direction, Packet, Result};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
pub struct Job {
    pub packet: Packet,
    pub direction: Direction,
    pub interval: Duration,
    pub next: Instant,
    pub remaining: Option<u32>,
    pub paused: bool,
    pub alignment_offset_ms: Option<u64>,
}

fn next_aligned(deadline: Instant, interval: Duration, now: Instant) -> Option<Instant> {
    if deadline > now {
        return Some(deadline);
    }
    let period = interval.as_nanos();
    let remaining = period - now.duration_since(deadline).as_nanos() % period;
    let delay = Duration::new(
        (remaining / 1_000_000_000) as u64,
        (remaining % 1_000_000_000) as u32,
    );
    now.checked_add(delay)
}
#[derive(Default)]
pub struct Scheduler {
    pub jobs: Vec<Job>,
}
impl Scheduler {
    /// Resuming skips missed sends and preserves the phase of aligned jobs.
    pub fn set_paused(&mut self, index: usize, paused: bool, now: Instant) -> Result<()> {
        let job = self
            .jobs
            .get_mut(index)
            .ok_or_else(|| error("unknown schedule"))?;
        if job.paused && !paused {
            job.next = if job.alignment_offset_ms.is_some() {
                next_aligned(job.next, job.interval, now)
            } else {
                now.checked_add(job.interval)
            }
            .ok_or_else(|| error("schedule deadline overflow"))?;
        }
        job.paused = paused;
        Ok(())
    }
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
            paused: false,
            alignment_offset_ms: None,
        });
        Ok(())
    }
    /// Align a millisecond interval to an offset within each Unix-clock period.
    pub fn add_aligned(
        &mut self,
        packet: Packet,
        direction: Direction,
        interval_ms: u64,
        offset_ms: u64,
        repeat: Option<u32>,
        clock: (Instant, SystemTime),
    ) -> Result<()> {
        let (now, wall) = clock;
        if interval_ms == 0 || interval_ms > 86_400_000 || offset_ms >= interval_ms {
            return Err(error("invalid schedule interval/offset"));
        }
        let interval = Duration::from_millis(interval_ms);
        let current = wall
            .duration_since(UNIX_EPOCH)
            .map_err(|_| error("system clock precedes Unix epoch"))?
            .as_nanos();
        let period = interval.as_nanos();
        let offset = u128::from(offset_ms) * 1_000_000;
        let wait = (offset + period - current % period) % period;
        let delay = Duration::new((wait / 1_000_000_000) as u64, (wait % 1_000_000_000) as u32);
        let next = now
            .checked_add(delay)
            .ok_or_else(|| error("schedule deadline overflow"))?;
        self.add(packet, direction, interval, repeat, now)?;
        let job = self.jobs.last_mut().expect("newly added schedule");
        job.next = next;
        job.alignment_offset_ms = Some(offset_ms);
        Ok(())
    }
    pub fn add_configured(
        &mut self,
        packet: Packet,
        direction: Direction,
        interval_ms: u64,
        offset_ms: Option<u64>,
        repeat: Option<u32>,
        clock: (Instant, SystemTime),
    ) -> Result<()> {
        match offset_ms {
            Some(offset) => self.add_aligned(packet, direction, interval_ms, offset, repeat, clock),
            None => self.add(
                packet,
                direction,
                Duration::from_millis(interval_ms),
                repeat,
                clock.0,
            ),
        }
    }
    /// At most one emission per job per tick; missed deadlines never create bursts.
    pub fn tick(&mut self, now: Instant) -> Vec<(Direction, Packet)> {
        let mut due = Vec::new();
        for job in &mut self.jobs {
            if !job.paused && job.next <= now && job.remaining != Some(0) {
                due.push((job.direction, job.packet.clone()));
                if let Some(count) = &mut job.remaining {
                    *count -= 1;
                }
                let next = if job.alignment_offset_ms.is_some() {
                    next_aligned(job.next, job.interval, now)
                } else {
                    now.checked_add(job.interval)
                };
                if let Some(next) = next {
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
