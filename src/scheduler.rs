use crate::packet::{error, Direction, Packet, Result};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The scheduler editor keeps its draft separate from the injection editor.
pub struct ScheduleDraft {
    pub expression: String,
    pub direction: Direction,
}
impl Default for ScheduleDraft {
    fn default() -> Self {
        Self {
            expression: "{in:Chat}{i:-1}{s:\"Frank loves G-Earth\"}{i:0}{i:33}{i:0}{i:0}".into(),
            direction: Direction::ToClient,
        }
    }
}
pub struct Job {
    pub id: u64,
    pub packet: Packet,
    pub direction: Direction,
    pub interval: Duration,
    pub next: Instant,
    pub remaining: Option<u32>,
    pub paused: bool,
    pub alignment_offset_ms: Option<u64>,
    clock_reference: Option<(Instant, SystemTime)>,
}

pub struct ScheduleSpec {
    pub packet: Packet,
    pub direction: Direction,
    pub interval_ms: u64,
    pub offset_ms: Option<u64>,
    pub repeat: Option<u32>,
}

fn deadline_from_wall(
    now: Instant,
    wall: SystemTime,
    interval: Duration,
    offset_ms: u64,
    strictly_future: bool,
) -> Option<Instant> {
    let current = wall.duration_since(UNIX_EPOCH).ok()?.as_nanos();
    let period = interval.as_nanos();
    if period == 0 || u128::from(offset_ms) * 1_000_000 >= period {
        return None;
    }
    let offset = u128::from(offset_ms) * 1_000_000;
    let mut wait = (offset + period - current % period) % period;
    if strictly_future && wait == 0 {
        wait = period;
    }
    let delay = Duration::new((wait / 1_000_000_000) as u64, (wait % 1_000_000_000) as u32);
    now.checked_add(delay)
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
    next_id: u64,
}
impl Scheduler {
    /// Time until the next unpaused job, with a minimum retry delay for due jobs.
    /// This is a UI wakeup hint; actual dispatch still depends on the runtime.
    pub fn next_wake_in(&self, now: Instant) -> Option<Duration> {
        self.jobs
            .iter()
            .filter(|job| !job.paused && job.remaining != Some(0))
            .map(|job| {
                job.next
                    .saturating_duration_since(now)
                    .max(Duration::from_millis(1))
            })
            .min()
    }
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
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or_else(|| error("schedule identifier exhausted"))?;
        self.jobs.push(Job {
            id,
            packet,
            direction,
            interval,
            next: now,
            remaining: repeat,
            paused: false,
            alignment_offset_ms: None,
            clock_reference: None,
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
        let next = deadline_from_wall(now, wall, interval, offset_ms, false)
            .ok_or_else(|| error("invalid system clock or schedule deadline"))?;
        self.add(packet, direction, interval, repeat, now)?;
        let job = self.jobs.last_mut().expect("newly added schedule");
        job.next = next;
        job.alignment_offset_ms = Some(offset_ms);
        job.clock_reference = Some((now, wall));
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
    /// Validate the entire batch before adding any jobs to the running scheduler.
    pub fn add_batch_configured(
        &mut self,
        specs: Vec<(ScheduleSpec, bool)>,
        clock: (Instant, SystemTime),
    ) -> Result<()> {
        let mut candidate = Self {
            jobs: Vec::new(),
            next_id: self.next_id,
        };
        for (spec, paused) in specs {
            candidate.add_configured(
                spec.packet,
                spec.direction,
                spec.interval_ms,
                spec.offset_ms,
                spec.repeat,
                clock,
            )?;
            candidate
                .jobs
                .last_mut()
                .expect("newly added schedule")
                .paused = paused;
        }
        self.next_id = candidate.next_id;
        self.jobs.extend(candidate.jobs);
        Ok(())
    }
    /// Replace all jobs only after the complete batch has been validated.
    pub fn replace_batch_configured(
        &mut self,
        specs: Vec<(ScheduleSpec, bool)>,
        clock: (Instant, SystemTime),
    ) -> Result<()> {
        let mut candidate = Self {
            jobs: Vec::new(),
            next_id: self.next_id,
        };
        candidate.add_batch_configured(specs, clock)?;
        *self = candidate;
        Ok(())
    }
    /// Atomically replace one active job while preserving its identity and pause state.
    pub fn update_configured(
        &mut self,
        id: u64,
        spec: ScheduleSpec,
        clock: (Instant, SystemTime),
    ) -> Result<()> {
        let index = self
            .jobs
            .iter()
            .position(|job| job.id == id)
            .ok_or_else(|| error("schedule is no longer active"))?;
        let paused = self.jobs[index].paused;
        let mut candidate = Self::default();
        candidate.add_configured(
            spec.packet,
            spec.direction,
            spec.interval_ms,
            spec.offset_ms,
            spec.repeat,
            clock,
        )?;
        let mut job = candidate.jobs.pop().expect("validated schedule");
        if job.alignment_offset_ms.is_none() {
            job.next = clock
                .0
                .checked_add(job.interval)
                .ok_or_else(|| error("schedule deadline overflow"))?;
        }
        job.id = id;
        job.paused = paused;
        self.jobs[index] = job;
        Ok(())
    }
    fn correct_wall_clock(&mut self, now: Instant, wall: SystemTime) {
        for job in &mut self.jobs {
            let (Some(offset), Some((reference, reference_wall))) =
                (job.alignment_offset_ms, job.clock_reference)
            else {
                continue;
            };
            let Some(elapsed) = now.checked_duration_since(reference) else {
                continue;
            };
            let Some(expected) = reference_wall.checked_add(elapsed) else {
                continue;
            };
            let drift = wall
                .duration_since(expected)
                .or_else(|_| expected.duration_since(wall));
            let tolerance = Duration::from_millis(20).min(job.interval / 2);
            if drift.is_ok_and(|drift| drift > tolerance) {
                if let Some(next) = deadline_from_wall(now, wall, job.interval, offset, true) {
                    job.next = next;
                    job.clock_reference = Some((now, wall));
                }
            }
        }
    }
    /// Correct aligned jobs after a system clock adjustment. Skipped deadlines
    /// are not replayed, and relative jobs are unaffected.
    pub fn tick_with_wall_clock(
        &mut self,
        now: Instant,
        wall: SystemTime,
    ) -> Vec<(Direction, Packet)> {
        self.correct_wall_clock(now, wall);
        self.tick(now)
    }

    /// Commit each scheduled send only after the caller accepts it for delivery.
    /// A failed enqueue leaves that job and later jobs due for a subsequent attempt.
    pub fn dispatch_with_wall_clock<E>(
        &mut self,
        now: Instant,
        wall: SystemTime,
        send: impl FnMut(Direction, &Packet) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        self.correct_wall_clock(now, wall);
        self.dispatch_due(now, send)
    }
    /// At most one emission per job per tick; missed deadlines never create bursts.
    pub fn tick(&mut self, now: Instant) -> Vec<(Direction, Packet)> {
        let mut due = Vec::new();
        let result = self.dispatch_due(now, |direction, packet| {
            due.push((direction, packet.clone()));
            Ok::<(), std::convert::Infallible>(())
        });
        match result {
            Ok(()) => {}
            Err(never) => match never {},
        }
        due
    }
    fn dispatch_due<E>(
        &mut self,
        now: Instant,
        mut send: impl FnMut(Direction, &Packet) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        let mut failure = None;
        for job in &mut self.jobs {
            if !job.paused && job.next <= now && job.remaining != Some(0) {
                if let Err(error) = send(job.direction, &job.packet) {
                    failure = Some(error);
                    break;
                }
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
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
