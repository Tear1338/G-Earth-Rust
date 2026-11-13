//! G-Earth beta-29 `.sched` files (tab-separated, UTF-8 on Java 21).
use crate::{
    expression,
    packet::{Direction, Packet, PacketFormat},
    packet_info::PacketInfoManager,
    scheduler::{Job, ScheduleSpec, MAX_INTERVAL_MS},
    settings::ScheduleTemplate,
};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

pub const MAX_SCHEDULE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ITEMS: usize = 10_000;

/// Compile active schedules atomically, optionally deferring unknown named IDs.
/// A deferred placeholder is paired with the original source and must be resolved
/// with `Job::resolve_packet` before dispatch.
pub fn compile_active(
    templates: &[ScheduleTemplate],
    info: &PacketInfoManager,
    format_for: impl Fn(Direction) -> PacketFormat,
    allow_deferred_names: bool,
) -> crate::packet::Result<Vec<(ScheduleSpec, bool, bool)>> {
    templates
        .iter()
        .map(|template| {
            let format = format_for(template.direction);
            let (packet, deferred) = match expression::parse_with_format(
                &template.expression,
                format,
                Some((template.direction, info)),
            ) {
                Ok(packet) => (packet, false),
                Err(_) if allow_deferred_names => {
                    // A file may be loaded before its eventual client is known.
                    // Accept syntax valid for either supported wire family; the
                    // actual family is checked again before dispatch.
                    if expression::validate_with_deferred_names(
                        &template.expression,
                        format,
                        template.direction,
                        info,
                    )
                    .is_err()
                    {
                        let alternate = match format {
                            PacketFormat::EvaWire => match template.direction {
                                Direction::ToClient => PacketFormat::WedgieIncoming,
                                Direction::ToServer => PacketFormat::WedgieOutgoing,
                            },
                            _ => PacketFormat::EvaWire,
                        };
                        expression::validate_with_deferred_names(
                            &template.expression,
                            alternate,
                            template.direction,
                            info,
                        )?;
                    }
                    (Packet::new_with_format(format, 0)?, true)
                }
                Err(error) => return Err(error),
            };
            Ok((
                ScheduleSpec {
                    packet,
                    source_expression: Some(template.expression.clone()),
                    direction: template.direction,
                    interval_ms: template.interval_ms,
                    offset_ms: template.offset_ms,
                    repeat: (template.repeat != 0).then_some(template.repeat),
                },
                template.paused,
                deferred,
            ))
        })
        .collect()
}

/// Write beside the destination and replace it only after a complete successful write.
pub fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    if text.len() > MAX_SCHEDULE_FILE_BYTES {
        return Err(io::Error::other("schedule file exceeds 2 MiB"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
    let name = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let temporary = parent.join(format!(".gearth-schedule-{name}.tmp"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| {
                io::Error::new(e.kind(), format!("creating temporary schedule file: {e}"))
            })?;
        file.write_all(text.as_bytes()).map_err(|e| {
            io::Error::new(e.kind(), format!("writing temporary schedule file: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            io::Error::new(e.kind(), format!("flushing temporary schedule file: {e}"))
        })?;
        drop(file);
        std::fs::rename(&temporary, path)
            .map_err(|e| io::Error::new(e.kind(), format!("replacing schedule file: {e}")))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Serialize running jobs in the original format without changing their behavior.
pub fn format_active(jobs: &[Job]) -> io::Result<String> {
    if jobs.len() > MAX_ITEMS {
        return Err(io::Error::other("too many schedule entries"));
    }
    let mut templates = Vec::with_capacity(jobs.len());
    let mut expression_bytes = 0usize;
    for (index, job) in jobs.iter().enumerate() {
        let interval_ms = u64::try_from(job.interval.as_millis())
            .map_err(|_| io::Error::other("schedule interval is too large"))?;
        if job.interval != std::time::Duration::from_millis(interval_ms) {
            return Err(io::Error::other(format!(
                "active schedule {} has a sub-millisecond interval",
                index + 1
            )));
        }
        if job.remaining.is_some() {
            return Err(io::Error::other(format!(
                "active schedule {} must repeat until cancelled for .sched export",
                index + 1
            )));
        }
        if job.alignment_offset_ms.is_none() {
            return Err(io::Error::other(format!(
                "active schedule {} must use a clock-aligned interval for .sched export",
                index + 1
            )));
        }
        if job.packet.bytes().len() > MAX_SCHEDULE_FILE_BYTES {
            return Err(io::Error::other("schedule packet is too large"));
        }
        let packet_expression = job
            .source_expression
            .clone()
            .unwrap_or_else(|| expression::wire_display(job.packet.bytes()));
        expression_bytes = expression_bytes
            .checked_add(packet_expression.len())
            .filter(|length| *length <= MAX_SCHEDULE_FILE_BYTES)
            .ok_or_else(|| io::Error::other("schedule file exceeds 2 MiB"))?;
        templates.push(ScheduleTemplate {
            expression: packet_expression,
            direction: job.direction,
            interval_ms,
            offset_ms: job.alignment_offset_ms,
            paused: job.paused,
            repeat: 0,
        });
    }
    format(&templates)
}

/// Parse the whole file before replacing any existing templates.
pub fn parse(input: &str) -> io::Result<Vec<ScheduleTemplate>> {
    if input.len() > MAX_SCHEDULE_FILE_BYTES {
        return Err(io::Error::other("schedule file exceeds 2 MiB"));
    }
    let mut templates = Vec::new();
    for (line_number, line) in input.lines().enumerate() {
        if templates.len() >= MAX_ITEMS {
            return Err(io::Error::other("too many schedule entries"));
        }
        let parse_line = || -> io::Result<ScheduleTemplate> {
            let fields: Vec<_> = line.splitn(6, '\t').collect();
            if fields.len() != 5 || fields[4].is_empty() {
                return Err(io::Error::other("expected five fields and a packet"));
            }
            fields[0]
                .parse::<i32>()
                .map_err(|_| io::Error::other("invalid index"))?;
            let paused = match fields[1] {
                "true" => true,
                "false" => false,
                _ => return Err(io::Error::other("invalid paused flag")),
            };
            let (delay, offset) = fields[2].split_once('+').unwrap_or((fields[2], "0"));
            let interval_ms = delay
                .parse::<u64>()
                .map_err(|_| io::Error::other("invalid interval"))?;
            let offset_ms = offset
                .parse::<u64>()
                .map_err(|_| io::Error::other("invalid offset"))?;
            if interval_ms == 0 || interval_ms > MAX_INTERVAL_MS || offset_ms > interval_ms {
                return Err(io::Error::other(
                    "offset must not exceed the interval, which must be 1 to 2147483647 ms",
                ));
            }
            let direction = Direction::parse(fields[3]).map_err(io::Error::other)?;
            Ok(ScheduleTemplate {
                expression: fields[4].to_owned(),
                direction,
                interval_ms,
                offset_ms: Some(offset_ms),
                paused,
                repeat: 0,
            })
        };
        templates.push(
            parse_line()
                .map_err(|error| io::Error::other(format!("line {}: {error}", line_number + 1)))?,
        );
    }
    Ok(templates)
}

/// Export only templates whose timing and repetition can be represented without loss.
pub fn format(templates: &[ScheduleTemplate]) -> io::Result<String> {
    if templates.len() > MAX_ITEMS {
        return Err(io::Error::other("too many schedule entries"));
    }
    let mut output = String::new();
    for (index, template) in templates.iter().enumerate() {
        let offset = template.offset_ms.ok_or_else(|| {
            io::Error::other(format!(
                "template {} must use a clock-aligned interval for .sched export",
                index + 1
            ))
        })?;
        if template.repeat != 0 {
            return Err(io::Error::other(format!(
                "template {} must repeat until cancelled for .sched export",
                index + 1
            )));
        }
        if template.interval_ms == 0
            || template.interval_ms > MAX_INTERVAL_MS
            || offset > template.interval_ms
            || template.expression.is_empty()
            || template.expression.contains(['\t', '\n', '\r'])
        {
            return Err(io::Error::other(format!(
                "template {} cannot be represented in .sched format",
                index + 1
            )));
        }
        if index > 0 {
            output.push('\n');
        }
        use std::fmt::Write;
        write!(
            output,
            "{}\t{}\t{}+{}\t{}\t{}",
            index,
            template.paused,
            template.interval_ms,
            offset,
            template.direction.name(),
            template.expression
        )
        .unwrap();
        if output.len() > MAX_SCHEDULE_FILE_BYTES {
            return Err(io::Error::other("schedule file exceeds 2 MiB"));
        }
    }
    Ok(output)
}
