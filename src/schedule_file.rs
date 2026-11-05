//! G-Earth beta-29 `.sched` files (tab-separated, UTF-8 on Java 21).
use crate::{packet::Direction, settings::ScheduleTemplate};
use std::io;

pub const MAX_SCHEDULE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ITEMS: usize = 10_000;

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
            if interval_ms == 0 || interval_ms > 86_400_000 || offset_ms >= interval_ms {
                return Err(io::Error::other(
                    "offset must be smaller than the interval, which must be 1 ms to 1 day",
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
            || template.interval_ms > 86_400_000
            || offset >= template.interval_ms
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
