extern crate spotr_sensing;

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::result::Result;
use std::{fs, path::PathBuf};

use spotr_sensing::{ProcessStats, Sensor, SensorOutput, Stat};

#[no_mangle]
pub fn initialize(_: &str) -> *mut dyn Sensor {
    Box::into_raw(Box::new(ProcessSensor::new()))
}

struct ProcessSensor {
    seen_processes: HashSet<(u32, String)>,
}

#[derive(Debug)]
enum ErrorCode {
    LineTooShort(String, usize),
    UnexpectedCharacter(String, usize),
    InvalidInput(String),
    EmptyFile(String),
    MissingMetaData(String),
    MissingFile(String),
}

impl ErrorCode {
    fn unexpected_character(content: &Vec<u8>, position: usize) -> ErrorCode {
        Self::UnexpectedCharacter(Self::content_as_string(content), position)
    }

    fn line_too_short(content: &Vec<u8>, position: usize) -> ErrorCode {
        Self::LineTooShort(Self::content_as_string(content), position)
    }

    fn invalid_input(content: &Vec<u8>) -> ErrorCode {
        Self::InvalidInput(Self::content_as_string(content))
    }

    fn content_as_string(content: &Vec<u8>) -> String {
        content.iter().map(|u| *u as char).collect()
    }
}

impl ProcessSensor {
    fn new() -> Self {
        ProcessSensor {
            seen_processes: HashSet::new(),
        }
    }

    fn read_proc<I>(&mut self, paths: I) -> Vec<SensorOutput>
    where
        I: Iterator<Item = Result<fs::DirEntry, std::io::Error>>,
    {
        let mut processes = Vec::new();
        let mut unseen_processes = self.seen_processes.clone();
        self.seen_processes.clear();
        for entry in paths.filter_map(|entry_result| entry_result.ok()) {
            let filename = &entry.file_name();
            match filename.to_str().unwrap().parse::<u32>() {
                Ok(pid) => {
                    let stat_file = &entry.path().join("stat");
                    let stat = match self.read_stat(stat_file) {
                        Ok(stat) => {
                            let key = (pid, stat.comm.clone());
                            unseen_processes.remove(&key);
                            self.seen_processes.insert(key);
                            ProcessStats::Stat(stat)
                        }
                        Err(code) => {
                            let message = format!("{:?}", code);
                            println!("{}", message);
                            ProcessStats::Error(message)
                        }
                    };
                    processes.push(SensorOutput::Process { pid, stat });
                }
                _ => (),
            }
        }

        for key in unseen_processes {
            self.seen_processes.remove(&key);
            processes.push(SensorOutput::Process {
                pid: key.0,
                stat: ProcessStats::Closed(key.0, key.1),
            });
        }
        processes
    }

    fn read_stat(&self, file_path: &PathBuf) -> Result<Stat, ErrorCode> {
        let mut file = File::open(file_path).map_err(|e| {
            ErrorCode::MissingFile(format!("{}: {}", file_path.to_string_lossy(), e))
        })?;
        let metadata = file.metadata().map_err(|e| {
            ErrorCode::MissingMetaData(format!("{}: {}", file_path.to_string_lossy(), e))
        })?;
        let mut buffer: Vec<u8> = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut buffer).unwrap();
        if buffer.len() > 0 {
            self.parse_stat_content(buffer)
        } else {
            Err(ErrorCode::EmptyFile(format!("{:?}", file_path)))
        }
    }

    fn parse_stat_content(&self, content: Vec<u8>) -> Result<Stat, ErrorCode> {
        let mut position = 0;
        // Skip the pid.
        while position < content.len() && content[position] != '(' as u8 {
            position += 1;
        }
        // Strip the '('
        while position < content.len() && content[position] == '(' as u8 {
            position += 1;
        }
        let mut comm = String::with_capacity(16);
        while position < content.len() && content[position] != ')' as u8 {
            comm.push(content[position] as char);
            position += 1;
        }
        // Skip the ') '
        while position < content.len() && content[position] == ')' as u8 {
            position += 1;
        }
        position += 1;
        if position >= content.len() {
            return Err(ErrorCode::invalid_input(&content));
        }
        let state = content[position] as char;
        position += 2;
        let (ppid, position) = next_u32(&content, position)?;
        let (pgrp, position) = next_u32(&content, position)?;
        let (session, position) = next_u32(&content, position)?;
        let (tty_nr, position) = next_u32(&content, position)?;
        let (tpgid, position) = next_i32(&content, position)?;
        let (flags, position) = next_i32(&content, position)?;
        let (minflt, position) = next_u64(&content, position)?;
        let (cminflt, position) = next_u64(&content, position)?;
        let (majflt, position) = next_u64(&content, position)?;
        let (cmajflt, position) = next_u64(&content, position)?;
        let (utime, position) = next_u64(&content, position)?;
        let (stime, position) = next_u64(&content, position)?;
        let (cutime, position) = next_u64(&content, position)?;
        let (cstime, position) = next_u64(&content, position)?;
        let (priority, position) = next_i64(&content, position)?;
        let (nice, position) = next_i64(&content, position)?;
        let (num_threads, position) = next_u64(&content, position)?;
        let (itrealvalue, position) = next_u64(&content, position)?;
        let (starttime, position) = next_u64(&content, position)?;
        let (vsize, position) = next_u64(&content, position)?;
        let (rss, position) = next_u64(&content, position)?;
        let (rsslim, position) = next_u64(&content, position)?;
        let (startcode, position) = next_u64(&content, position)?;
        let (endcode, position) = next_u64(&content, position)?;
        let (startstack, position) = next_u64(&content, position)?;
        let (kstkesp, position) = next_u64(&content, position)?;
        let (kstkeip, position) = next_u64(&content, position)?;
        let (signal, position) = next_u64(&content, position)?;
        let (blocked, position) = next_u64(&content, position)?;
        let (sigignore, position) = next_u64(&content, position)?;
        let (sigcatch, position) = next_u64(&content, position)?;
        let (wchan, position) = next_u64(&content, position)?;
        let (nswap, position) = next_u64(&content, position)?;
        let (cnswap, position) = next_u64(&content, position)?;
        let (exit_signal, position) = next_maybe_i32(&content, position)?;
        let (processor, position) = next_maybe_u32(&content, position)?;
        let (rt_priority, position) = next_maybe_u32(&content, position)?;
        let (policy, position) = next_maybe_u32(&content, position)?;
        let (delayacct_blkio_ticks, position) = next_maybe_u64(&content, position)?;
        let (guest_time, position) = next_maybe_u64(&content, position)?;
        let (cguest_time, position) = next_maybe_i64(&content, position)?;
        let (start_data, position) = next_maybe_u64(&content, position)?;
        let (end_data, position) = next_maybe_u64(&content, position)?;
        let (start_brk, position) = next_maybe_u64(&content, position)?;
        let (arg_start, position) = next_maybe_u64(&content, position)?;
        let (arg_end, position) = next_maybe_u64(&content, position)?;
        let (env_start, position) = next_maybe_u64(&content, position)?;
        let (env_end, position) = next_maybe_u64(&content, position)?;
        let (exit_code, _position) = next_maybe_i32(&content, position)?;

        Ok(Stat {
            comm,
            state,
            ppid,
            pgrp,
            session,
            tty_nr,
            tpgid,
            flags,
            minflt,
            cminflt,
            majflt,
            cmajflt,
            utime,
            stime,
            cutime,
            cstime,
            priority,
            nice,
            num_threads,
            itrealvalue,
            starttime,
            vsize,
            rss,
            rsslim,
            startcode,
            endcode,
            startstack,
            kstkesp,
            kstkeip,
            signal,
            blocked,
            sigignore,
            sigcatch,
            wchan,
            nswap,
            cnswap,
            exit_signal,
            processor,
            rt_priority,
            policy,
            delayacct_blkio_ticks,
            guest_time,
            cguest_time,
            start_data,
            end_data,
            start_brk,
            arg_start,
            arg_end,
            env_start,
            env_end,
            exit_code,
        })
    }
}

fn next_u32(content: &Vec<u8>, start_position: usize) -> Result<(u32, usize), ErrorCode> {
    let mut position = start_position;
    let mut result = 0;
    while valid_non_blank_position(content, position) {
        result = result * 10
            + (content[position] as char)
                .to_digit(10)
                .ok_or_else(|| ErrorCode::unexpected_character(content, position))?;
        position += 1;
    }
    if position == start_position {
        Err(ErrorCode::line_too_short(content, position))
    } else {
        position += 1;
        Ok((result, position))
    }
}

fn next_i32(content: &Vec<u8>, start_position: usize) -> Result<(i32, usize), ErrorCode> {
    let mut position = start_position;
    let sign = if content[position] == '-' as u8 {
        position = position + 1;
        -1
    } else {
        1
    };
    next_u32(content, position).map(|(value, position)| (sign * value as i32, position))
}

fn next_maybe_u32(
    content: &Vec<u8>,
    start_position: usize,
) -> Result<(Option<u32>, usize), ErrorCode> {
    if content.len() <= start_position {
        Ok((None, start_position))
    } else {
        next_u32(content, start_position).map(|(value, position)| (Some(value), position))
    }
}

fn next_maybe_i32(
    content: &Vec<u8>,
    start_position: usize,
) -> Result<(Option<i32>, usize), ErrorCode> {
    if content.len() <= start_position {
        Ok((None, start_position))
    } else {
        next_i32(content, start_position).map(|(value, position)| (Some(value), position))
    }
}

fn valid_non_blank_position(content: &Vec<u8>, position: usize) -> bool {
    position < content.len() && content[position] != ' ' as u8 && content[position] != '\n' as u8
}

fn next_u64(content: &Vec<u8>, start_position: usize) -> Result<(u64, usize), ErrorCode> {
    let mut position = start_position;
    let mut result = 0;
    while valid_non_blank_position(content, position) {
        result = result * 10
            + (content[position] as char)
                .to_digit(10)
                .ok_or_else(|| ErrorCode::unexpected_character(content, position))?
                as u64;
        position += 1;
    }
    if position == start_position {
        Err(ErrorCode::line_too_short(content, position))
    } else {
        position += 1;
        Ok((result, position))
    }
}

fn next_i64(content: &Vec<u8>, start_position: usize) -> Result<(i64, usize), ErrorCode> {
    let mut position = start_position;
    let sign = if content[position] == '-' as u8 {
        position = position + 1;
        -1
    } else {
        1
    };
    next_u64(content, position).map(|(value, position)| (sign * value as i64, position))
}

fn next_maybe_u64(
    content: &Vec<u8>,
    start_position: usize,
) -> Result<(Option<u64>, usize), ErrorCode> {
    if content.len() <= start_position {
        Ok((None, start_position))
    } else {
        next_u64(content, start_position).map(|(value, position)| (Some(value), position))
    }
}

fn next_maybe_i64(
    content: &Vec<u8>,
    start_position: usize,
) -> Result<(Option<i64>, usize), ErrorCode> {
    if content.len() <= start_position {
        Ok((None, start_position))
    } else {
        next_i64(content, start_position).map(|(value, position)| (Some(value), position))
    }
}

impl Sensor for ProcessSensor {
    fn sample(&mut self) -> Result<Vec<SensorOutput>, std::io::Error> {
        let proc_read_result = fs::read_dir("/proc");

        match proc_read_result {
            Ok(paths) => Ok(self.read_proc(paths)),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ErrorCode, ProcessSensor};

    #[test]
    fn read_proc_creates_a_process_sensor_with_empty_processes() {
        let tmp_dir = std::env::temp_dir().join("spotr1");
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let mut sensor = ProcessSensor::new();
        let processes = sensor.read_proc(std::fs::read_dir(&tmp_dir).unwrap());

        std::fs::remove_dir_all(&tmp_dir).unwrap();

        assert_eq!(0, processes.len());
    }

    #[test]
    fn read_proc_creates_a_process_sensor_with_processes_for_each_numeric_directory() {
        let tmp_dir = std::env::temp_dir().join("spotr2");
        std::fs::create_dir_all(tmp_dir.join("12345")).unwrap();
        std::fs::create_dir_all(tmp_dir.join("54321")).unwrap();

        let mut sensor = ProcessSensor::new();
        let processes = sensor.read_proc(std::fs::read_dir(&tmp_dir).unwrap());

        std::fs::remove_dir_all(&tmp_dir).unwrap();

        assert_eq!(2, processes.len());
        let mut pids: Vec<u32> = processes
            .into_iter()
            .map(|p| match p {
                super::SensorOutput::Process { pid, stat: _ } => pid,
                _ => 0,
            })
            .collect();
        pids.sort();
        assert_eq!(12345, pids[0]);
        assert_eq!(54321, pids[1]);
    }

    #[test]
    fn next_u32_parses_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        let (result, position) = super::next_u32(&buffer, 1).unwrap();
        assert_eq!(234, result);
        assert_eq!(5, position);
    }

    #[test]
    fn next_maybe_u32_parses_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        match super::next_maybe_u32(&buffer, 1).unwrap() {
            (Some(result), position) => {
                assert_eq!(234, result);
                assert_eq!(5, position);
            }
            (None, _position) => assert!(false, "Expected number to be parsed."),
        }
    }

    #[test]
    fn next_maybe_u32_returns_none() {
        let buffer = vec!['1' as u8];
        match super::next_maybe_u32(&buffer, 1).unwrap() {
            (Some(_result), _position) => assert!(false, "Unexpected value parsed"),
            (None, position) => assert_eq!(1, position),
        }
    }

    #[test]
    fn next_u32_reports_an_unexpected_character() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, 'a' as u8, ' ' as u8, '2' as u8,
        ];
        match super::next_u32(&buffer, 1).unwrap_err() {
            ErrorCode::UnexpectedCharacter(content, position) => {
                assert_eq!("123a 2", content.as_str());
                assert_eq!(3, position);
            }
            e => {
                assert!(false, "Unexpected error {:?}", e);
            }
        }
    }

    #[test]
    fn next_u32_reports_an_line_too_short() {
        let buffer = vec!['1' as u8, '2' as u8, '3' as u8, ' ' as u8];
        match super::next_u32(&buffer, 3).unwrap_err() {
            ErrorCode::LineTooShort(content, position) => {
                assert_eq!("123 ", content.as_str());
                assert_eq!(3, position);
            }
            e => {
                assert!(false, "Unexpected error {:?}", e);
            }
        }
    }

    #[test]
    fn next_u64_parses_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        let (result, position) = super::next_u64(&buffer, 1).unwrap();
        assert_eq!(234, result);
        assert_eq!(5, position);
    }

    #[test]
    fn next_maybe_u64_parses_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        match super::next_maybe_u64(&buffer, 1).unwrap() {
            (Some(result), position) => {
                assert_eq!(234, result);
                assert_eq!(5, position);
            }
            (None, _position) => assert!(false, "Expected number to be parsed."),
        }
    }

    #[test]
    fn next_maybe_u64_returns_none() {
        let buffer = vec!['1' as u8];
        match super::next_maybe_u64(&buffer, 1).unwrap() {
            (Some(_result), _position) => assert!(false, "Unexpected value parsed"),
            (None, position) => assert_eq!(1, position),
        }
    }

    #[test]
    fn next_u64_reports_an_unexpected_character() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, 'a' as u8, ' ' as u8, '2' as u8,
        ];
        match super::next_u64(&buffer, 1).unwrap_err() {
            ErrorCode::UnexpectedCharacter(content, position) => {
                assert_eq!("123a 2", content.as_str());
                assert_eq!(3, position);
            }
            e => {
                assert!(false, "Unexpected error {:?}", e);
            }
        }
    }

    #[test]
    fn next_u64_reports_an_line_too_short() {
        let buffer = vec!['1' as u8, '2' as u8, '3' as u8, ' ' as u8];
        match super::next_u64(&buffer, 3).unwrap_err() {
            ErrorCode::LineTooShort(content, position) => {
                assert_eq!("123 ", content.as_str());
                assert_eq!(3, position);
            }
            e => {
                assert!(false, "Unexpected error {:?}", e);
            }
        }
    }

    #[test]
    fn next_i32_parses_negative_number() {
        let buffer = vec![
            '1' as u8, '-' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        let (result, position) = super::next_i32(&buffer, 1).unwrap();
        assert_eq!(-234, result);
        assert_eq!(6, position);
    }

    #[test]
    fn next_i32_parses_positive_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        let (result, position) = super::next_i32(&buffer, 1).unwrap();
        assert_eq!(234, result);
        assert_eq!(5, position);
    }

    #[test]
    fn next_maybe_i32_parses_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        match super::next_maybe_i32(&buffer, 1).unwrap() {
            (Some(result), position) => {
                assert_eq!(234, result);
                assert_eq!(5, position);
            }
            (None, _position) => assert!(false, "Expected number to be parsed."),
        }
    }

    #[test]
    fn next_maybe_i32_returns_none() {
        let buffer = vec!['1' as u8];
        match super::next_maybe_i32(&buffer, 1).unwrap() {
            (Some(_result), _position) => assert!(false, "Unexpected value parsed"),
            (None, position) => assert_eq!(1, position),
        }
    }

    #[test]
    fn next_i64_parses_negative_number() {
        let buffer = vec![
            '1' as u8, '-' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        let (result, position) = super::next_i64(&buffer, 1).unwrap();
        assert_eq!(-234, result);
        assert_eq!(6, position);
    }

    #[test]
    fn next_i64_parses_positive_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        let (result, position) = super::next_i64(&buffer, 1).unwrap();
        assert_eq!(234, result);
        assert_eq!(5, position);
    }

    #[test]
    fn next_maybe_i64_parses_number() {
        let buffer = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, ' ' as u8, '2' as u8,
        ];
        match super::next_maybe_i64(&buffer, 1).unwrap() {
            (Some(result), position) => {
                assert_eq!(234, result);
                assert_eq!(5, position);
            }
            (None, _position) => assert!(false, "Expected number to be parsed."),
        }
    }

    #[test]
    fn next_maybe_i64_returns_none() {
        let buffer = vec!['1' as u8];
        match super::next_maybe_i64(&buffer, 1).unwrap() {
            (Some(_result), _position) => assert!(false, "Unexpected value parsed"),
            (None, position) => assert_eq!(1, position),
        }
    }

    #[test]
    fn read_proc_creates_a_process_sensor_ignores_non_numeric_directories() {
        let tmp_dir = std::env::temp_dir().join("spotr3");
        std::fs::create_dir_all(tmp_dir.join("p1234")).unwrap();
        std::fs::create_dir_all(tmp_dir.join("1234p")).unwrap();
        std::fs::create_dir_all(tmp_dir.join("test")).unwrap();

        let mut sensor = ProcessSensor::new();
        let processes = sensor.read_proc(std::fs::read_dir(&tmp_dir).unwrap());

        std::fs::remove_dir_all(&tmp_dir).unwrap();

        assert_eq!(0, processes.len());
    }

    #[test]
    fn parse_proc_errors_when_stat_format_incorrect() {
        let content = "4000 Command S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0 0 0 17 1 0 0 0 0 0 94903732950432 94903732954352 94903761399808 140733005624370 140733005624599 140733005624599 140733005631437 0\n";
        let parsed_content =
            ProcessSensor::new().parse_stat_content(content.to_string().into_bytes());

        match parsed_content {
            Err(ErrorCode::InvalidInput(input)) => assert_eq!(content, input.as_str()),
            Err(e) => assert!(false, "Unexpected error {:?}", e),
            Ok(_) => assert!(false, "Parse should have failed"),
        }
    }

    #[test]
    fn parse_proc_errors_when_stat_content_too_short() {
        let content = "4000 (Command) S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0\n";
        let parsed_content =
            ProcessSensor::new().parse_stat_content(content.to_string().into_bytes());

        match parsed_content {
            Err(ErrorCode::LineTooShort(input, position)) => assert_eq!(content, input.as_str()),
            Err(e) => assert!(false, "Unexpected error {:?}", e),
            Ok(_) => assert!(false, "Parse should have failed"),
        }
    }

    #[test]
    fn parse_proc_handles_space_in_parenthesis() {
        let content = "4000 (Socket Process) S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0 0 0 17 1 0 0 0 0 0 94903732950432 94903732954352 94903761399808 140733005624370 140733005624599 140733005624599 140733005631437 0\n";
        let parsed_content = ProcessSensor::new()
            .parse_stat_content(content.to_string().into_bytes())
            .unwrap();

        assert_eq!(parsed_content.comm, "Socket Process");
        assert_eq!(parsed_content.state, 'S');
        assert_eq!(parsed_content.ppid, 2957);
        assert_eq!(parsed_content.pgrp, 2262);
        assert_eq!(parsed_content.session, 2262);
        assert_eq!(parsed_content.tty_nr, 0);
        assert_eq!(parsed_content.tpgid, -1);
        assert_eq!(parsed_content.flags, 4194560);
        assert_eq!(parsed_content.minflt, 2869);
        assert_eq!(parsed_content.cminflt, 0);
        assert_eq!(parsed_content.majflt, 9);
        assert_eq!(parsed_content.cmajflt, 0);
        assert_eq!(parsed_content.utime, 8);
        assert_eq!(parsed_content.stime, 6);
        assert_eq!(parsed_content.cutime, 0);
        assert_eq!(parsed_content.cstime, 0);
        assert_eq!(parsed_content.priority, 20);
        assert_eq!(parsed_content.nice, 0);
        assert_eq!(parsed_content.num_threads, 5);
        assert_eq!(parsed_content.itrealvalue, 0);
        assert_eq!(parsed_content.starttime, 6668);
        assert_eq!(parsed_content.vsize, 225017856);
        assert_eq!(parsed_content.rss, 9295);
        assert_eq!(parsed_content.rsslim, 18446744073709551615);
        assert_eq!(parsed_content.startcode, 94903732310016);
        assert_eq!(parsed_content.endcode, 94903732943512);
        assert_eq!(parsed_content.startstack, 140733005618320);
        assert_eq!(parsed_content.kstkesp, 0);
        assert_eq!(parsed_content.kstkeip, 0);
        assert_eq!(parsed_content.signal, 0);
        assert_eq!(parsed_content.blocked, 0);
        assert_eq!(parsed_content.sigignore, 69634);
        assert_eq!(parsed_content.sigcatch, 1073745144);
        assert_eq!(parsed_content.wchan, 0);
        assert_eq!(parsed_content.nswap, 0);
        assert_eq!(parsed_content.cnswap, 0);
        assert_eq!(parsed_content.exit_signal, Some(17));
        assert_eq!(parsed_content.processor, Some(1));
        assert_eq!(parsed_content.rt_priority, Some(0));
        assert_eq!(parsed_content.policy, Some(0));
        assert_eq!(parsed_content.delayacct_blkio_ticks, Some(0));
        assert_eq!(parsed_content.guest_time, Some(0));
        assert_eq!(parsed_content.cguest_time, Some(0));
        assert_eq!(parsed_content.start_data, Some(94903732950432));
        assert_eq!(parsed_content.end_data, Some(94903732954352));
        assert_eq!(parsed_content.start_brk, Some(94903761399808));
        assert_eq!(parsed_content.arg_start, Some(140733005624370));
        assert_eq!(parsed_content.arg_end, Some(140733005624599));
        assert_eq!(parsed_content.env_start, Some(140733005624599));
        assert_eq!(parsed_content.env_end, Some(140733005631437));
        assert_eq!(parsed_content.exit_code, Some(0));
    }
}
