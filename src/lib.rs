extern crate regex;
extern crate spotr_sensing;

use std::result::Result;
use std::{fs, path::PathBuf};

use spotr_sensing::{ProcessStats, Sensor, SensorOutput};

use regex::Regex;

#[no_mangle]
pub fn initialize(_: &str) -> *mut dyn Sensor {
    Box::into_raw(Box::new(ProcessSensor))
}

struct ProcessSensor;

impl ProcessSensor {
    fn read_proc<I>(paths: I) -> Vec<SensorOutput>
    where
        I: Iterator<Item = Result<fs::DirEntry, std::io::Error>>,
    {
        let input_re = Regex::new(r#"^(\d+)$"#).unwrap();
        let mut processes = Vec::new();
        for result in paths {
            match result {
                Ok(entry) => {
                    let filename = &entry.file_name();
                    let stat_file = &entry.path().join("stat");
                    for capture in input_re.captures_iter(filename.to_str().unwrap()) {
                        let pid = capture[1].parse::<u32>().unwrap();
                        println!("pid: {}", pid);
                        processes.push(SensorOutput::Process {
                            pid,
                            stat: ProcessSensor::read_stat(stat_file),
                        });
                    }
                }
                Err(_) => {}
            };
        }
        processes
    }

    fn read_stat(file: &PathBuf) -> ProcessStats {
        match fs::read_to_string(&file) {
            Err(_) => ProcessStats::Error(format!("{}: Not found", file.to_string_lossy())),
            Ok(content) => match ProcessSensor::parse_stat_content(content) {
                Ok(result) => result,
                Err(message) => {
                    ProcessStats::Error(format!("{}: {}", file.to_string_lossy(), message))
                }
            },
        }
    }

    fn parse_stat_content(content: String) -> Result<ProcessStats, String> {
        let input_re = Regex::new(r#"^\d+ ([(][^)]+[)]) (.*)\n$"#).unwrap();
        match input_re.captures(&content) {
            None => Err("Invalid input".to_string()),
            Some(captures) => {
                let comm = captures[1].to_string();
                let stats: Vec<String> = captures[2]
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                if stats.len() < 35 {
                    Err("Line too short".to_string())
                } else {
                    Ok(ProcessStats::Stat {
                        comm,
                        state: stats[0].chars().next().unwrap(),
                        ppid: stats[1].parse().unwrap(),
                        pgrp: stats[2].parse().unwrap(),
                        session: stats[3].parse().unwrap(),
                        tty_nr: stats[4].parse().unwrap(),
                        tpgid: stats[5].parse().unwrap(),
                        flags: stats[6].parse().unwrap(),
                        minflt: stats[7].parse().unwrap(),
                        cminflt: stats[8].parse().unwrap(),
                        majflt: stats[9].parse().unwrap(),
                        cmajflt: stats[10].parse().unwrap(),
                        utime: stats[11].parse().unwrap(),
                        stime: stats[12].parse().unwrap(),
                        cutime: stats[13].parse().unwrap(),
                        cstime: stats[14].parse().unwrap(),
                        priority: stats[15].parse().unwrap(),
                        nice: stats[16].parse().unwrap(),
                        num_threads: stats[17].parse().unwrap(),
                        itrealvalue: stats[18].parse().unwrap(),
                        starttime: stats[19].parse().unwrap(),
                        vsize: stats[20].parse().unwrap(),
                        rss: stats[21].parse().unwrap(),
                        rsslim: stats[22].parse().unwrap(),
                        startcode: stats[23].parse().unwrap(),
                        endcode: stats[24].parse().unwrap(),
                        startstack: stats[25].parse().unwrap(),
                        kstkesp: stats[26].parse().unwrap(),
                        kstkeip: stats[27].parse().unwrap(),
                        signal: stats[28].parse().unwrap(),
                        blocked: stats[29].parse().unwrap(),
                        sigignore: stats[30].parse().unwrap(),
                        sigcatch: stats[31].parse().unwrap(),
                        wchan: stats[32].parse().unwrap(),
                        nswap: stats[33].parse().unwrap(),
                        cnswap: stats[34].parse().unwrap(),
                        exit_signal: stats.get(35).and_then(|v| v.parse().ok()),
                        processor: stats.get(36).and_then(|v| v.parse().ok()),
                        rt_priority: stats.get(37).and_then(|v| v.parse().ok()),
                        policy: stats.get(38).and_then(|v| v.parse().ok()),
                        delayacct_blkio_ticks: stats.get(39).and_then(|v| v.parse().ok()),
                        guest_time: stats.get(40).and_then(|v| v.parse().ok()),
                        cguest_time: stats.get(41).and_then(|v| v.parse().ok()),
                        start_data: stats.get(42).and_then(|v| v.parse().ok()),
                        end_data: stats.get(43).and_then(|v| v.parse().ok()),
                        start_brk: stats.get(44).and_then(|v| v.parse().ok()),
                        arg_start: stats.get(45).and_then(|v| v.parse().ok()),
                        arg_end: stats.get(46).and_then(|v| v.parse().ok()),
                        env_start: stats.get(47).and_then(|v| v.parse().ok()),
                        env_end: stats.get(48).and_then(|v| v.parse().ok()),
                        exit_code: stats.get(49).and_then(|v| v.parse().ok()),
                    })
                }
            }
        }
    }
}

impl Sensor for ProcessSensor {
    fn sample(&self) -> Result<Vec<SensorOutput>, std::io::Error> {
        let proc_read_result = fs::read_dir("/proc");

        match proc_read_result {
            Ok(paths) => Ok(ProcessSensor::read_proc(paths)),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use spotr_sensing::ProcessStats;

    #[test]
    fn read_proc_creates_a_process_sensor_with_empty_processes() {
        let tmp_dir = std::env::temp_dir().join("spotr1");
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let processes = super::ProcessSensor::read_proc(std::fs::read_dir(&tmp_dir).unwrap());

        std::fs::remove_dir_all(&tmp_dir).unwrap();

        assert_eq!(0, processes.len());
    }

    #[test]
    fn read_proc_creates_a_process_sensor_with_processes_for_each_numeric_directory() {
        let tmp_dir = std::env::temp_dir().join("spotr2");
        std::fs::create_dir_all(tmp_dir.join("12345")).unwrap();
        std::fs::create_dir_all(tmp_dir.join("54321")).unwrap();

        let processes = super::ProcessSensor::read_proc(std::fs::read_dir(&tmp_dir).unwrap());

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
    fn read_proc_creates_a_process_sensor_ignores_non_numeric_directories() {
        let tmp_dir = std::env::temp_dir().join("spotr3");
        std::fs::create_dir_all(tmp_dir.join("p1234")).unwrap();
        std::fs::create_dir_all(tmp_dir.join("1234p")).unwrap();
        std::fs::create_dir_all(tmp_dir.join("test")).unwrap();

        let processes = super::ProcessSensor::read_proc(std::fs::read_dir(&tmp_dir).unwrap());

        std::fs::remove_dir_all(&tmp_dir).unwrap();

        assert_eq!(0, processes.len());
    }

    #[test]
    fn parse_proc_errors_when_stat_format_incorrect() {
        let content = "4000 Command S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0 0 0 17 1 0 0 0 0 0 94903732950432 94903732954352 94903761399808 140733005624370 140733005624599 140733005624599 140733005631437 0\n";
        let parsed_content = super::ProcessSensor::parse_stat_content(content.to_string());

        match parsed_content {
            Err(message) => assert_eq!(message, "Invalid input"),
            Ok(_) => assert!(false, "Parse should have failed"),
        }
    }

    #[test]
    fn parse_proc_errors_when_stat_content_too_short() {
        let content = "4000 (Command) S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0\n";
        let parsed_content = super::ProcessSensor::parse_stat_content(content.to_string());

        match parsed_content {
            Err(message) => assert_eq!(message, "Line too short"),
            Ok(_) => assert!(false, "Parse should have failed"),
        }
    }

    #[test]
    fn parse_proc_handles_space_in_parenthesis() {
        let content = "4000 (Socket Process) S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0 0 0 17 1 0 0 0 0 0 94903732950432 94903732954352 94903761399808 140733005624370 140733005624599 140733005624599 140733005631437 0\n";
        let parsed_content = super::ProcessSensor::parse_stat_content(content.to_string()).unwrap();

        match parsed_content {
            ProcessStats::Stat {
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
            } => {
                assert_eq!(comm, "(Socket Process)");
                assert_eq!(state, 'S');
                assert_eq!(ppid, 2957);
                assert_eq!(pgrp, 2262);
                assert_eq!(session, 2262);
                assert_eq!(tty_nr, 0);
                assert_eq!(tpgid, -1);
                assert_eq!(flags, 4194560);
                assert_eq!(minflt, 2869);
                assert_eq!(cminflt, 0);
                assert_eq!(majflt, 9);
                assert_eq!(cmajflt, 0);
                assert_eq!(utime, 8);
                assert_eq!(stime, 6);
                assert_eq!(cutime, 0);
                assert_eq!(cstime, 0);
                assert_eq!(priority, 20);
                assert_eq!(nice, 0);
                assert_eq!(num_threads, 5);
                assert_eq!(itrealvalue, 0);
                assert_eq!(starttime, 6668);
                assert_eq!(vsize, 225017856);
                assert_eq!(rss, 9295);
                assert_eq!(rsslim, 18446744073709551615);
                assert_eq!(startcode, 94903732310016);
                assert_eq!(endcode, 94903732943512);
                assert_eq!(startstack, 140733005618320);
                assert_eq!(kstkesp, 0);
                assert_eq!(kstkeip, 0);
                assert_eq!(signal, 0);
                assert_eq!(blocked, 0);
                assert_eq!(sigignore, 69634);
                assert_eq!(sigcatch, 1073745144);
                assert_eq!(wchan, 0);
                assert_eq!(nswap, 0);
                assert_eq!(cnswap, 0);
                assert_eq!(exit_signal, Some(17));
                assert_eq!(processor, Some(1));
                assert_eq!(rt_priority, Some(0));
                assert_eq!(policy, Some(0));
                assert_eq!(delayacct_blkio_ticks, Some(0));
                assert_eq!(guest_time, Some(0));
                assert_eq!(cguest_time, Some(0));
                assert_eq!(start_data, Some(94903732950432));
                assert_eq!(end_data, Some(94903732954352));
                assert_eq!(start_brk, Some(94903761399808));
                assert_eq!(arg_start, Some(140733005624370));
                assert_eq!(arg_end, Some(140733005624599));
                assert_eq!(env_start, Some(140733005624599));
                assert_eq!(env_end, Some(140733005631437));
                assert_eq!(exit_code, Some(0));
            }
            ProcessStats::Error(m) => assert!(false, "Parse error {}", m),
        }
    }
}
