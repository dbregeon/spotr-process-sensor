extern crate spotr_sensing;

use std::collections::HashSet;
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
        for result in paths {
            match result {
                Ok(entry) => {
                    let filename = &entry.file_name();
                    let stat_file = &entry.path().join("stat");
                    match filename.to_str().unwrap().parse::<u32>() {
                        Ok(pid) => {
                            let stat = match self.read_stat(stat_file) {
                                Ok(stat) => {
                                    let key = (pid, stat.comm.clone());
                                    unseen_processes.remove(&key);
                                    self.seen_processes.insert(key);
                                    ProcessStats::Stat(stat)
                                }
                                Err(message) => ProcessStats::Error(message),
                            };
                            processes.push(SensorOutput::Process { pid, stat });
                        }
                        _ => (),
                    }
                }
                Err(_) => {}
            };
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

    fn read_stat(&self, file: &PathBuf) -> Result<Stat, String> {
        fs::read_to_string(&file)
            .map_err(|_| format!("{}: Not found", file.to_string_lossy()))
            .and_then(|content| self.parse_stat_content(content))
    }

    fn parse_stat_content(&self, content: String) -> Result<Stat, String> {
        let tail = content
            .split(" (")
            .skip(1)
            .next()
            .ok_or("Invalid format for stat")?;
        let mut comm_split = tail.split(") ");
        let comm = comm_split
            .next()
            .ok_or("Invalid format for stat")?
            .to_string();
        let stats: Vec<String> = comm_split
            .next()
            .ok_or("Invalid format for stat")?
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if stats.len() < 35 {
            Err("Line too short".to_string())
        } else {
            Ok(Stat {
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
    use crate::ProcessSensor;

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
        let parsed_content = ProcessSensor::new().parse_stat_content(content.to_string());

        match parsed_content {
            Err(message) => assert_eq!(message, "Invalid format for stat"),
            Ok(_) => assert!(false, "Parse should have failed"),
        }
    }

    #[test]
    fn parse_proc_errors_when_stat_content_too_short() {
        let content = "4000 (Command) S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0\n";
        let parsed_content = ProcessSensor::new().parse_stat_content(content.to_string());

        match parsed_content {
            Err(message) => assert_eq!(message, "Line too short"),
            Ok(_) => assert!(false, "Parse should have failed"),
        }
    }

    #[test]
    fn parse_proc_handles_space_in_parenthesis() {
        let content = "4000 (Socket Process) S 2957 2262 2262 0 -1 4194560 2869 0 9 0 8 6 0 0 20 0 5 0 6668 225017856 9295 18446744073709551615 94903732310016 94903732943512 140733005618320 0 0 0 0 69634 1073745144 0 0 0 17 1 0 0 0 0 0 94903732950432 94903732954352 94903761399808 140733005624370 140733005624599 140733005624599 140733005631437 0\n";
        let parsed_content = ProcessSensor::new()
            .parse_stat_content(content.to_string())
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
