extern crate regex;
extern crate spotr_sensing;

use std::fs;
use std::result::Result;

use spotr_sensing::{Sensor, SensorOutput};


use regex::Regex;

#[no_mangle]
pub fn initialize() -> *mut dyn Sensor {
    Box::into_raw(Box::new(ProcessSensor))
}


struct ProcessSensor;

impl ProcessSensor {
    fn read_proc<I>(paths: I) -> Vec<SensorOutput> where I: Iterator<Item = Result<fs::DirEntry, std::io::Error>> {
        let input_re = Regex::new(r#"^(\d+)$"#).unwrap();
        let mut processes = Vec::new();
        for result in paths {
            match result {
                Ok(entry) => {
                    let name = entry.file_name().into_string().unwrap();
                    for capture in input_re.captures_iter(name.as_str()) {
                        let pid = capture[1].parse::<u32>().unwrap();
                        processes.push(SensorOutput::Process { pid });
                    }
                },
                Err(_) => {}
            };
        }
        processes
    }
}

impl Sensor for ProcessSensor {
    fn sample(&self) -> Result<Vec<SensorOutput>, std::io::Error> {
        let proc_read_result = fs::read_dir("/proc");

        match proc_read_result {
            Ok(paths) => Ok(ProcessSensor::read_proc(paths)),
            Err(e) => Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
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
        let mut pids: Vec<u32> = processes.into_iter().map(|p| match p { super::SensorOutput::Process { pid } => pid, _ => 0}).collect();
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
}
