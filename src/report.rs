use std::{
    io::{self, Write},
    path::Path,
};

use clap::ArgMatches;

use crate::{
    DEBUG_MODE,
    node::{State, Timeline},
};

pub fn process_report<P: AsRef<Path>>(_sub_match: &ArgMatches, state: &mut State, path: P) {
    let contents: String = time_line_to_markdown(&state.time_line);

    match generate_file(path, contents.as_str()) {
        Ok(()) => {
            if DEBUG_MODE {
                println!("Report successfully generated. ");
            }
        }
        Err(e) => eprintln!("There was an error while storing the report: \n{e:?}"),
    }
}

/// Generates a report file with the provided contents.
///
/// # Errors
///
/// This function will return an error if:
/// - There was an error creating/opening the report file.
/// - There was an error writing into the report file.
///
pub fn generate_file<P: AsRef<Path>>(path: P, content: &str) -> Result<(), io::Error> {
    let data: &[u8] = content.as_bytes();

    let mut file: std::fs::File = std::fs::OpenOptions::new()
        .write(true) // Open for writing
        .truncate(true) // Discard previous contents
        .create(true) // Create new file it it does not exist
        .open(path)?; // Open the given file or backpropagate error

    let out: Result<(), io::Error> = file.write_all(data);
    out?; // Backpropagate possible writing errors. 

    return Ok(());
}

fn time_line_to_markdown(time_line: &Timeline) -> String {
    return String::new();
}
