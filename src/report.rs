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
    /*
       To print the timeline of events, we want:
       - We want to make divisions to separate the events by the day they ocurred.
        - To have a list of events sorted.

        (This could probably be better implemented)
    */
    let mut group_by_day: Vec<(chrono::NaiveDate, Vec<usize>)> = Vec::new();

    for (i, node) in time_line.0.iter().enumerate() {
        let date: chrono::NaiveDate = node.time_stamp.date_naive();

        let idx_opt: Option<usize> = group_by_day
            .iter()
            .position(|d: &(chrono::NaiveDate, Vec<usize>)| d.0 == date);

        match idx_opt {
            Some(idx) => {
                let nodes_by_date: &mut (chrono::NaiveDate, Vec<usize>) = &mut group_by_day[idx];
                nodes_by_date.1.push(i);
            }
            None => group_by_day.push((date, vec![i])),
        }
    }
    // Now I have subdivided all nodes into multiple collections depending on the day

    for collection in &mut group_by_day {
        collection.1.sort_by(|&i, &j| {
            let a: chrono::DateTime<chrono::Utc> =
                time_line.0.get(i).expect("Valid index").time_stamp;
            let b: chrono::DateTime<chrono::Utc> =
                time_line.0.get(j).expect("Valid index").time_stamp;
            a.cmp(&b)
        });
    }
    // Now the index of each collecion are sorted by the time the node was created.

    group_by_day.sort_by(|x, y| x.0.cmp(&y.0));

    // Now the groups themselves are sorted.

    let mut ret: String = String::from("## Timeline of events\n\n");
    let mut aux: String = String::new();

    for collection in group_by_day {
        aux.clear();
        aux = format!(" - {}: \n", collection.0.format("%d/%m/%Y"));
        ret.push_str(&aux);

        for i in collection.1 {
            aux.clear();
            let current: &crate::node::Node = time_line.0.get(i).expect("Valid index. ");
            let time: chrono::NaiveTime = current.time_stamp.time();
            aux = format!(
                "     - {}: {}\n",
                time.format("%H:%M"),
                current.category.to_string()
            );
            ret.push_str(&aux);
        }
    }

    return ret;
}
