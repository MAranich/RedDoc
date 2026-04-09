//! # `RedDoc`
//!
//! `RedDoc` is a tool for documentation targeted to cybersecurity profesionals.
//!
//!
use atty::Stream;
use std::{
    io::{self, BufRead, Read},
    path::Path,
};

use clap::{Arg, Command, command};

use crate::{
    action::process_action, consequences::process_consequences, event::process_event, node::State,
    report::process_report,
};

const ABOUT_ACTION_CLAP: &str = "Adds a node that represents an action. ";
const ABOUT_CONSEQUENCE_CLAP: &str =
    "Add a node that represents a consequence to a previous action. ";
const ABOUT_EVENT_CLAP: &str = "Add an event, a *consequence* without your cause";
const ABOUT_COMMAND_CLAP: &str = "Execute the provided command and document it. ";
const ABOUT_CONFIG_CLAP: &str = "Subcommand for configuration changes. ";

/// Sub command action
const SUB_ACTION: &str = "action";
/// Sub command Consequence
const SUB_CONSEQUENCE: &str = "consequence";
/// Sub command event
const SUB_EVENT: &str = "event";
/// Sub command *command*
const SUB_COMMAND: &str = "command";
/// Sub command configuration
const SUB_CONFIG: &str = "configuration";
/// Sub command report
const SUB_REPORT: &str = "report";

// Sub commands for action: **********************************************
const ACTION_CUSTOM: &str = "custom";
const ACTION_CUSTOM_ABOUT: &str =
    "Introduce any text you want to be saved between quotes. \"Hello world!\"

This option can be used to store: 
 - Comments
 - Scenatios not accounted in the program. ";

// Sub commands for consequence: *****************************************
const CONSEQUENCE_CUSTOM: &str = "custom";
const CONSEQUENCE_CUSTOM_ABOUT: &str =
    "Introduce any text you want to be saved between quotes. \"Hello world!\"

This option can be used to store: 
 - Comments
 - Scenatios not accounted in the program. ";

// Sub commands for events: **********************************************
const EVENT_CUSTOM: &str = "custom";
const EVENT_CUSTOM_ABOUT: &str =
    "Introduce any text you want to be saved between quotes. \"Hello world!\"

This option can be used to store: 
 - Comments
 - Scenatios not accounted in the program. ";

pub mod action;
pub mod consequences;
pub mod event;
pub mod information;
pub mod node;
pub mod report;

// ****************************

const DEBUG_MODE: bool = true;

fn main() {
    let matches: clap::ArgMatches = command!()
        .subcommand(
            Command::new(SUB_ACTION)
                .about(ABOUT_ACTION_CLAP)
                .alias("act")
                .alias("a")
                .subcommand(
                    Command::new(ACTION_CUSTOM)
                        .arg(Arg::new("content"))
                        .about(ACTION_CUSTOM_ABOUT),
                ),
        )
        .subcommand(
            Command::new(SUB_CONSEQUENCE)
                .about(ABOUT_CONSEQUENCE_CLAP)
                .alias("cons")
                .subcommand(
                    Command::new(CONSEQUENCE_CUSTOM)
                        .arg(Arg::new("content"))
                        .about(CONSEQUENCE_CUSTOM_ABOUT),
                ),
        )
        .subcommand(
            Command::new(SUB_EVENT)
                .about(ABOUT_EVENT_CLAP)
                .alias("ev")
                .alias("e")
                .subcommand(
                    Command::new(EVENT_CUSTOM)
                        .arg(Arg::new("content"))
                        .about(EVENT_CUSTOM_ABOUT),
                ),
        )
        .subcommand(
            Command::new(SUB_COMMAND)
                .about(ABOUT_COMMAND_CLAP)
                .alias("comm")
                .alias("com")
                .alias("c"),
        )
        .subcommand(
            Command::new(SUB_CONFIG)
                .about(ABOUT_CONFIG_CLAP)
                .alias("conf"),
        )
        .get_matches();

    // //////////

    let project_path: &Path = Path::new("./project.json");
    let report_path: &Path = Path::new("./report.md");

    let mut state: State = State::get_state(project_path);

    match matches.subcommand() {
        Some((SUB_ACTION, sub_match)) => process_action(sub_match, &mut state),
        Some((SUB_CONSEQUENCE, sub_match)) => process_consequences(sub_match, &mut state),
        Some((SUB_EVENT, sub_match)) => process_event(sub_match, &mut state),
        Some((SUB_COMMAND, _sub_match)) => todo!("Sub command *command* not implemented yet. "),
        Some((SUB_CONFIG, _sub_match)) => todo!("Sub command configuration not implemented yet. "),
        Some((SUB_REPORT, sub_match)) => process_report(sub_match, &mut state, report_path),
        Some(_) => todo!("Unrecognized subcommand provided"),
        None => todo!("No subcommand provided. "),
    }

    let save_result: Result<(), std::io::Error> = State::save_state(project_path, &state);
    if let Err(e) = save_result {
        println!("There has been an error storing the state. Error: \n{e:?}");
    }
}

/// Returns a strig containing the standard input.
///
/// Empty if noting was provided.
///
/// # Panics
///
/// Panics if there was an error reading from stdin
#[must_use]
pub fn get_stdin() -> String {
    let mut ret: String = String::new();

    if DEBUG_MODE {
        println!("\tEntered get_stdin");
    }

    if atty::is(Stream::Stdin) {
        if DEBUG_MODE {
            println!("\tNo pipe detected");
        }
    } else {
        if DEBUG_MODE {
            println!("\tInput is piped");
        }
        let _ = io::stdin()
            .read_to_string(&mut ret)
            .expect("\tNo error reading from stdin. ");
    }

    /*

    if atty::is(atty::Stream::Stdin) {
        io::stdin()
            .read_to_string(&mut ret)
            .expect("No error readin from stdin. ");
    }

     */

    /*
     loop {
        let mut input: String = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(len) => {
                if len == 0 {
                    println!("Length 0. ");
                    break;
                } else {
                            if DEBUG_MODE {
                    println!("|{input}|");
                }
                    ret.push_str(&input);
                }
            }
            Err(error) => {
                eprintln!("Error while reading stdin: \n{error}");
                break;
            }
        }
    }
    */

    /*
    let ret = io::stdin()
        .lock()
        .lines()
        .fold("".to_string(), |acc, line| acc + &line.unwrap() + "\n");
     */

    if DEBUG_MODE {
        println!("\tExited get_stdin\n\tString obtained form stdin: |{}|", ret.trim());
    }

    return ret;
}
