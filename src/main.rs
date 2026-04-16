//! # `RedDoc`
//!
//! `RedDoc` is a tool for documentation targeted to cybersecurity profesionals.
//!
//!
use atty::Stream;
use clap::{Arg, ArgAction, Command, command};
use std::{
    env,
    io::{self, Read},
    path::Path,
};

use crate::{
    action::{process_action, process_command},
    consequences::process_consequences,
    event::process_event,
    node::State,
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
/// Sub command configuration
const SUB_CONFIG: &str = "configuration";
/// Sub command report
const SUB_REPORT: &str = "report";

/// Sub command *command*
const SUB_COMMAND: &str = "command";
const SUB_COMMAND_ALIAS: [&str; 4] = [SUB_COMMAND, "comm", "com", "c"];

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

const MAX_CHARS_CUSTOM_REPORT: usize = 64;

pub mod action;
pub mod consequences;
pub mod event;
pub mod information;
pub mod node;
pub mod report;

// ****************************

const DEBUG_MODE: bool = true;

fn main() {
    /*
       The subcommand *command* needs to be parsed differently to the resto of
       commands because clap is not able to correcly parse all commands.

       For example, clap would parse `rd command ls -la` with a "-la" flag,
       wich is not the intended use.

       For this reason we will detect the use of the subcommand *command* and parse it manually.
    */

    let raw_arguments: env::ArgsOs = env::args_os(); 
    // `stdin == ""` => Nothing was piped
    let stdin: String = get_stdin(); 

    if let Some(sub_command) = raw_arguments.into_iter().skip(1).next() {
        let second_arg: String = sub_command.into_string().unwrap_or_default();
        let is_second_arg_command: bool = SUB_COMMAND_ALIAS.iter().any(|&s| s == second_arg);
        if is_second_arg_command {
            process_command();
        }
    }

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
                .alias("c")
                .arg(Arg::new("command").action(ArgAction::Append)),
        )
        .subcommand(
            Command::new(SUB_CONFIG)
                .about(ABOUT_CONFIG_CLAP)
                .alias("conf"),
        )
        .subcommand(Command::new(SUB_REPORT).about("Generate a report of the collected data. "))
        .get_matches();

    // //////////

    let project_path: &Path = Path::new("./project.json");
    let report_path: &Path = Path::new("./report.md");

    let mut state: State = State::get_state(project_path);

    match matches.subcommand() {
        Some((SUB_ACTION, sub_match)) => process_action(sub_match, stdin, &mut state),
        Some((SUB_CONSEQUENCE, sub_match)) => process_consequences(sub_match, stdin, &mut state),
        Some((SUB_EVENT, sub_match)) => process_event(sub_match, stdin, &mut state),
        Some((SUB_CONFIG, _sub_match)) => todo!("Sub command configuration not implemented yet. "),
        Some((SUB_REPORT, sub_match)) => process_report(sub_match, stdin, &mut state, report_path),
        Some((SUB_COMMAND, _sub_match)) => unreachable!(
            "Sub command *command* should not be reachable through this execution path. "
        ),
        Some(_) => {
            eprintln!("Unrecognized subcommand provided. ");
            return;
        }
        None => {
            eprintln!("No subcommand provided. ");
            return;
        }
    }

    let save_result: Result<(), std::io::Error> = State::save_state(project_path, &state);
    if let Err(e) = save_result {
        eprintln!("There has been an error storing the state. Error: \n{e:?}");
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
    let print: bool = false;

    if DEBUG_MODE & print {
        println!("\tEntered get_stdin");
    }

    if atty::is(Stream::Stdin) {
        if DEBUG_MODE & print {
            println!("\tNo pipe detected");
        }
    } else {
        if DEBUG_MODE & print {
            println!("\tInput is piped");
        }
        let _ = io::stdin()
            .read_to_string(&mut ret)
            .expect("\tNo error reading from stdin. ");
    }

    if DEBUG_MODE & print {
        println!(
            "\tExited get_stdin\n\tString obtained form stdin: |{}|",
            ret.trim()
        );
    }

    return ret;
}
