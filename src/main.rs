//! # RedDoc
//!
//! RedDoc is a tool for documentation targeted to cybersecurity profesionals.
//!
//!

use clap::{Arg, ArgMatches, Command, command};

use crate::node::*;

const ABOUT_ACTION_CLAP: &str = "Adds a node that represents an action. ";
const ABOUT_CONSEQUENCE_CLAP: &str =
    "Add a node that represents a consequence to a previous action. ";
const ABOUT_EVENT_CLAP: &str = "Add an event, a *consequence* without your cause";
const ABOUT_COMMAND_CLAP: &str = "Execute the provided command and document it. ";

/// Sub command action
const SUB_ACTION: &str = "action";
/// Sub command Consequence
const SUB_CONSEQUENCE: &str = "consequence";
/// Sub command event
const SUB_EVENT: &str = "event";
/// Sub command *command*
const SUB_COMMAND: &str = "command";

// Sub commands fot action:
const ACTION_CUSTOM: &str = "custom";
const ACTION_CUSTOM_ABOUT: &str =
    "Introduce any text you want to be saved between quotes. \"Hello world!\"

This option can be used to store: 
 - Comments
 - Scenatios not accounted in the program. ";

pub mod information;
pub mod node;

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
                .alias("cons"),
        )
        .subcommand(Command::new(SUB_EVENT).about(ABOUT_EVENT_CLAP).alias("ev"))
        .subcommand(
            Command::new(SUB_COMMAND)
                .about(ABOUT_COMMAND_CLAP)
                .alias("c"),
        )
        .get_matches();

    let _ = match matches.subcommand() {
        Some((SUB_ACTION, sub_match)) => process_action(sub_match),
        Some(_) => todo!("Unrecognized subcommand provided"),
        None => todo!("No subcommand provided. "),
    };
}

fn process_action(sub_match: &ArgMatches) -> Result<(), ()> {
    if DEBUG_MODE {
        println!("Action detected! Processing...");
    }

    let new_node: Node = match sub_match.subcommand() {
        Some((ACTION_CUSTOM, raw_content)) => {
            let content: Option<&String> = raw_content.get_one::<String>("content");

            let content: &str = match content {
                Some(string) => string.as_str(),
                None => "",
            };

            Node::new(Category::Action(Action::Custom(String::from(content))))
        }
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    println!("New node: \n{:?}", new_node); 

    return Ok(());
}
