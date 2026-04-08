//! # `RedDoc`
//!
//! `RedDoc` is a tool for documentation targeted to cybersecurity profesionals.
//!
//!

use std::path::Path;

use clap::{Arg, ArgMatches, Command, command};

use crate::node::{Action, Category, Node, State};

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

    let project_directory: &str = "./project.json";
    let mut state: State = State::get_state(Path::new(project_directory))
        .expect("Error obtaining project information. ");

    let _ = match matches.subcommand() {
        Some((SUB_ACTION, sub_match)) => process_action(sub_match, &mut state),
        Some((SUB_CONSEQUENCE, sub_match)) => process_consequences(sub_match, &mut state),
        Some((SUB_EVENT, sub_match)) => process_event(sub_match, &mut state),
        Some(_) => todo!("Unrecognized subcommand provided"),
        None => todo!("No subcommand provided. "),
    };

    let save_result: Result<(), std::io::Error> = State::save_state(project_directory, &state);
    if let Err(e) = save_result {
        println!("There has been an error storing the state. Error: \n{e:?}");
    }
}

fn process_action(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Action detected! Processing...");
    }

    let new_node: Node = match sub_match.subcommand() {
        Some((ACTION_CUSTOM, raw_content)) => {
            let content: Option<&String> = raw_content.get_one::<String>("content");

            let content: &str = content.map_or("", |string| string.as_str());

            Node::new(Category::Action(Action::Custom(String::from(content))))
        }
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    println!("New node: \n{new_node:?}");

    state.add_node(&new_node);
}

fn process_consequences(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Consequence detected! Processing...");
    }

    let new_node: Node = match sub_match.subcommand() {
        Some((CONSEQUENCE_CUSTOM, raw_content)) => {
            let content: Option<&String> = raw_content.get_one::<String>("content");

            let content: &str = content.map_or("", |string| string.as_str());

            Node::new(Category::Consequence(node::Consequence::Custom(
                String::from(content),
            )))
        }
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    println!("New node: \n{new_node:?}");

    state.add_node(&new_node);
}

fn process_event(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Event detected! Processing...");
    }

    let new_node: Node = match sub_match.subcommand() {
        Some((EVENT_CUSTOM, raw_content)) => {
            let content: Option<&String> = raw_content.get_one::<String>("content");

            let content: &str = content.map_or("", |string| string.as_str());

            Node::new(Category::Event(node::Event::Custom(String::from(content))))
        }
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    println!("New node: \n{new_node:?}");

    state.add_node(&new_node);
}
