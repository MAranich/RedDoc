//! # `RedDoc`
//!
//! `RedDoc` is a tool for documentation targeted to cybersecurity profesionals.
//!
//!

use std::{
    io::{self, Read},
    path::Path,
};

use clap::{Arg, ArgMatches, Command, command};

use crate::node::{Action, Consequence, Event, Category, Node, State};

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

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((ACTION_CUSTOM, raw_content)) => {
            let contents: String = handle_custom_subcommand(raw_content);

            if contents.is_empty() {
                None
            } else {
                Some(Node::new(Category::Action(Action::Custom(String::from(
                    contents,
                )))))
            }
        }
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    if let None = new_node {
        if DEBUG_MODE {
            println!("No node has been created. ");
        }
        return;
    }

    let new_node: Node = new_node.expect("To contain the Some variant. ");

    if DEBUG_MODE {
        println!("New node: \n{new_node:?}");
    }

    state.add_node(&new_node);
}

fn process_consequences(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Consequence detected! Processing...");
    }

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((CONSEQUENCE_CUSTOM, raw_content)) => {
            let contents: String = handle_custom_subcommand(raw_content);

            if contents.is_empty() {
                None
            } else {
                Some(Node::new(Category::Consequence(Consequence::Custom(String::from(
                    contents,
                )))))
            }
        }
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    if let None = new_node {
        if DEBUG_MODE {
            println!("No node has been created. ");
        }
        return;
    }

    let new_node: Node = new_node.expect("To contain the Some variant. ");

    if DEBUG_MODE {
        println!("New node: \n{new_node:?}");
    }

    state.add_node(&new_node);
}

fn process_event(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Event detected! Processing...");
    }

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((EVENT_CUSTOM, raw_content)) => {
            let contents: String = handle_custom_subcommand(raw_content);

            if contents.is_empty() {
                None
            } else {
                Some(Node::new(Category::Event(Event::Custom(String::from(
                    contents,
                )))))
            }
        }
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    if let None = new_node {
        if DEBUG_MODE {
            println!("No node has been created. ");
        }
        return;
    }

    let new_node: Node = new_node.expect("To contain the Some variant. ");

    if DEBUG_MODE {
        println!("New node: \n{new_node:?}");
    }

    state.add_node(&new_node);
}

/// Returns a strig containing the standard input.
///
/// Empty if noting was provided.
pub fn get_stdin() -> String {
    let mut ret: String = String::new();
    io::stdin()
        .read_to_string(&mut ret)
        .expect("No error readin from stdin. ");

    return ret;
}

pub fn handle_custom_subcommand(raw_content: &ArgMatches) -> String {
    // Abstracted because a lot of code was the same. Done here because it's part of both Action, Consequence and Event
    /*
       We need to check if we got the values from the argument or stdin and handle each case:
        - Both argument and stdin: send warning, concatenate inputs and save.
        - Neither argument not stdin: send error message and do nothing.
    */

    // content obtained from the argument
    let content_arg_opt: Option<&String> = raw_content.get_one::<String>("content");
    let exists_content_arg: bool = !content_arg_opt.is_none_or(|s: &String| s.trim().is_empty());
    let mut content_arg: String = content_arg_opt.map(|s| s.clone()).unwrap_or_default();

    let content_stdin: String = get_stdin();
    let exists_std_input: bool = !content_stdin.trim().is_empty();

    let content: String = match (exists_content_arg, exists_std_input) {
        (true, true) => {
            println!(
                "Info: There were inputs on both argument and stdin. The stdin was concatenated to the argument. "
            );
            // add some space
            content_arg.push_str("\n\n\n");

            content_arg.push_str(&content_stdin);
            content_arg
        }
        (true, false) => content_arg,
        (false, true) => content_stdin,
        (false, false) => {
            eprintln!(
                "Error: No information was provided through the standard input (piped) nor a as raw text. \nNo action was taken. "
            );
            return String::new();
        }
    };

    return content;
}
