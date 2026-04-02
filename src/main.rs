//! # RedDoc
//! 
//! RedDoc is a tool for documentation targeted to cybersecurity profesionals. 
//! 
//! 

use clap::{Command, command};

const ABOUT_ACTION_CLAP: &'static str = "Adds a node that represents an action. ";
const ABOUT_CONSEQUENCE_CLAP: &'static str =
    "Add a node that represents a consequence to a previous action. ";
const ABOUT_EVENT_CLAP: &'static str = "Add an event, a *consequence* without your cause";
const ABOUT_COMMAND_CLAP: &'static str = "Execute the provided command and document it. ";

pub mod node;

fn main() {
    let matches: clap::ArgMatches = command!()
        .subcommand(
            Command::new("action")
                .about(ABOUT_ACTION_CLAP)
                .alias("act")
                .alias("a"),
        )
        .subcommand(
            Command::new("consequence")
                .about(ABOUT_CONSEQUENCE_CLAP)
                .alias("cons"),
        )
        .subcommand(Command::new("event").about(ABOUT_EVENT_CLAP).alias("ev"))
        .subcommand(Command::new("command").about(ABOUT_COMMAND_CLAP).alias("c"))
        .get_matches();
}
