use clap::ArgMatches;
use serde::{Deserialize, Serialize};

use crate::{
    DEBUG_MODE, EVENT_CUSTOM, MAX_CHARS_CUSTOM_REPORT,
    node::{Category, Node, State},
};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Custom(String),
    /// The Blue team (Defenders) have discovered the activity.
    Detection,
}

impl ToString for Event {
    fn to_string(&self) -> String {
        match self {
            Self::Custom(content) => {
                // remove unnecessary whitespace
                let mut curated: &str = content.trim();
                // set maximum length for convenience.

                let mut clamped: &str = if MAX_CHARS_CUSTOM_REPORT < curated.len() {
                    curated = &curated[..MAX_CHARS_CUSTOM_REPORT.min(curated.len())];
                    "..."
                } else {
                    ""
                };

                // reduce size if /n was found
                curated = curated.find('\n').map_or(curated, |i| {
                    clamped = "...";
                    &curated[..i]
                });

                format!("custom: {curated}{clamped}")
            }
            Self::Detection => todo!("Currently not implemented. "),
        }
    }
}

/// Processes the event
///
/// # Panics
///
/// Panics if:
///  - No subcommand was passed
///  - An unrecognized subcommand was passed.
///  - Due to other errors caused by the different subcommands.
pub fn process_event(sub_match: &ArgMatches, stdin: String, state: &mut State) {
    if DEBUG_MODE {
        println!("Event detected! Processing...");
    }

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((EVENT_CUSTOM, raw_content)) => handle_subcommand_custom(raw_content, stdin),
        Some(_) => todo!("Unrecognized action subcommand provided"),
        None => todo!("No action subcommand provided. "),
    };

    if new_node.is_none() {
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

fn handle_subcommand_custom(raw_content: &ArgMatches, stdin: String) -> Option<Node> {
    let contents: String = crate::action::handle_general_custom(raw_content, stdin);

    if contents.is_empty() {
        None
    } else {
        Some(Node::new(Category::Event(Event::Custom(contents))))
    }
}
