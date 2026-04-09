use clap::ArgMatches;
use serde::{Deserialize, Serialize};

use crate::{
    CONSEQUENCE_CUSTOM, DEBUG_MODE, MAX_CHARS_CUSTOM_REPORT, information::InfoRef, node::{Category, Node, State}
};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Consequence {
    Custom(String),
    /// Output of a command
    Command(String),
    NewInformation(InfoRef),
    /// The Blue team (Defenders) have discovered the activity.
    Detection,
    /// No consequence for the previous action
    None,
    // Unresolved(String)
}

impl ToString for Consequence {
    fn to_string(&self) -> String {
        match self {
            Consequence::Custom(content) => {
                // remove unnecessary whitespace
                let mut curated: &str = content.trim();
                // set maximum length for convenience.

                let mut clamped = ""; 

                if MAX_CHARS_CUSTOM_REPORT < curated.len() {
                    curated = &curated[..MAX_CHARS_CUSTOM_REPORT.min(curated.len())];
                    clamped = "..."; 
                }
                
                // reduce size if /n was found
                curated = match curated.find('\n') {
                    Some(i) => {
                        clamped = "..."; 
                        &curated[..i]
                    },
                    None => curated,
                };

                format!("custom: {curated}{clamped}")
            },
            _ => todo!("Currently not implemented. ")
        }
    }
}


/// Processes the consequence
///
/// # Panics
///
/// Panics if:
///  - No subcommand was passed
///  - An unrecognized subcommand was passed.
///  - Due to other errors caused by the different subcommands.
pub fn process_consequences(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Consequence detected! Processing...");
    }

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((CONSEQUENCE_CUSTOM, raw_content)) => handle_subcommand_custom(raw_content),
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

fn handle_subcommand_custom(raw_content: &ArgMatches) -> Option<Node> {
    let contents: String = crate::action::handle_general_custom(raw_content);

    if contents.is_empty() {
        None
    } else {
        Some(Node::new(Category::Consequence(Consequence::Custom(
            contents,
        ))))
    }
}
