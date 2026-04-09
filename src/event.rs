use clap::ArgMatches;

use crate::{
    DEBUG_MODE, EVENT_CUSTOM,
    node::{Category, Event, Node, State},
};

/// Processes the event
///
/// # Panics
///
/// Panics if:
///  - No subcommand was passed
///  - An unrecognized subcommand was passed.
///  - Due to other errors caused by the different subcommands.
pub fn process_event(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Event detected! Processing...");
    }

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((EVENT_CUSTOM, raw_content)) => handle_subcommand_custom(raw_content),
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
        Some(Node::new(Category::Event(Event::Custom(contents))))
    }
}
