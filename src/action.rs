use clap::ArgMatches;
use serde::{Deserialize, Serialize};

use crate::{
    ACTION_CUSTOM, DEBUG_MODE, get_stdin,
    node::{Category, KnownCommnad, Node, State},
};


#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// A custom action, the user may store any string
    Custom(String),
    /// The execution of a command (the output is sored in another node)
    Command(String),
    KnownCommnad(KnownCommnad),
    // /// Execution of a script, string is for the code
    // Script(String)
}


impl ToString for Action {
    fn to_string(&self) -> String {
        match self {
            Action::Custom(content) => format!("custom: {content}"),
            _ => todo!("Currently not implemented. ")
        }
    }
}

/// Processes the action
///
/// # Panics
///
/// Panics if:
///  - No subcommand was passed
///  - An unrecognized subcommand was passed.
///  - Due to other errors caused by the different subcommands.
pub fn process_action(sub_match: &ArgMatches, state: &mut State) {
    if DEBUG_MODE {
        println!("Action detected! Processing...");
    }

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((ACTION_CUSTOM, raw_content)) => handle_subcommand_custom(raw_content),
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
    let contents: String = handle_general_custom(raw_content);

    if contents.is_empty() {
        None
    } else {
        Some(Node::new(Category::Action(Action::Custom(contents))))
    }
}

/// Obtains the string information necessary for the custom subcommands
///
/// Used in both Action, Consequence and Event
#[must_use]
pub fn handle_general_custom(raw_content: &ArgMatches) -> String {
    // Abstracted because a lot of code was the same. Done here because it's part of both Action, Consequence and Event
    /*
       We need to check if we got the values from the argument or stdin and handle each case:
        - Both argument and stdin: send warning, concatenate inputs and save.
        - Neither argument not stdin: send error message and do nothing.
    */

    // content obtained from the argument
    let content_arg_opt: Option<&String> = raw_content.get_one::<String>("content");
    let exists_content_arg: bool = !content_arg_opt.is_none_or(|s: &String| s.trim().is_empty());
    let mut content_arg: String = content_arg_opt.cloned().unwrap_or_default();

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



