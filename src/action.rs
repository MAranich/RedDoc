use std::{
    env::{self},
    io::Write,
    process::{Command, Stdio},
};

use clap::ArgMatches;
use serde::{Deserialize, Serialize};

use crate::{
    ACTION_CUSTOM, DEBUG_MODE, MAX_CHARS_CUSTOM_REPORT,
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
            _ => todo!("Currently not implemented. "),
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
pub fn process_action(sub_match: &ArgMatches, stdin: &str, state: &mut State) {
    if DEBUG_MODE {
        println!("Action detected! Processing...");
    }

    let new_node: Option<Node> = match sub_match.subcommand() {
        Some((ACTION_CUSTOM, raw_content)) => handle_subcommand_custom(raw_content, stdin),
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

fn handle_subcommand_custom(raw_content: &ArgMatches, stdin: &str) -> Option<Node> {
    let contents: String = handle_general_custom(raw_content, stdin);

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
pub fn handle_general_custom(raw_content: &ArgMatches, stdin: &str) -> String {
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

    let exists_std_input: bool = !stdin.trim().is_empty();

    let content: String = match (exists_content_arg, exists_std_input) {
        (true, true) => {
            println!(
                "Info: There were inputs on both argument and stdin. The stdin was concatenated to the argument. "
            );
            // add some space
            content_arg.push_str("\n\n");

            content_arg.push_str(stdin);
            content_arg
        }
        (true, false) => content_arg,
        (false, true) => String::from(stdin),
        (false, false) => {
            eprintln!(
                "Error: No information was provided through the standard input (piped) nor a as raw text. \nNo action was taken. "
            );
            return String::new();
        }
    };

    return content;
}

/// Processes the command and stores the adequate representation on the state.
///
/// Quotes can be used so everything is treated as a single command: 
/// `"ls -la | grep meow"`
/// 
/// # Known problems
/// 
///  - Programs that requiere a terminal will fail. 
///      - Example: `nano`
///  - Programs that execute forever will also not terminate nor record data. 
///      - Example: `ping` (without `-c`)
/// 
/// # Panics
///
/// Panics if arguments contain invalid Uncode data.
/// 
pub fn process_command(stdin: &str) {
    /*
       For this we need to:
       1. Store the command execution action
       2. Execute the command given in the args
            - With the provided args and stdin
       3. Store the result of the execution as a consequence.
    */

    // Get command as a single string
    let args_vec: Vec<String> = env::args_os()
        .skip(2)
        .map(|x: std::ffi::OsString| {
            x.into_string()
                .expect("Invalid UTF-8 in args. ")
        }).collect();
    // args are all arguments afrer the *command* argument

    if args_vec.is_empty() {
        // early return
        eprintln!("No command passed. Aborting. ");
        return;
    }

    // Join arguments into a single string
    let args: String = args_vec.join(" ");

    // get child handle
    let mut child: std::process::Child = Command::new("sh")
    .arg("-c")        
    .arg(args.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Could not spawn process in `process_command`. ");

    // Pass stdin
    if let Some(mut stdin_handle) = child.stdin.take() {
        let result: Result<(), std::io::Error> = stdin_handle.write_all(stdin.as_bytes()); 
        if let Err(e) = result {
            eprintln!("Failed to write to stdin in `process_command`. Was attempting to execute command |sh -c {args}| . Error: \n{e}"); 
        }

        drop(stdin_handle);
    }

    // Wait for process to exit and store output
    let result: Result<std::process::Output, std::io::Error> = child.wait_with_output();

    match result {
        Ok(output) => {
            // print the output in screes so user can see it
            if output.status.success() {
                let out_str: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
                print!("{out_str}");
            } else {
                let e: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stderr);
                let out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
                eprint!("There was an error with the command |{args}| . ");

                let empty_e: bool = e.trim().is_empty(); 
                let empty_out: bool = out.trim().is_empty(); 
                if empty_e && empty_out {
                    eprint!("Error: \n{e}\nOutput: \n{out}"); 
                } else if empty_e {
                    eprint!("Error: \n{e}"); 
                } else {
                    // empty_out
                    eprint!("Output: \n{out}"); 
                }
                
            }
        }
        Err(e) => {
            eprintln!(
                "There was an IO error while executing command |sh -c {args}| . No data was stored. Error: \n{e}"
            );
        }
    }

    // todo!();
}
