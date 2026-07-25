//! # `RedDoc`
//!
//! `RedDoc` is a tool for documentation targeted to cybersecurity profesionals.
//!
//! TODO: complete documentation
//!
//! ## Naming
//!
//! When giving a name to something, you can give it any name you want, but to avoid
//! errors whan comparing strings, names are **standardized**. For example, "Linux" and "linux"
//! should be treated as the same element, but their binary representation is different.
//! To avoid this problem, names are standardized before being used. The following rules are
//! applied:
//! 1. Set all characters to lowercase (when it applies)
//! 2. Discard non-ascii characters
//! 3. Discard control characters
//! 4. Trim (remove whitespace at start and end)
//! 5. Limit the length of the name
//!      - (Disabled by default)
//!
//!
//!
use atty::Stream;
use clap::{Arg, ArgAction, Command, command};
use std::{
    env,
    hash::{DefaultHasher, Hash, Hasher},
    io::{self, Read},
    path::Path,
};

use crate::{
    action::{process_action, process_command},
    consequences::process_consequences,
    event::process_event,
    node::State,
    questions::ask_bool_question,
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
const CONSEQUENCE_INFO_COMPUTER: &str = "computer";
const CONSEQUENCE_INFO_IP: &str = "ip";
// const CONSEQUENCE_INFO_PORT: &str = "port";
const CONSEQUENCE_INFO_DOMAIN: &str = "domain";
const CONSEQUENCE_INFO_SERVICE: &str = "service";
const CONSEQUENCE_INFO_SOFTWARE: &str = "software";
const CONSEQUENCE_INFO_VULNERABILITY: &str = "vulnerability";
const CONSEQUENCE_INFO_FIREWALL: &str = "firewall";
const CONSEQUENCE_INFO_FILE: &str = "file";
const CONSEQUENCE_INFO_HONEYPOT: &str = "honeypot";
const CONSEQUENCE_INFO_VIRTUAL_MACHINE: &str = "virtual_machine";
const CONSEQUENCE_INFO_CREDENTIALS: &str = "credentials";

// Sub commands for events: **********************************************
const EVENT_CUSTOM: &str = "custom";
const EVENT_CUSTOM_ABOUT: &str =
    "Introduce any text you want to be saved between quotes. \"Hello world!\"

This option can be used to store: 
 - Comments
 - Scenatios not accounted in the program. ";

const MAX_CHARS_CUSTOM_REPORT: usize = 64;
const CONF_NAME_ALLOW_NON_ASCII: bool = false;
const CONF_NAME_CAST_TO_LOWERCASE: bool = true;
/// 0 = no limit
const CONF_NAME_MAX_LENGTH: usize = 0;
const CONF_VERSION_MAX_LENGTH: usize = 50;

pub mod action;
pub mod consequences;
pub mod event;
pub mod information;
pub mod node;
pub mod questions;
pub mod report;

// ****************************

const DEBUG_MODE: bool = true;

#[allow(
    clippy::too_many_lines,
    reason = "The main function contains the Clap builder that parses the inputs. Breaking this into multiple functions would decrease redability. "
)]
fn main() {
    /*
       The subcommand *command* needs to be parsed differently to the resto of
       commands because clap is not able to correcly parse all commands.

       For example, clap would parse `rd command ls -la` with a "-la" flag,
       wich is not the intended use.

       For this reason we will detect the use of the subcommand *command* and parse it manually.
    */

    let project_path: &Path = Path::new("./project.json");
    let report_path: &Path = Path::new("./report.md");

    let mut state: State = State::get_state(project_path);
    let original_state_hash: u64 = {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        state.hash(&mut hasher);
        hasher.finish()
    };

    // ////////////////

    let raw_arguments: env::ArgsOs = env::args_os();
    // `stdin == ""` => Nothing was piped
    let stdin_binding: String = get_stdin();
    let stdin: &str = stdin_binding.as_str();

    if let Some(sub_command) = raw_arguments.into_iter().nth(1) {
        let second_arg: String = sub_command.into_string().unwrap_or_default();
        let is_second_arg_command: bool = SUB_COMMAND_ALIAS.iter().any(|&s| s == second_arg);
        if is_second_arg_command {
            let command_nodes: Option<(node::Node, node::Node)> = process_command(stdin);
            if let Some((input_node, output_node)) = command_nodes {
                state.add_node(&input_node);
                state.add_node(&output_node);
            }

            let updated_state_hash: u64 = {
                let mut hasher: DefaultHasher = DefaultHasher::new();
                state.hash(&mut hasher);
                hasher.finish()
            };
            if updated_state_hash == original_state_hash {
                println!("No changes were made. ");
                return;
            }

            let save_result: Result<(), std::io::Error> = State::save_state(project_path, &state);
            if let Err(e) = save_result {
                eprintln!("There has been an error storing the state. Error: \n{e:?}");
            }
            return;
        }
    }

    let ttp_option: Arg = Arg::new("ttp")
        .global(true)
        .long("tactics_techniques_procedures")
        .required(false)
        .action(ArgAction::Append)
        .alias("ttp")
        .alias("tactic")
        .alias("technique")
        .alias("procedure")
        .alias("ttp_category")
        .alias("ttp_cat")
        .long_help("TTPs (tactics, techniques and procedures) are strategies used by attackers to obtain an advantage and advance on their objectives. \
        RedDoc uses the ma matrix as the base of all possible TTPs. See https://attack.mitre.org/ for more information. \n\n\
        There are multiple categories 
        ")
        .help("The TTP used to perform the action. ");

    let matches: clap::ArgMatches = command!()
        .subcommand(
            Command::new(SUB_ACTION)
                .about(ABOUT_ACTION_CLAP)
                .alias("act")
                .alias("a")
                .arg(ttp_option)
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
                        .arg(Arg::new("content").required(true))
                        .about(CONSEQUENCE_CUSTOM_ABOUT),
                    ).subcommand(
                        Command::new(CONSEQUENCE_INFO_COMPUTER)
                        .arg(Arg::new("name"))
                        .arg(Arg::new("ip").help("An ipv4 or ipv6 ip adress. Can be used multiple times. "))
                        //.arg(Arg::new("port").help("An open port. Can be used multiple times. "))
                        .arg(Arg::new("os").alias("operating_system").help("The name of the operating system. Must be previusly declared as software. "))
                        .about("Intregrate the existance of a new computer into the model. \nThis is stating that a given computer exists. The argument is a name/tag you give to it. `red_doc cons computer objectie_42`"),
                )
                .subcommand(
                    Command::new(CONSEQUENCE_INFO_IP)
                        .arg(
                            Arg::new("ip_dir")
                            .help("One or many IP directions. Can be either IPv4 or IPv6. ")
                            .action(ArgAction::Append)
                            .required(true)
                        ).arg(
                            Arg::new("computer")
                            .help("The name of the computer. (must already exist)")
                            .required(true)
                        ).about("Relate the provided IP to a computer. "),
                )
                /* 
                .subcommand(Command::new(CONSEQUENCE_INFO_PORT)
                    .arg(Arg::new("ports").action(ArgAction::Append).required(true))
                    .arg(Arg::new("computer").required(true))
                    .about("Define wich ports are open for a certain computer. "),),
                */
                .subcommand(
                    Command::new(CONSEQUENCE_INFO_SOFTWARE)
                        .arg(Arg::new("name").required(true))
                        .arg(
                            Arg::new("computer_name")
                            .required(false)
                            .help("The name of the computer. (must already exist)")
                        ).arg(
                            Arg::new("description")
                                .short('d')
                                .long("description")
                                .aliases(["desc", "des"])
                                .help("Description of the software or other relevant information you may want to store. ")
                        ).arg(
                            Arg::new("version")
                                .short('v')
                                .long("version")
                                .aliases(["vers", "ver"])
                                .help("The version of the software. ")
                        ).about("Assert that a certain computer has some software. "),
                )
                .subcommand(
                Command::new(CONSEQUENCE_INFO_SERVICE)
                        .arg(
                            Arg::new("name")
                            .required(true)
                            .help("The name of the service offered. May be repeated. ")
                        ).arg(
                            Arg::new("computer_name")
                            .required(true)
                            .help("The computer must have already been created. ")
                        ).arg(
                            Arg::new("software_name")
                            .required(false)
                            .help("The software must have already been created. ")
                            .long_help("The software that os providing the server. "))
                        .arg(
                            Arg::new("port")
                                .short('p')
                                .long("port")
                                .help("In wich port is the service offered. ")
                        ).arg(
                            Arg::new("regex")
                            .short('r')
                            .long("regex")
                            .action(ArgAction::SetTrue)
                            .help("Treat \"computer_name\" as a regex expression and state theat the service is offered by all computers with a name that matches the regex. ")
                        ).about("State that some software is offered as a service in a computer. "),
                )
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
        .subcommand(Command::new("debug").about("For development and debug pruposes only. "))
        .get_matches();

    // //////////

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

    let updated_state_hash: u64 = {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        state.hash(&mut hasher);
        hasher.finish()
    };
    if updated_state_hash == original_state_hash {
        println!("No changes were made. ");
        return;
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

#[must_use]
pub fn standardize_name(name: &str) -> String {
    /*
       Operations:
       1. Trim (remove whitespace at start and end)
       2. Discard non-ascii
       3. Discard control characters
       4. Limit max amount of characters (default: unlimited)
       5. Map all characters to lowercase (if aplicable)
    */
    let op_1: std::str::Chars<'_> = name.trim().chars();

    let op_2 = op_1.filter(|c: &char| c.is_ascii() || CONF_NAME_ALLOW_NON_ASCII);

    let op_3 = op_2.filter(|c: &char| !c.is_control());

    let op_4: String = if CONF_NAME_MAX_LENGTH == 0 {
        op_3.collect::<String>()
    } else {
        op_3.take(CONF_NAME_MAX_LENGTH).collect::<String>()
    };

    let ret: String = if CONF_NAME_CAST_TO_LOWERCASE {
        op_4.to_lowercase()
    } else {
        op_4
    };

    return ret;
}

#[must_use]
pub fn standardize_version(name: &str) -> String {
    /*
        We use the same procedure as in standardize_name but we do not set the characters to lowercase.
       Operations:
       1. Trim (remove whitespace at start and end)
       2. Discard non-ascii
       3. Discard control characters
       4. Limit max amount of characters (default: 50)
    */

    let op_1: std::str::Chars<'_> = name.trim().chars();

    let op_2 = op_1.filter(|c: &char| c.is_ascii() || CONF_NAME_ALLOW_NON_ASCII);

    let op_3 = op_2.filter(|c: &char| !c.is_control());

    let ret: String = if CONF_VERSION_MAX_LENGTH == 0 {
        op_3.collect::<String>()
    } else {
        op_3.take(CONF_VERSION_MAX_LENGTH).collect::<String>()
    };

    return ret;
}

pub fn process_debug(_sub_match: &clap::ArgMatches, _stdin: &str, _state: &mut State) {
    println!("================================================");
    println!("======             DEBUG MODE            =======");
    println!("================================================");

    let awnser: bool = ask_bool_question("Awnser yes. ");
    if awnser {
        println!("correct");
    } else {
        println!("incorrect");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standardize_name_as_identity() {
        // strings that should not be modified

        let cases: [&str; 5] = [
            "spinx of the black quartz, judge my vow.",
            "_-abc-_",
            ":str;",
            "",
            "!\"$%&/()=?|@#~{[]}+*^",
        ];
        // Not accepted: ·¿½¬
        for elem in cases {
            let standardized: String = standardize_name(elem);
            assert_eq!(elem, standardized);
        }
    }

    #[test]
    fn standardize_name_as_non_identity() {
        // strings that should be modified

        let cases: [(&str, &str); 4] = [
            (
                "SPINX OF THE BLACK QUARTZ, JUDGE MY VOW.",
                "spinx of the black quartz, judge my vow.",
            ),
            ("·¿½¬", ""),
            ("  untrimmed \n", "untrimmed"),
            ("control_characters\0\n\t\r", "control_characters"),
        ];

        for (elem, expected) in cases {
            let standardized: String = standardize_name(elem);
            assert_eq!(standardized, expected);
        }
    }
}
