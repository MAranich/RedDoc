use std::net::IpAddr;

use clap::ArgMatches;
use serde::{Deserialize, Serialize};

use crate::{
    CONSEQUENCE_CUSTOM,
    CONSEQUENCE_INFO_COMPUTER,
    CONSEQUENCE_INFO_CREDENTIALS,
    CONSEQUENCE_INFO_DOMAIN,
    CONSEQUENCE_INFO_FILE,
    CONSEQUENCE_INFO_FIREWALL,
    CONSEQUENCE_INFO_HONEYPOT,
    CONSEQUENCE_INFO_IP,
    // CONSEQUENCE_INFO_PORT,
    CONSEQUENCE_INFO_SERVICE,
    CONSEQUENCE_INFO_SOFTWARE,
    CONSEQUENCE_INFO_VIRTUAL_MACHINE,
    CONSEQUENCE_INFO_VULNERABILITY,
    DEBUG_MODE,
    MAX_CHARS_CUSTOM_REPORT,
    information::{Computer, InfoRef, Software},
    node::{Category, Node, State},
};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Consequence {
    Custom(String),
    /// Output of a command and stderr
    Command(String, String),
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

/// Processes the consequence
///
/// # Panics
///
/// Panics if:
///  - No subcommand was passed
///  - An unrecognized subcommand was passed.
///  - Due to other errors caused by the different subcommands.
pub fn process_consequences(sub_match: &ArgMatches, stdin: &str, state: &mut State) {
    if DEBUG_MODE {
        println!("Consequence detected! Processing...");
    }

    let new_nodes: Vec<Node> = match sub_match.subcommand() {
        Some((CONSEQUENCE_CUSTOM, raw_content)) => handle_subcommand_custom(raw_content, stdin),
        Some((CONSEQUENCE_INFO_IP, raw_content)) => handle_subcommand_ip(state, raw_content),
        Some((CONSEQUENCE_INFO_COMPUTER, raw_content)) => {
            handle_subcommand_computer(state, raw_content)
        }
        //Some((CONSEQUENCE_INFO_PORT, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_SOFTWARE, raw_content)) => {
            handle_subcommand_software(state, raw_content)
        }
        Some((CONSEQUENCE_INFO_SERVICE, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_DOMAIN, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_VULNERABILITY, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_FIREWALL, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_FILE, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_HONEYPOT, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_VIRTUAL_MACHINE, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_CREDENTIALS, _raw_content)) => todo!(),
        Some(_) => panic!("Unrecognized action subcommand provided"),
        None => panic!("No action subcommand provided. "),
    };

    if new_nodes.is_empty() {
        if DEBUG_MODE {
            println!("No node has been created. ");
        }
        return;
    }

    for (i, node) in new_nodes.iter().enumerate() {
        if DEBUG_MODE {
            println!("New node {i}: \n{node:?}");
        }

        state.add_node(node);
    }
}

fn handle_subcommand_custom(raw_content: &ArgMatches, stdin: &str) -> Vec<Node> {
    let contents: String = crate::action::get_content(raw_content, stdin);

    if contents.is_empty() {
        if DEBUG_MODE {
            println!("No node has been created. ");
        }
        Vec::new()
    } else {
        vec![Node::new(Category::Consequence(Consequence::Custom(
            contents,
        )))]
    }
}

fn handle_subcommand_computer(state: &mut State, raw_content: &ArgMatches) -> Vec<Node> {
    // TODO: add services flag
    /*
       1. Get name
       2. Crete computer
       3. Fill found ports
       4. Add computer to state to obtain id
       5. Add all ips to state
       6. (Unimplemented) Add services
       7. return node new computer
    */

    let mut new_computer: Computer = if let Some(arg_name) = raw_content.get_one::<String>("name") {
        Computer::new(arg_name.as_str())
    } else {
        if DEBUG_MODE {
            println!("No node has been created. ");
        }
        return Vec::new();
    };

    let arg_port: Vec<u16> = raw_content
        .get_many::<String>("port")
        .unwrap_or_default()
        .filter_map(|port: &String| port.parse::<u16>().ok())
        .collect::<Vec<u16>>();

    new_computer.ports = arg_port;

    let id: usize = if let Some(v) = state.add_computer(new_computer) {
        v
    } else {
        if DEBUG_MODE {
            println!("No node has been created. ");
        }
        return Vec::new();
    };

    raw_content
        .get_many::<String>("ip")
        .unwrap_or_default()
        .filter_map(|ip: &String| ip.as_str().parse::<IpAddr>().ok())
        .for_each(|ip: IpAddr| {
            let _ = state.add_ip(ip, id);
        });

    return vec![Node::new(Category::Consequence(
        Consequence::NewInformation(InfoRef {
            index: id,
            class: crate::information::InfoClass::Computer,
        }),
    ))];
}

fn handle_subcommand_ip(state: &mut State, raw_content: &ArgMatches) -> Vec<Node> {
    // get the id of the computer passed as argument or return empty vec + err message
    let computer_id: usize = {
        let computer_tag_opt: Option<&String> = raw_content.get_one::<String>("computer");
        let computer_tag: &String = if let Some(v) = computer_tag_opt {
            v
        } else {
            if DEBUG_MODE {
                println!("No node has been created. ");
            }
            return Vec::new();
        };

        let computer_id_opt: Option<usize> = state
            .information
            .computers
            .iter()
            .position(|c: &Computer| c.name.eq(computer_tag));

        if let Some(v) = computer_id_opt {
            v
        } else {
            if DEBUG_MODE {
                println!("No node has been created. ");
            }
            return Vec::new();
        }
    };

    let ret: Vec<Node> = raw_content
        .get_many::<String>("ip_dir")
        .unwrap_or_default()
        .filter_map(|ip: &String| ip.as_str().parse::<IpAddr>().ok())
        .filter_map(|ip: IpAddr| {
            let id_opt: Option<usize> = state.add_ip(ip, computer_id);
            // None = ignore duplicated ips
            id_opt.map(|id: usize| {
                Node::new(Category::Consequence(Consequence::NewInformation(
                    InfoRef {
                        index: id,
                        class: crate::information::InfoClass::IP,
                    },
                )))
            })
        })
        .collect::<Vec<Node>>();

    return ret;
}

fn handle_subcommand_software(state: &mut State, raw_content: &ArgMatches) -> Vec<Node> {
    let arg_name: &String = if let Some(name) = raw_content.get_one::<String>("name") {
        name
    } else {
        eprintln!("Error: Could not obtain name argument. ");
        return Vec::new();
    };

    let arg_descr: String = raw_content
        .get_one::<String>("description")
        .cloned()
        .unwrap_or_default();

    let arg_version: Option<String> = raw_content.get_one::<String>("version").cloned();

    let new_software: Software =
        Software::new(arg_name.as_str(), arg_descr.as_str(), arg_version.clone());

    let id: usize = if let Some(id) = state.add_software(new_software) {
        id
    } else {
        eprintln!(
            "Error: New software could not be added. The software with name {arg_name} and version {arg_version:?} already exists. Aborting. "
        );
        return Vec::new();
    };

    // TODO: allow adding vulnerabilities

    let ret: Node = Node::new(Category::Consequence(Consequence::NewInformation(
        InfoRef {
            index: id,
            class: crate::information::InfoClass::Software,
        },
    )));

    return vec![ret];
}
