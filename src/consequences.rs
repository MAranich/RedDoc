use std::net::IpAddr;

use clap::ArgMatches;
use serde::{Deserialize, Serialize};

use crate::{
    CONSEQUENCE_CUSTOM, CONSEQUENCE_INFO_COMPUTER, CONSEQUENCE_INFO_CREDENTIALS,
    CONSEQUENCE_INFO_DOMAIN, CONSEQUENCE_INFO_FILE, CONSEQUENCE_INFO_FIREWALL,
    CONSEQUENCE_INFO_HONEYPOT, CONSEQUENCE_INFO_IP, CONSEQUENCE_INFO_PORT,
    CONSEQUENCE_INFO_SERVICE, CONSEQUENCE_INFO_SOFTWARE, CONSEQUENCE_INFO_VIRTUAL_MACHINE,
    CONSEQUENCE_INFO_VULNERABILITY, DEBUG_MODE, MAX_CHARS_CUSTOM_REPORT,
    information::{Computer, InfoRef},
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

    let subcommand = sub_match.subcommand();

    if let Some((CONSEQUENCE_INFO_IP, raw_content)) = subcommand {
        // Needs special handling because it supports multiple ips at once.
        let new_nodes = handle_subcommand_ip(state, raw_content);
        return;
    }

    let new_node: Option<Node> = match subcommand {
        Some((CONSEQUENCE_CUSTOM, raw_content)) => handle_subcommand_custom(raw_content, stdin),
        Some((CONSEQUENCE_INFO_COMPUTER, raw_content)) => {
            handle_subcommand_computer(state, raw_content)
        }
        Some((CONSEQUENCE_INFO_PORT, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_DOMAIN, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_SERVICE, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_SOFTWARE, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_VULNERABILITY, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_FIREWALL, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_FILE, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_HONEYPOT, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_VIRTUAL_MACHINE, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_CREDENTIALS, _raw_content)) => todo!(),
        Some((CONSEQUENCE_INFO_IP, raw_content)) => unreachable!("Case already handled. "),
        Some(_) => panic!("Unrecognized action subcommand provided"),
        None => panic!("No action subcommand provided. "),
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
    let contents: String = crate::action::get_content(raw_content, stdin);

    if contents.is_empty() {
        None
    } else {
        Some(Node::new(Category::Consequence(Consequence::Custom(
            contents,
        ))))
    }
}

fn handle_subcommand_computer(state: &mut State, raw_content: &ArgMatches) -> Option<Node> {
    let arg_name: &String = raw_content.get_one::<String>("name")?;

    let arg_ip: Vec<IpAddr> = raw_content
        .get_many::<String>("ip")
        .unwrap_or_default()
        .flat_map(|ip| ip.as_str().parse::<IpAddr>())
        .collect::<Vec<IpAddr>>();

    let arg_port: Vec<u16> = raw_content
        .get_many::<String>("port")
        .unwrap_or_default()
        .flat_map(|port| port.parse::<u16>())
        .collect::<Vec<u16>>();

    // TODO: add services flag
    let new_computer: Computer = Computer {
        name: arg_name.clone(),
        ips: arg_ip,
        ports: arg_port,
        services: Vec::new(),
        is_honeypot: false,
        is_virtualized: (false, None),
        infection_level: crate::information::ComputerControl::None,
        operating_system: None,
    };

    let id: usize = state.add_computer(new_computer)?;

    Some(Node::new(Category::Consequence(
        Consequence::NewInformation(InfoRef {
            index: id,
            class: crate::information::InfoClass::Computer,
        }),
    )))
}

fn handle_subcommand_ip(state: &mut State, raw_content: &ArgMatches) -> Vec<Node> {
    let ret: Vec<Node> = raw_content
        .get_many::<String>("ip")
        .unwrap_or_default()
        .flat_map(|ip: &String| ip.as_str().parse::<IpAddr>())
        .flat_map(|ip: IpAddr| {
            let id_opt: Option<usize> = state.add_ip(ip);
            if let Some(id) = id_opt {
                let new_node: Node = Node::new(Category::Consequence(Consequence::NewInformation(
                    InfoRef {
                        index: id,
                        class: crate::information::InfoClass::IP,
                    },
                )));
                Some(new_node)
            } else {
                // ignore duplicated ips
                None
            }
        })
        .collect::<Vec<Node>>();

    return ret;
}
