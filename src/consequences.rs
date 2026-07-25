use std::{collections::HashSet, net::IpAddr};

use clap::ArgMatches;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    CONSEQUENCE_CUSTOM, CONSEQUENCE_INFO_COMPUTER, CONSEQUENCE_INFO_CREDENTIALS,
    CONSEQUENCE_INFO_DOMAIN, CONSEQUENCE_INFO_FILE, CONSEQUENCE_INFO_FIREWALL,
    CONSEQUENCE_INFO_HONEYPOT, CONSEQUENCE_INFO_IP, CONSEQUENCE_INFO_SERVICE,
    CONSEQUENCE_INFO_SOFTWARE, CONSEQUENCE_INFO_VIRTUAL_MACHINE, CONSEQUENCE_INFO_VULNERABILITY,
    DEBUG_MODE, MAX_CHARS_CUSTOM_REPORT,
    information::{Computer, InfoClass, InfoRef, Service, Software},
    node::{Category, Node, State},
    questions::{ask_bool_question, ask_options_question},
    standardize_name,
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
        Some((CONSEQUENCE_INFO_SERVICE, raw_content)) => {
            handle_subcommand_service(state, raw_content)
        }
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
            print!("No node has been created. ");
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
        eprint!("Error: \"contents\" is empty. ");
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

    let name: &String = if let Some(arg_name) = raw_content.get_one::<String>("name") {
        arg_name
    } else {
        eprint!("Error: Could not obtain \"name\" argument. ");
        return Vec::new();
    };
    let new_computer: Computer = Computer::new(name.as_str());

    /*
    
    let arg_port: Vec<u16> = raw_content
        .get_many::<String>("port")
        .unwrap_or_default()
        .filter_map(|port: &String| port.parse::<u16>().ok())
        .collect::<Vec<u16>>();

    new_computer.ports = arg_port;
    */

    let id: usize = if let Some(v) = state.add_computer(new_computer) {
        v
    } else {
        eprint!("Error: Computer with \"computer_tag\" (name) = {name} already exists. ");
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
            eprint!("Error: Could not obtain \"computer_tag\" argument. ");
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
            eprint!("Error: Could not find computer wuth \"computer_tag\" = {computer_tag}. ");
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
        eprint!("Error: Could not obtain \"name\" argument. ");
        return Vec::new();
    };

    let arg_descr: &str = raw_content
        .get_one::<String>("description")
        .map_or("", |name| name.as_str());

    let arg_comp_name: Option<&String> = raw_content.get_one::<String>("computer_name");
    let computers_id_opt: Option<usize> = match arg_comp_name {
        Some(comp_name) => {
            let std_name: String = standardize_name(comp_name);
            let comp_id: Option<usize> = state.get_computer_id(&std_name);
            if comp_id.is_none() {
                eprint!("Error: Could not find a computer with name {std_name} . Aborting. ");
                return Vec::new();
            }
            comp_id
        }
        None => None,
    };

    let arg_version: Option<String> = raw_content.get_one::<String>("version").cloned();

    let new_software: Software = Software::new(arg_name.as_str(), arg_descr, arg_version.clone());

    let id: usize = if let Some(id) = state.add_software(new_software, computers_id_opt) {
        id
    } else {
        eprint!(
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

fn handle_subcommand_service(state: &mut State, raw_content: &ArgMatches) -> Vec<Node> {
    /*
        1. Get name of service
        2. Get the ids of computer
             - Basic case
             - Regex case
    */

    let arg_name: String = if let Some(name) = raw_content.get_one::<String>("name") {
        standardize_name(name)
    } else {
        eprintln!("Error: Could not obtain name argument. ");
        return Vec::new();
    };

    #[allow(clippy::option_if_let_else, reason = "Normal version is better")]
    let arg_comp_name: &str = match raw_content.get_one::<String>("computer_name") {
        Some(v) => v.as_str(),
        None => unreachable!(
            "Error: Did not find \"computer_name\" argument but it was requiered. Aborting. No actions were taken. "
        ),
    };

    let use_regex: bool = raw_content.get_flag("regex");

    let computers_id: Vec<usize> = if use_regex {
        let re: Regex = match Regex::new(arg_comp_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "Error: Could nor parse regex expression. Aborting. No actions were taken. Error of the regex: \n{e}"
                );
                return Vec::new();
            }
        };

        let mut matched_computers: Vec<usize> = Vec::new();
        for (i, computer) in state.information.computers.iter().enumerate() {
            if re.is_match(&computer.name) {
                matched_computers.push(i);
                println!(
                    "{}.  Computer \"{}\" \t(id: {i})",
                    matched_computers.len(),
                    computer.name
                );
            }
        }

        if matched_computers.is_empty() {
            // warn user and early reutrn
            print!("Warning: The pattern \"{arg_comp_name}\" had 0 matches. ");
            return Vec::new();
        }

        matched_computers
    } else {
        let std_name: String = standardize_name(arg_comp_name);
        let id_opt: Option<usize> = state.get_computer_id(&std_name);
        let comp_id: usize = if let Some(id) = id_opt {
            id
        } else {
            eprint!("Error: Could not find a computer with name {std_name} . Aborting. ");
            return Vec::new();
        };

        vec![comp_id]
    };

    let arg_port: u16 = if let Some(port) = raw_content.get_one::<String>("port") {
        match port.parse::<u16>() {
            Ok(v) => v,
            Err(e) => {
                eprint!("Could not parse the \"port\" argument. Error: {e:?} ");
                return Vec::new();
            }
        }
    } else {
        eprint!("Error: Could not obtain port argument. ");
        return Vec::new();
    };

    let arg_software: Option<String> = raw_content
        .get_one::<String>("software_name")
        .map(|s: &String| standardize_name(s));

    let software: Option<usize> = if let Some(software_name) = arg_software {
        let software_id_opt: Option<usize> =
            service_get_software(state, &software_name, &computers_id);
        if software_id_opt.is_none() {
            return Vec::new();
        }
        software_id_opt
    } else {
        None
    };

    // Alredy verified manually the invariants of the structure
    let service: Service = Service {
        name: arg_name,
        port: arg_port,
        software,
    };

    let mut ret: Vec<Node> = Vec::with_capacity(computers_id.len());
    for id in computers_id {
        let idx: usize = state
            .add_service(service.clone(), id)
            .expect("The ids are always valid, add_service cannot fail. ");
        let new_node: Node = Node::new(Category::Consequence(Consequence::NewInformation(
            InfoRef {
                index: idx,
                class: InfoClass::Service,
            },
        )));
        ret.push(new_node);
    }

    return ret;
}

fn service_get_software(
    state: &mut State,
    software_name: &str,
    computers_id: &Vec<usize>,
) -> Option<usize> {
    /*
       1. Search all the software options
            - If there is only one, use that one
                - Ask to add if it does not exist in the computer's software
            - If there are none warn the user and return error
            - If there are multiple options:

        2. Obtain union and intersecion of the *used* software version in the computers
             - Case: empty union
             - Case: non-empty union but empty intersection
             - Case: intersection with 1 element
             - Case: intersection multiple elements
        3. Select behaviour:
        - Auto-choose (fast mode)
             - Debug mode: Display decision procedure
            Note: if needed also ask for addition of the software in computers

        - Manual selection
             - Following question: Display options:
                 - Only intersection ({num} elements)
                 - Only union ({num} elements)
                 - Everything ({num} elements)
                Note: for options 2 and 3 also ask for addition of the software in computers
        - Abort
    */

    // Get all of the versions of the software (and it's id )
    let all_software: Vec<(usize, &Software)> = state
        .information
        .software
        .iter()
        .enumerate()
        .filter(|s| s.1.name == software_name)
        .collect::<Vec<(usize, &Software)>>();

    if all_software.is_empty() {
        eprint!("There does not exist a software with the name \"{software_name}\" . Aborting. ");
        return None;
    }
    if all_software.len() == 1 {
        let software_id: usize = all_software.first().expect("must exist").0;

        // Check if all computers have the software installed

        let mut all_installed: bool = true;
        for &comp_id in computers_id {
            let computer: &Computer = &state.information.computers[comp_id];
            let contains_software: bool = computer
                .software
                .iter()
                .map(|&soft_id| &state.information.software[soft_id])
                .any(|s: &Software| s.name == software_name);
            if !contains_software {
                println!(
                    "We found that the computer \"{}\" (id: {comp_id}) does not have the software \"{software_name}\" installed. There may be more cases like this one. ",
                    computer.name
                );
                all_installed = false;
                break;
            }
        }

        if all_installed {
            // there is only 1 option and all the computers use it, we can return early
            return Some(software_id);
        }

        // Ask to add if it does not exist in the computer's software
        let question: String =
            format!("Do you wish to add \"{software_name}\" in the list of installed software? ");
        let awnser: bool = ask_bool_question(&question);

        let mut added_software_count: i32 = 0;
        if awnser {
            // check all computera again, but now add the software
            for &comp_id in computers_id {
                let computer: &mut Computer = &mut state.information.computers[comp_id];
                let contains_software: bool = computer
                    .software
                    .iter()
                    .map(|&soft_id| &state.information.software[soft_id])
                    .any(|s: &Software| s.name == software_name);

                if !contains_software {
                    computer.software.push(software_id);

                    added_software_count += 1_i32;
                    if DEBUG_MODE {
                        println!(
                            "{added_software_count}.  Software added to the computer \"{}\" (id: {comp_id})",
                            computer.name
                        );
                    }
                }
            }
        }
        println!("The software was added to {added_software_count} computers. ");
        return Some(software_id);
    }
    // Case: multiple software options.

    let all_software_ids: Vec<usize> = all_software.iter().map(|(x, _)| *x).collect::<Vec<usize>>();

    return service_select_software_from_multiple(
        state,
        software_name,
        computers_id,
        all_software_ids,
    );
}

// Function made to break up larger function
fn service_select_software_from_multiple(
    state: &mut State,
    software_name: &str,
    computers_id: &Vec<usize>,
    all_software_ids: Vec<usize>,
) -> Option<usize> {
    let (intersection, union) = {
        let software_lists = computers_id.iter().filter_map(|c_id: &usize| {
            let comp_id: usize = *c_id;
            state
                .information
                .computers
                .get(comp_id)
                //.map(|c: &Computer| (comp_id, &c.software))
                .map(|c: &Computer| &c.software)
        });

        let hashsets = software_lists
            .map(|s_list: &Vec<usize>| -> HashSet<usize> { HashSet::from_iter(s_list.clone()) });

        let mut intersection: Vec<usize> = hashsets
            .clone()
            .reduce(|a: HashSet<usize>, b: HashSet<usize>| a.intersection(&b).copied().collect())
            .map(|hashmap: HashSet<usize>| hashmap.iter().copied().collect::<Vec<usize>>())
            .unwrap_or(vec![]);

        let mut union: Vec<usize> = hashsets
            .reduce(|a: HashSet<usize>, b: HashSet<usize>| a.union(&b).copied().collect())
            .map(|hashmap: HashSet<usize>| hashmap.iter().copied().collect::<Vec<usize>>())
            .unwrap_or(vec![]);

        // sort for consistent results
        intersection.sort_unstable();
        union.sort_unstable();

        (intersection, union)
    };

    let autoselect: bool = {
        let question_behaviour: &str = "There are multiple versions of the software in use. \
            Wich version should be used in the Service object? ";
        let options_behaviour: [&str; 3] = [
            "Autoselect version (fast mode)",
            "Manually select version to use. ",
            "Abort",
        ];

        let awnser_behaviour: usize = ask_options_question(question_behaviour, &options_behaviour);

        match awnser_behaviour {
            1 => true,
            2 => false,
            3 => return None,
            _ => unreachable!("This branch should be unreachable. "),
        }
    };

    if autoselect {
        if let Some(first) = intersection.first() {
            if DEBUG_MODE {
                println!(
                    "The intersection contains at {} element(s). We will use the first element of the intersection set. ",
                    intersection.len()
                );
            }
            return Some(*first);
        }

        #[allow(clippy::option_if_let_else, reason = "Normal version is better. ")]
        let selected_id: usize = if let Some(first) = union.first() {
            if DEBUG_MODE {
                println!(
                    "The union contains at {} element(s). We will use the first element of the union set. ",
                    union.len()
                );
            }
            *first
        } else {
            if DEBUG_MODE {
                println!(
                    "Neither the intersection nor union contain elements, we will use a version that none of the computers have. "
                );
            }

            // use from all_software
            let id: usize = *all_software_ids
                .first()
                .expect("`all_software` must be non-empty. ");
            id
        };

        add_software_to_computers(state, selected_id, software_name, computers_id);
        return Some(selected_id);
    }
    // maual selection

    return Some(service_software_manual_selection(
        state,
        intersection,
        union,
        all_software_ids,
        software_name,
        computers_id,
    ));
}

// Function made to break up larger function
fn service_software_manual_selection(
    state: &mut State,
    intersection: Vec<usize>,
    union: Vec<usize>,
    all_software_ids: Vec<usize>,
    software_name: &str,
    computers_id: &Vec<usize>,
) -> usize {
    // select the list of versions you want to select from
    let awnser_collection: usize = {
        let question_collection: &str = "Select a set to reduce searc space. \n - \"intersection\" contains \
                the versions that are in all the computers\n - \"union\" contains the versions that \
                are at least on 1 computer. \n - The last option contains all versions of that software. \
                \n\tSelection: ";

        let option_intersection: String = format!(
            "Select an element from the intersection (contains {} elements)",
            intersection.len()
        );
        let option_union: String = format!(
            "Select an element from the union (contains {} elements)",
            union.len()
        );
        let option_all: String = format!(
            "Select an element from all possible choices (contains {} elements)",
            all_software_ids.len()
        );

        let options_collection: [&str; 3] = [
            option_intersection.as_str(),
            option_union.as_str(),
            option_all.as_str(),
        ];

        ask_options_question(question_collection, &options_collection)
    };

    let collection: Vec<usize> = match awnser_collection {
        1 => intersection,
        2 => union,
        3 => all_software_ids,
        _ => unreachable!("This branch should be unreachable. "),
    };

    let version_list: Vec<(usize, &str)> = {
        let mut list: Vec<(usize, &str)> = collection
            .iter()
            .map(|&id| (id, &state.information.software[id].version))
            .map(|(id, version)| -> (usize, &str) {
                let ver_str: &str = version.as_ref().map_or("None", |v: &String| v.as_str());
                (id, ver_str)
            })
            .collect::<Vec<(usize, &str)>>();
        list.sort_by_key(|(_, ver)| *ver);
        list
    };

    let options_version: Vec<&str> = version_list
        .iter()
        .map(|x: &(usize, &str)| x.1)
        .collect::<Vec<&str>>();

    let question_version: &str = "Select the version to use: ";
    let awnser_version: usize = ask_options_question(question_version, &options_version);

    let final_index_software: usize = version_list[awnser_version - 1].0;
    add_software_to_computers(state, final_index_software, software_name, computers_id);
    return final_index_software;
}

fn add_software_to_computers(
    state: &mut State,
    selected_id: usize,
    software_name: &str,
    computers_id: &Vec<usize>,
) {
    // does not check if software is not contained in computrs, it is assumed
    let software_version_selected: Option<&String> =
        state.information.software[selected_id].version.as_ref();
    let question_add_software: String = format!(
        "The software selected {software_name} v: {:?} is not included as part of the software of all the computers affected. Do you wish to add the selected software to the computers? ",
        software_version_selected.map_or("None", std::string::String::as_str)
    );

    let add_software: bool = ask_bool_question(&question_add_software);
    if add_software {
        for &c_id in computers_id {
            let computer: &mut Computer = &mut state.information.computers[c_id];
            let contains_software: bool = computer.software.contains(&selected_id);
            if !contains_software {
                // add the software to the computer
                computer.software.push(selected_id);
            }
        }
    }
}
