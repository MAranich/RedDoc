//!
//! A module dedicated to the structure [Node], wich is the fundamental building block
//! for storing the information.
//!

use crate::{
    action::Action,
    consequences::Consequence,
    event::Event,
    information::{Computer, Information, Service, Software, User, Vulnerability},
};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::read,
    io::{self, ErrorKind, Write},
    net::IpAddr,
    path::Path,
};

/// Basic structure that stores the relevant information
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub time_stamp: DateTime<Utc>,
    pub category: Category,
}

/// The different classes of events that can happen:
///  - [`Category::Action`]: Codifies actions taken by the user
///  - [`Category::Consequence`]: Codifies the consequences of actions.
///  - [`Category::Event`]: Codifies any other fact that cannot be direcly attributed to an action.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Action(Action),
    Consequence(Consequence),
    Event(Event),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnownCommnad {
    None,
} // TODO

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Timeline(pub Vec<Node>);

/// Represents all the information known by the program
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub time_line: Timeline,
    pub information: Information,
}

impl Node {
    #[must_use]
    pub fn new(cat: Category) -> Self {
        return Self {
            time_stamp: Utc::now(),
            category: cat,
        };
    }
}

impl State {
    // const DEFAULT_FILE_NAME: &str = "project.rd";

    /// Reads the contents of the file at the provided `path` and generates a [State] form it.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - There was an error parsing the state.
    ///      - (from JSON to the internal reperesntation)
    ///  - Obtained any error (other than `NotFound`) while reading the file.
    ///
    pub fn get_state<P: AsRef<Path>>(path: P) -> Self {
        // TODO update to add project files and /etc/config file

        let ret: Self = match read(path) {
            Ok(f) => {
                // let contents: String = String::from(f);
                let x: &[u8] = &f[..];
                match serde_json::from_slice::<Self>(x) {
                    Ok(v) => v,
                    Err(e) => panic!("There was an error parsing the state. Error: \n{e:?}"),
                }
            }
            Err(e) => {
                // No file found error.

                match e.kind() {
                    ErrorKind::NotFound => Self::empty(),
                    ErrorKind::PermissionDenied => {
                        panic!("Permission was denied to access file: \n{e:?}")
                    }
                    //ErrorKind::AlreadyExists => unreachable!(),
                    ErrorKind::InvalidInput => panic!("An invalid input was introduced: \n{e:?}"),
                    _ => panic!("An unaccounded error has ocurred: \n{e:?}"),
                }
            }
        };

        return ret;
    }

    /// Saves the state in a file provided by `path`.
    ///
    /// The file is generated if it does not exist.
    ///
    /// # Panics
    ///
    /// Panics if there was an eror generating the JSON.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - There was an error creating/opening the report file.
    /// - There was an error writing into the report file.
    ///
    pub fn save_state<P: AsRef<Path>>(path: P, state: &Self) -> Result<(), io::Error> {
        let state_text: String = match serde_json::to_string(state) {
            Ok(json) => json,
            Err(e) => panic!("Error trasforming data to JSON. Error: \n{e:?}"),
        };

        /*
        - If file exists:
            - Open file
            - Overwrite all of it's contents with the new contents.
        - If the file does not exist:
            - Create new file
            - Write the new contents in it.
        */
        let data: &[u8] = state_text.as_bytes();

        let mut file: std::fs::File = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(path)?;

        let out: Result<(), io::Error> = file.write_all(data);
        out?;

        return Ok(());
    }

    /// Creates a new empty State
    #[must_use]
    pub const fn empty() -> Self {
        return Self {
            time_line: Timeline::new(),
            information: Information::new(),
        };
    }

    pub fn add_node(&mut self, node: &Node) {
        self.time_line.0.push(node.clone());
    }

    /// Adds an [`Computer`] to the [`State`]. Returns [None] if it already exists.  
    pub fn add_computer(&mut self, computer: Computer) -> Option<usize> {
        let duplicated: bool = self
            .information
            .computers
            .iter()
            .any(|c: &Computer| c.name == computer.name);

        if duplicated {
            return None;
        }

        self.information.computers.push(computer);
        return Some(self.information.computers.len() - 1);
    }

    /// Adds an [`IpAddr`] to the [`State`] and relates it to the [`Computer`].
    ///
    /// Returns [None] if:  
    ///  - The ip already exists.
    ///  - The computer does not exist
    pub fn add_ip(&mut self, ip: IpAddr, id_computer: usize) -> Option<usize> {
        let duplicated: bool = self
            .information
            .ips
            .iter()
            .any(|other: &IpAddr| ip.eq(other));

        if duplicated {
            return None;
        }

        let computer: &mut Computer = self.information.computers.get_mut(id_computer)?;

        let id_ip: usize = self.information.ips.len();

        self.information.ips.push(ip);
        computer.ips.push(id_ip);

        println!(
            "Ip {} (id: {}) is now asociated to Computer {} (id: {}). ",
            ip, id_ip, computer.name, id_computer
        );

        return Some(id_ip);
    }

    /// Adds [Software] to the [`State`]. Returns [None] if it already exists.  
    pub fn add_software(
        &mut self,
        software: Software,
        computer_id_opt: Option<usize>,
    ) -> Option<usize> {
        let duplicated: bool = self.information.software.iter().any(|other: &Software| {
            software.name.eq(&other.name) && software.version.eq(&other.version)
        });

        if duplicated {
            return None;
        }

        let id: usize = self.information.software.len();
        if let Some(computer_id) = computer_id_opt
            && let Some(computer) = self.information.computers.get_mut(computer_id)
        {
            computer.software.push(id);
        }

        self.information.software.push(software);
        return Some(id);
    }

    /// Adds [Service] to the [`State`]. Returns [None] the data is invalid.
    ///
    /// If the service already exists in the global state, then just the
    /// computer is updated by adding a reference.
    pub fn add_service(&mut self, service: Service, computer_id: usize) -> Option<usize> {
        let computer: &mut Computer = match self.information.computers.get_mut(computer_id) {
            Some(c) => c,
            None => {
                return None;
            }
        };

        let duplicated: Option<usize> = self
            .information
            .services
            .iter()
            .position(|s: &Service| service.eq(s));

        let idx: usize = if let Some(idx) = duplicated {
            idx
        } else {
            let idx: usize = self.information.services.len();
            self.information.services.push(service);

            idx
        };

        let service_already_in_computer: bool = computer.services.contains(&idx);
        if service_already_in_computer {
            let service_name: &str = self.information.services[idx].name.as_str();
            eprintln!(
                "Computer \"{}\" already contains the service {} (same software/port)",
                computer.name, service_name
            );
            return None;
        }

        computer.services.push(idx);

        return Some(idx);
    }

    /// Adds a [Vulnerability] to the [`State`]. Returns [None] if it already exists.  
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) -> Option<usize> {
        let duplicated: bool = self
            .information
            .vulnerabilities
            .iter()
            .any(|other: &Vulnerability| vulnerability.cve.eq(&other.cve));

        if duplicated {
            return None;
        }

        self.information.vulnerabilities.push(vulnerability);
        return Some(self.information.vulnerabilities.len() - 1);
    }

    /// Adds a Domain to the [`State`]. Returns [None] if it already exists.  
    pub fn add_domain(&mut self, domain: String) -> Option<usize> {
        let duplicated: bool = self
            .information
            .domains
            .iter()
            .any(|other: &String| domain.eq(other));

        if duplicated {
            return None;
        }
        self.information.domains.push(domain);
        return Some(self.information.domains.len() - 1);
    }

    /// Adds an [`User`] to the [`State`]. Returns [None] if it already exists.  
    pub fn add_user(&mut self, user: User) -> Option<usize> {
        self.information.users.push(user);
        return Some(self.information.users.len() - 1);
    }

    /// Adds a fact to the [State]. Returns [None] if it already exists.  
    pub fn add_fact(&mut self, fact: String) -> Option<usize> {
        self.information.facts.push(fact);
        return Some(self.information.facts.len() - 1);
    }

    #[must_use]
    pub fn get_computer_id(&self, name: &str) -> Option<usize> {
        self.information
            .computers
            .iter()
            .position(|c: &Computer| c.name == name)
    }

    /// Relates an [`IpAddr`] to a [`Computer`].
    ///
    /// If the ip is already related to the computer, an error message
    /// is emited and no other actions are taken.
    ///
    /// # Panics
    ///
    /// Both the ip adress and the computer must already exists in the
    /// [`Information`] struct. If this is false, the function will panic as
    /// this signals an inconsintent state in the program.
    ///
    pub fn relate_ip_computer(&mut self, id_computer: usize, id_ip: usize) {
        assert!(
            self.information.ips.get(id_ip).is_some(),
            "id of ip adress does not exist"
        );

        let ip: &IpAddr = self
            .information
            .ips
            .get(id_ip)
            .unwrap_or_else(|| panic!("id of ip adress does not exist"));

        // id are valid

        let computer_opt: Option<&mut Computer> = self.information.computers.get_mut(id_computer);
        match computer_opt {
            None => panic!("id of computer does not exist"),
            Some(computer) => {
                if computer.ips.contains(&id_ip) {
                    // duplicated
                    eprintln!(
                        "Computer {} (id: {}) already is asociated to ip {} (id: {}). \n\nAborting. No actions have been taken. ",
                        computer.name, id_computer, ip, id_ip
                    );
                    return;
                }
                // not duplicated
                computer.ips.push(id_ip);

                println!(
                    "Ip {} (id: {}) is now asociated to Computer {} (id: {}). ",
                    ip, id_ip, computer.name, id_computer
                );
            }
        }
    }
}

impl Timeline {
    #[must_use]
    pub const fn new() -> Self {
        return Self(Vec::new());
    }
}

impl ToString for Node {
    fn to_string(&self) -> String {
        format!("{:?} : {}", self.time_stamp, self.category.to_string())
    }
}

impl ToString for Category {
    fn to_string(&self) -> String {
        match self {
            Self::Action(action) => format!("Action {}", action.to_string()),
            Self::Consequence(consequence) => format!("Consequence: {}", consequence.to_string()),
            Self::Event(event) => format!("Event: {}", event.to_string()),
        }
    }
}
