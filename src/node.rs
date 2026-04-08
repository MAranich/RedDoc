//!
//! A module dedicated to the structure [Node], wich is the fundamental building block
//! for storing the information.
//!

use crate::information::{InfoRef, Information};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::read,
    io::{self, ErrorKind, Write},
    path::Path,
};

/// Basic structure that stores the relevant information
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    time_stamp: DateTime<Utc>,
    category: Category,
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
pub enum Action {
    /// A custom action, the user may store any string
    Custom(String),
    /// The execution of a command (the output is sored in another node)
    Command(String),
    KnownCommnad(KnownCommnad),
    // /// Execution of a script, string is for the code
    // Script(String)
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnownCommnad {
    None,
} // TODO

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

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Custom(String),
    /// The Blue team (Defenders) have discovered the activity.
    Detection,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline(Vec<Node>);

/// Represents all the information known by the program
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    time_line: Timeline,
    information: Information,
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

    pub fn get_state<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
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

        return Ok(ret);
    }

    pub fn save_state<P: AsRef<Path>>(path: P, state: &State) -> Result<(), io::Error> {
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
        let _ = out?;

        return Ok(());
    }

    /// Creates a new empty State
    #[must_use]
    pub fn empty() -> Self {
        return Self {
            time_line: Timeline::new(),
            information: Information::new(),
        };
    }

    pub fn add_node(&mut self, node: &Node) {
        self.time_line.0.push(node.clone());
    }
}

impl Timeline {
    pub fn new() -> Self {
        return Self(Vec::new());
    }
}
