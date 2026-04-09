//!
//! A module dedicated to the structure [Node], wich is the fundamental building block
//! for storing the information.
//!

use crate::{action::Action, consequences::Consequence, event::Event, information::Information};
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
