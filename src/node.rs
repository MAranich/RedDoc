//!
//! A module dedicated to the structure [Node], wich is the fundamental building block
//! for storing the information.
//!

use crate::information::InfoRef;
use chrono::prelude::*;

/// Basic structure that stores the relevant information
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Node {
    time_stamp: DateTime<Utc>,
    category: Category,
}

/// The different classes of events that can happen:
///  - [Category::Action]: Codifies actions taken by the user
///  - [Category::Consequence]: Codifies the consequences of actions.
///  - [Category::Event]: Codifies any other fact that cannot be direcly attributed to an action.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Category {
    Action(Action),
    Consequence(Consequence),
    Event(Event),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Action {
    /// A custom action, the user may store any string
    Custom(String),
    /// The execution of a command (the output is sored in another node)
    Command(String),
    KnownCommnad(KnownCommnad),
    // /// Execution of a script, string is for the code
    // Script(String)
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum KnownCommnad {
    A,
    B,
    C,
} // TODO

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Event {
    Custom(String),
    /// The Blue team (Defenders) have discovered the activity.
    Detection,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Timeline(Vec<Node>);

impl Node {
    pub fn new(cat: Category) -> Node {
        return Node {
            time_stamp: Utc::now(),
            category: cat,
        };
    }
}
