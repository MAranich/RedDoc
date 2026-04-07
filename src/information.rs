//! This module is dedicated to modeling the information obtained.
//!
//!
//!

use serde::{Deserialize, Serialize};

/// Information that has been obtained
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Information {
    pub computers: Vec<Computer>,
    pub ips: Vec<IP>,
    pub software: Vec<Software>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub domains: Vec<String>,
    pub users: Vec<User>,
    pub facts: Vec<String>,
}

/// Helper enum for [`InfoRef`] that indicates what kind of information it is.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfoClass {
    Computer,
    IP,
    Software,
    Vulnerability,
    Domain,
    User,
    Fact,
}

/// Reference to a particular element inside an [Information] struct.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoRef {
    index: usize,
    class: InfoClass,
}

/// Information of a computer.
///
/// It does not need to be linked to physical hardware (it may be virtualized).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Computer {
    /// A name to quicky identify the computer
    pub name: String,
    pub ips: Vec<IP>,
    /// List of open / relevant ports
    pub ports: Vec<u16>,
    /// Valid Indices to the [Information] stuct (software column)
    pub services: Vec<usize>,
    pub is_honeypot: bool,
    /// The bool indicates if virtulization was used. The second term is an
    /// optional reference to the virtualitzation software used.
    ///
    /// (false, Some(...)) is invalid
    /// Valid Indices to the [Information] stuct (software column)
    pub is_virtualized: (bool, Option<usize>),
    /// Represents the highest level of control ever achieved.
    pub infection_level: ComputerControl,
    /// Valid Indices to the [Information] stuct (software column)
    pub operating_system: Option<usize>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputerControl {
    /// Administrative privileges
    Root,
    /// User with normal privileges
    User,
    /// Very limited contol
    Limited,
    /// No control
    None,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum IP {
    V4(u32),
    V6(u64),
}

/// Some software used somewhere
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Software {
    pub name: String,
    pub description: String,
    pub version: String,
    /// Valid Indices to the [Information] stuct (Vulnerability column)
    pub vulnerabilities: Vec<usize>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve: String,
    pub description: String,
    /// severity can go from [0, 1 000] and represent numbers from [0.0, 10.0] with 2 digits of acuracy.
    pub severity: Option<i16>,
    /// (optinal), code used to exploit this vulnerability
    pub exploit: String,
    pub known_vunlerable_versions: Vec<String>,
}

/// Subject (possibly a person) related.
///
/// Information possibly used for phishing attacks.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    // (optional)
    pub name: String,
    // (optional)
    pub email: Vec<String>,
    pub phone_number: Vec<u64>,
    /// The string descrives there the credentals are used.
    pub credentials: Vec<(String, Credential)>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Credential {
    User(String),
    UserPassword(String, String),
    UserHashedPassword(String, String),
    Token(String),
    PrivateKey(String),
}

impl Information {
    /// Creates empty Information struct
    pub fn new() -> Self {
        return Self {
            computers: Vec::new(),
            ips: Vec::new(),
            software: Vec::new(),
            vulnerabilities: Vec::new(),
            domains: Vec::new(),
            users: Vec::new(),
            facts: Vec::new(),
        };
    }
}
