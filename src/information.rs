//! This module is dedicated to modeling the information obtained.
//!
//!
//!

use serde::{Deserialize, Serialize};
use std::{fmt::Display, hash::Hash, net::IpAddr};

use crate::{standardize_name, standardize_version};

/// Information that has been obtained
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Information {
    pub computers: Vec<Computer>,
    pub ips: Vec<IpAddr>,
    pub software: Vec<Software>,
    pub services: Vec<Service>,
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
    Service,
    Domain,
    User,
    Fact,
}

/// Reference to a particular element inside an [Information] struct.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoRef {
    pub index: usize,
    pub class: InfoClass,
}

/// Information of a computer.
///
/// May also be refered as "machine" in the documantation. It does not need
/// to be linked to physical hardware (it may be virtualized).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Computer {
    /// A name to quicky identify the computer
    pub name: String,
    /// List of indexes to IP directions asociated to this machine
    pub ips: Vec<usize>,
    /// List of open / relevant ports
    pub ports: Vec<u16>,
    /// Valid Indices to the [Information] struct (service column)
    pub services: Vec<usize>,
    /// Valid Indices to the [Information] struct (software column)
    pub software: Vec<usize>,
    pub is_honeypot: bool,
    /// The bool indicates if virtulization was used. The second term is an
    /// optional reference to the virtualitzation software used.
    ///
    /// (false, Some(...)) is invalid
    /// Valid Indices to the [Information] stuct (software column)
    pub is_virtualized: (bool, Option<usize>),
    /// Represents the highest level of control ever achieved. User defined.
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

/// Some software used somewhere
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    pub name: String,
    pub description: String,
    pub version: Option<String>,
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

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Name of the service / protocol (ssh, rdp...)
    pub name: String,
    /// The port at wich the service is exposed
    pub port: u16,
    /// Optional reference to the software used
    pub software: Option<usize>,
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

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum TTP {
    /// The name of the technique itself
    Name(String),
    /// The category of the technique used (what is the objective)
    Tactic(Tactic),
    /// What method was used. The id is stored
    ///
    /// `T1548` -> `TTP::Technique(1548)`
    Technique(u16),
    /// What method was used and the subtechnique. The id of the technique and subtechnique is stored
    ///
    /// `T1548.001` -> `TTP::Technique(1548, 1)`
    SubTechnique(u16, u8),
}

/// Obtained from: https://attack.mitre.org/tactics/enterprise/
/// (07/2026)
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tactic {
    Reconnaissance = 43,
    ResourceDevelopment = 42,
    InitialAccess = 1,
    Execution = 2,
    Persistence = 3,
    PrivilegeEscalation = 4,
    Stealth = 5,
    DefenseImpairment = 112,
    CredentialAccess = 6,
    Discovery = 7,
    LateralMovement = 8,
    Collection = 9,
    CommandControl = 11,
    Exfiltration = 10,
    Impact = 40,
}

impl Computer {
    #[must_use]
    pub fn new(name_: &str) -> Self {
        let std_name: String = standardize_name(name_);

        return Self {
            name: std_name,
            ips: Vec::new(),
            ports: Vec::new(),
            services: Vec::new(),
            software: Vec::new(),
            is_honeypot: false,
            is_virtualized: (false, None),
            infection_level: ComputerControl::None,
            operating_system: None,
        };
    }
}

impl Software {
    #[must_use]
    pub fn new(name_: &str, description_: &str, version_: Option<String>) -> Self {
        let std_name: String = standardize_name(name_);
        let std_version: Option<String> = version_.map(|v: String| standardize_version(&v));

        Self {
            name: std_name,
            description: description_.to_string(),
            version: std_version,
            vulnerabilities: Vec::new(),
        }
    }
}

impl PartialEq for Software {
    fn eq(&self, other: &Self) -> bool {
        // We consider software to be equal if the name and version coincide.
        // We ignore differences in their descriptions or list of vulnerabilities.
        self.name == other.name && self.version == other.version
    }
}

impl Eq for Software {}

impl Hash for Software {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        /*
           We use the defualt implementation for hash even if the Eq implementation does not coincide.
           The hash is used as a part of the state to check for changes, and we need to detect changes
           in the fields of description and vulnerabilities, wich are not needed for normal comparasion
           where we want to detect if they represent the same thing.
        */
        self.name.hash(state);
        self.description.hash(state);
        self.version.hash(state);
        self.vulnerabilities.hash(state);
    }
}

impl Display for Tactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let natural_name: &str = self.get_natural_name();
        let identifier: String = self.get_identifier();
        write!(f, "{natural_name} ({identifier})")
    }
}

impl Display for TTP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TTP::Name(name) => write!(f, "{name}"),
            TTP::Tactic(tactic) => write!(f, "{}", tactic),
            TTP::Technique(identifier) => write!(f, "T{:0>4}", identifier),
            TTP::SubTechnique(identifier, sub_identifier) => {
                write!(f, "T{:0>4}.{:0>3}", identifier, sub_identifier)
            }
        }
    }
}

impl From<&str> for TTP {
    fn from(value: &str) -> Self {
        //todo!("Currently unimplemented")
        Self::Name(value.to_string())
    }
}

impl Tactic {
    pub fn get_natural_name(&self) -> &str {
        return match self {
            Tactic::Reconnaissance => "Reconnaissance",
            Tactic::ResourceDevelopment => "Resource development",
            Tactic::InitialAccess => "Initial access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege escalation",
            Tactic::Stealth => "Stealth",
            Tactic::DefenseImpairment => "Defense impairment",
            Tactic::CredentialAccess => "Credential access",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral movement",
            Tactic::Collection => "Collection",
            Tactic::CommandControl => "Command and control",
            Tactic::Exfiltration => "Exfiltration",
            Tactic::Impact => "Impact",
        };
    }

    pub fn get_identifier(&self) -> String {
        return format!("TA{:0>4}", self.clone() as isize);
    }
}

impl Service {
    /// Invariants: name must be standardized
    #[must_use]
    pub fn new(name: &str, port_: u16) -> Self {
        let std_name: String = standardize_name(name);
        return Self {
            name: std_name,
            software: None,
            port: port_,
        };
    }
}

impl Information {
    /// Creates empty Information struct
    #[must_use]
    pub const fn new() -> Self {
        return Self {
            computers: Vec::new(),
            ips: Vec::new(),
            software: Vec::new(),
            services: Vec::new(),
            vulnerabilities: Vec::new(),
            domains: Vec::new(),
            users: Vec::new(),
            facts: Vec::new(),
        };
    }

    #[must_use]
    pub fn get_sowtware_versions(&self, name: &str) -> Vec<&str> {
        let curated_name: String = standardize_name(name);

        /*
        // imperative version of the code
        let mut ret: Vec<&str> = Vec::new();
        for software in self.software.iter() {
            if software.name != curated_name {
                continue;
            }
            match &software.version {
                Some(version) => {
                    ret.push(version.as_str());
                },
                None => {},
            }
        }
        return ret;
        */

        self.software
            .iter()
            .filter(|software: &&Software| software.name == curated_name)
            .filter_map(|software: &Software| software.version.as_ref())
            .map(|s: &String| s.as_str())
            .collect::<Vec<&str>>()
    }
}
