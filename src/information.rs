//! This module is dedicated to modeling the information obtained. 
//! 
//! 
//! 




/// Information that has been obtained
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Information<'a> {
    pub computers: Vec<Computer<'a>>, 
    pub ips: Vec<IP>, 
    pub software: Vec<Software<'a>>, 
    pub vulnerabilities: Vec<Vulnerability>, 
    pub domains: Vec<String>, 
    pub users: Vec<User>, 
    pub facts: Vec<String>, 
}

/// Helper enum for [InfoRef] that indicates what kind of information it is. 
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct InfoRef {
    index: usize, 
    class: InfoClass, 
}

/// Information of a computer. 
/// 
/// It does not need to be linked to physical hardware (it may be virtualized). 
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Computer<'c> {
    /// A name to quicky identify the computer
    pub name: String, 
    pub ips: Vec<IP>, 
    /// List of open / relevant ports
    pub ports: Vec<u16>, 
    pub services: Vec<&'c Software<'c>>, 
    pub is_honeypot: bool, 
    /// The bool indicates if virtulization was used. The second term is an 
    /// optional reference to the virtualitzation software used. 
    /// 
    /// (false, Some(...)) is invalid
    pub is_virtualized: (bool, Option<&'c Software<'c>>), 
    pub infection_level: ComputerControl, 
    pub operating_system: &'c Software<'c>, 
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ComputerControl {
    /// Administrative privileges
    Root, 
    /// User with normal privileges
    User, 
    /// Very limited contol
    Limited, 
    /// No control
    None
}


#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum IP {
    V4(u32), 
    V6(u64), 
}

/// Some software used somewhere
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Software<'b> {
    pub name: String, 
    pub description: String, 
    pub version: String, 
    pub vulnerabilities: Vec<&'b Vulnerability>, 
}


#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct User {
    // (optional)
    pub name: String, 
    // (optional)
    pub email: Vec<String>, 
    pub phone_number: Vec<u64>, 
    /// The string descrives there the credentals are used. 
    pub credentials: Vec<(String, Credential)>
}


#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Credential {
    User(String), 
    UserPassword(String, String), 
    UserHashedPassword(String, String), 
    Token(String), 
    PrivateKey(String), 
}


