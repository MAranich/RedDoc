//! Module dedicated to interacting with the file system
//!
//!

use serde::{Deserialize, Serialize};

use crate::node::State;
use std::{
    fs::OpenOptions,
    hash::{DefaultHasher, Hash, Hasher},
    io::{ErrorKind, Write},
    path::PathBuf,
};

pub const CONFIGURATION_PATH: &str = "/etc/red_doc.config";
pub const DEFAULT_PROJECT_FILE_NAME: &str = "project.json";

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct Configuration {
    project_path: PathBuf,
}

/// Loads the project
/// 
/// # Panics
/// 
///  - Panics if there was an IO error. 
///  - Panics if the data of the file is malformed. 
///  - Panics if there was any problem reading the configuration file. 
///      - (Or creating it if necessary)
#[must_use]
pub fn load_project() -> State {
    // TODO update to add project files and /etc/config file

    let project_path: PathBuf = get_project_path();

    let ret: State = match std::fs::read(project_path) {
        Ok(f) => {
            // let contents: String = String::from(f);
            let x: &[u8] = &f[..];
            match serde_json::from_slice::<State>(x) {
                Ok(v) => v,
                Err(e) => panic!("There was an error parsing the state. Error: \n{e:?}"),
            }
        }
        Err(e) => {
            // No file found error.

            match e.kind() {
                ErrorKind::NotFound => {
                    println!(
                        "WARNING: no project file found. Creating new one at the current directory. \n\
                    This is expected when executing for the first time. \n\
                    Configure the location of the project file with `red_doc config project_path <new_path>` . "
                    );

                    // update config
                    Configuration::set_project_path_to_cwd();

                    State::empty()
                }
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

/// Saves the project in its project file.
///
///  - The `original_state_hash` just serves to avoid performing the save if it was not
///    needed.
///      - And display a messago for the user.
///      - If it is not remebered, set it to any number distinct to the current
///        hash to forcefully save it.
pub fn save_project(state: &State, original_state_hash: u64) {
    let project_path: PathBuf = get_project_path();

    let updated_state_hash: u64 = {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        state.hash(&mut hasher);
        hasher.finish()
    };
    if updated_state_hash == original_state_hash {
        println!("No changes were made. ");
        return;
    }

    let save_result: Result<(), std::io::Error> = State::save_state(project_path, state);
    if let Err(e) = save_result {
        eprintln!("There has been an error storing the state. Error: \n{e:?}");
    }
}

fn get_project_path() -> PathBuf {
    let config: Configuration = Configuration::read_config();
    return config.project_path;
}

impl Configuration {
    /// Creates a new default configuration with the current path for the current project.
    fn new() -> Configuration {
        // use local directory
        let mut path: PathBuf = std::env::current_dir()
            .expect("Cannot obtain current working directory. (try launching from terminal?)");
        path.push(PathBuf::from(DEFAULT_PROJECT_FILE_NAME));

        println!("INFO: New project path: {}", path.display()); 

        return Configuration { project_path: path };
    }

    /// Reads the contents of the config file and returns it.
    ///
    ///  - If the config file does not exist, then it returns a new default [Configuration].
    ///
    /// ## Errors
    ///  - Some IO error has happened.
    ///
    fn read_config() -> Configuration {
        let config: Configuration = match std::fs::read(CONFIGURATION_PATH) {
            Ok(data) => match serde_json::from_slice::<Configuration>(&data) {
                Ok(v) => v,
                Err(e) => panic!("There was an error parsing the state. Error: \n{e:?}"),
            },
            Err(e) => {
                // No file found error.

                match e.kind() {
                    ErrorKind::NotFound => {
                        println!(
                            "WARNING: no configuration file found. Creating new one. \n\
                        This is expected when executing for the first time. "
                        );
                        let new_config: Configuration = Configuration::new();
                        Configuration::update_config_or_panic(&new_config); 
                        new_config
                    }
                    ErrorKind::PermissionDenied => {
                        panic!("Permission was denied to access file: \n{e:?}")
                    }
                    //ErrorKind::AlreadyExists => unreachable!(),
                    ErrorKind::InvalidInput => panic!("An invalid input was introduced: \n{e:?}"),
                    _ => panic!("An unaccounded error has ocurred: \n{e:?}"),
                }
            }
        };

        return config;
    }

    /// Overwrites the configuration file with the new configuration provided.
    fn update_config(config: &Configuration) -> Result<(), std::io::Error> {
        let data: String = serde_json::to_string(config)
            .expect("The Configuration type should be able to be stringified. ");
        let mut conf_file: std::fs::File = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(CONFIGURATION_PATH)?;

        conf_file.write_all(data.as_bytes())?;

        // close file by dropping conf_file
        return Ok(());
    }

    fn update_config_or_panic(config: &Configuration) {
        if let Err(conf_err) = Configuration::update_config(config) {
            match conf_err.kind() {
                ErrorKind::PermissionDenied => {
                    panic_configuration_privileges();
                }
                _ => panic!(
                    "ERROR: There has been an error while attempting to update the configuration file. Error: \n\t{conf_err:?}"
                ),
            }
        }
    }

    /// Updates the configuration file.
    ///
    /// Just sets the project directory to the current file.
    fn set_project_path_to_cwd() {
        let mut config: Configuration = Configuration::read_config();

        // keep original filename or use the default one
        let filename: String = config
            .project_path
            .file_name()
            .and_then(|os_s: &std::ffi::OsStr| os_s.to_str())
            .unwrap_or(DEFAULT_PROJECT_FILE_NAME)
            .to_owned();

        // update just project_path variable
        config.project_path = std::env::current_dir()
            .expect("Cannot obtain current working directory. (try launching from terminal?)");
        config.project_path.set_file_name(filename);

        // store again
        Configuration::update_config_or_panic(&config);
    }
}

fn panic_configuration_privileges() -> ! {
    panic!(
        "ERROR: The program does not have enough privileges to add or edit configuration files (in /etc/. )\n\
        To avoid this program, use the sudo command to elevate privileges. `sudo <previous command>` \n\
        The elevated privileges are only needed when creating or modifying the configuration file \
        (not always). "
    );
}


