//! This module is in charge of interacting with the user
//!
//!

use std::io;
use std::io::Write;

pub fn ask_bool_question(question: &str) -> bool {
    const ACCEPT_CHAR: char = 'y';
    const REJECT_CHAR: char = 'n';
    const INSTRUCTIONS: &str =
        "Use 'y' to accept, 'n' to reject or ctrl + C to terminate the program. \n";

    let ret: bool = loop {
        println!("{question}");
        print!("Awnser with y/n: ");
        let _ = std::io::stdout().flush(); // flushing
        let mut awnser: String = String::new();
        let read_out: Result<usize, io::Error> = io::stdin().read_line(&mut awnser);
        if let Err(e) = read_out {
            // this error may be caused if the user sends invalid UTF-8 characters or if the
            // `Read` method returns an error.
            panic!("Error when reading from standard input. Error: \n{e:?}\n");
        }

        let first_char: Option<char> = awnser.chars().next();
        match first_char {
            Some(c) => {
                let c_low: char = c
                    .to_lowercase()
                    .next()
                    .expect("The iterator is non-empty. ");
                if c_low == ACCEPT_CHAR {
                    break true;
                }
                if c_low == REJECT_CHAR {
                    break false;
                }
                println!("What you inserted is not a valid awnser. {INSTRUCTIONS}")
            }
            None => println!("You need to awnser the question. {INSTRUCTIONS}"),
        }
    };

    return ret;
}

pub fn ask_options_question(question: &str, options: &[&str]) -> usize {
    const INSTRUCTIONS: &str =
        "Type *only* the number of the option you want or ctrl + C to terminate the program. \n";

    let ret: usize = loop {
        println!("{question}");

        for (i, option) in options.iter().enumerate() {
            println!("{} : {option}", i + 1);
        }

        print!("Type the number of the option you want: ");
        let _ = std::io::stdout().flush(); // flushing
        let mut awnser: String = String::new();
        let read_out: Result<usize, io::Error> = io::stdin().read_line(&mut awnser);
        if let Err(e) = read_out {
            // this error may be caused if the user sends invalid UTF-8 characters or if the
            // `Read` method returns an error.
            panic!("Error when reading from standard input. Error: \n{e:?}\n");
        }

        let selected_option: Result<usize, std::num::ParseIntError> =
            awnser.trim().parse::<usize>();

        match selected_option {
            Ok(number) => {
                if (1..=options.len()).contains(&number) {
                    break number;
                }
                println!("The number you inserted is out of range. {INSTRUCTIONS}")
            }
            Err(_e) => {
                println!("The awnser you provided was empty or invalid. {INSTRUCTIONS}")
            }
        }
    };

    // assert correctness
    assert!(1 <= ret);
    assert!(ret <= options.len());

    return ret;
}
