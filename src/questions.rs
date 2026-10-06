//! This module is in charge of interacting with the user
//!
//!

use std::fs::{self, File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::process::Command;
use std::{env, io};

use regex::Regex;

///
/// ## Panics
///
/// Panics may be caused if the user sends invalid UTF-8 characters or if the
/// `Read` method returns an error.
///
#[must_use]
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
                println!("What you inserted is not a valid awnser. {INSTRUCTIONS}");
            }
            None => println!("You need to awnser the question. {INSTRUCTIONS}"),
        }
    };

    return ret;
}

///
/// ## Panics
///
/// Panics may be caused if the user sends invalid UTF-8 characters or if the
/// `Read` method returns an error.
///
#[must_use]
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
                println!("The number you inserted is out of range. {INSTRUCTIONS}");
            }
            Err(_e) => {
                println!("The awnser you provided was empty or invalid. {INSTRUCTIONS}");
            }
        }
    };

    // assert correctness
    assert!(1 <= ret);
    assert!(ret <= options.len());

    return ret;
}

const HELP_MESSGE: &str = "// Write in a newline after the line what value do you want to give it. 
// Lines in C-like comments are ignored. Be carefull with open multi-line comments
/*this too*/
// Do NOT erase the values like [0123456789] because they are needed for 
// reading back the awnser. Put your awnser between the 2 markers. 
// Your awnser is trimmed, so extra newlines at the start or end do not matter. 
// 
// You can leave your awnser empty if needed. ";

/// A wrapper fo [`ask_write_text_temporal`]. Ask the user some questions and
/// let the user write in a teporary file and collect the result.
///
/// ## Errors
///  - Returns error if there was a problem with file operations.
///
/// ## Panics
///  - When the text editor process returned an error.
///  - When it is not possible to read the awnser in the file.
///
pub fn handler_write_user(questions: &[&str]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let n_questions: usize = questions.len();

    // prepare the text file
    let mut initial_content: String = format!("{HELP_MESSGE}\n");

    let mut question_hashes: Vec<String> = Vec::with_capacity(n_questions);
    for &question in questions {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        question.hash(&mut hasher);
        // 32 bits for our usecase is more than enough
        let hash: u64 = hasher.finish() >> 32;
        let hash_str: String = format!("{hash:x}");
        let aux: String = format!("\n[{hash_str}] {question} \n\n\n\n[{hash_str}]");
        initial_content.push_str(&aux);
        question_hashes.push(hash_str);
    }
    for _ in 0..16 {
        initial_content.push('\n');
    }

    // let user write
    let original_awnser: String = ask_write_text_temporal(&initial_content)?;

    // collect the awnser
    let full_awnser: String = remove_c_comments(&original_awnser);
    let mut ret: Vec<String> = Vec::with_capacity(n_questions);

    for q_hash in question_hashes {
        let regex_pattern: String = format!("\\[{q_hash}\\](?<awnser>(?:.|\n)*?)\\[{q_hash}\\]");
        let re: Regex =
            Regex::new(&regex_pattern).expect("Regex should be valid. (fn handler_write_user)");
        let cap: regex::Captures<'_> = re.captures(&full_awnser).expect(
            "You may have removed the markers and the file was not parsed correcly. Aborting. ",
        );

        let awnser: String = cap["awnser"].trim().to_string();
        ret.push(awnser);
    }

    return Ok(ret);
}

/// Let the user write in a teporary file and collect the result.
///
/// ## Errors
///  - Returns error if there was a problem with file operations.
///
/// ## Panics
///  - When the text editor process returned an error.
///  - When it is not possible to read the awnser in the file.
///
pub fn ask_write_text_temporal(
    initial_content: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // If the file is not removed, the information is preserved until the computer shuts down.
    // If true, there is a small save on memory.
    const REMOVE_FILE_AFTER_OPERATION: bool = true;

    // save to temporaty directory
    let temp_dir: std::path::PathBuf = env::temp_dir();
    let filename: String = format!(
        "reddoc_tmp_file_{}.txt",
        chrono::Utc::now().format("%Y-%m%dT%H:%M:%S")
    );
    // Use a unique name for safety. Using time in ISO format
    let file_path: std::path::PathBuf = temp_dir.join(&filename);

    {
        let file_res: Result<File, std::io::Error> = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&file_path);

        let mut file: File = file_res?;

        let _ = file.write(initial_content.as_bytes());

        // close file by droping `file`
    }

    // ////////////////////////////////////////////////////////////////////////
    // Launch nano to let the user edit the file

    let mut binding: Command = Command::new("nano");
    let nano_command: &mut Command = binding.arg(&file_path);

    let mut nano_process: std::process::Child = nano_command.spawn()?;

    let status: std::process::ExitStatus = nano_process.wait()?;

    // ////////////////////////////////////////////////////////////////////////

    assert!(
        status.success(),
        "ERROR: Nano terminated with an error status: {status}"
    );

    let updated_text: String = match fs::read_to_string(&file_path) {
        Ok(s) => s,
        Err(e) => panic!("ERROR: in function write_text_temporal. Error message: \n{e:?}"),
    };

    if REMOVE_FILE_AFTER_OPERATION {
        fs::remove_file(&file_path)?;
    }

    return Ok(updated_text);
}

fn remove_c_comments(input: &str) -> String {
    let a: String = remove_c_single_comments(input);
    return remove_c_multi_comments(&a);
}

fn remove_c_single_comments(input: &str) -> String {
    let mut output: String = String::new();
    let mut in_comment: bool = false;
    let mut is_prev_slash: bool = false;

    for c in input.chars() {
        let is_slash = c == '/';
        if is_slash && is_prev_slash && !in_comment {
            // Found // comment start
            output.pop();
            in_comment = true;
            continue;
        }

        if in_comment {
            // We are inside a comment, consume characters until a newline is found
            if c == '\n' {
                output.push('\n');
                in_comment = false;
            }
            // If it's not a newline, we discard the character (it's part of the comment)
        } else {
            // Not in a comment, append the character
            output.push(c);
        }
        is_prev_slash = is_slash;
    }

    output
}

fn remove_c_multi_comments(input: &str) -> String {
    // Can fail for sequences like "/* */* */" but idc
    let mut ret: String = String::new();

    let mut is_prev_slash: bool = false;
    let mut is_prev_star: bool = false;
    let mut nesting_lvl: u32 = 0;

    for c in input.chars() {
        let is_slash: bool = c == '/';
        let is_star: bool = c == '*';
        if is_prev_slash && is_star {
            // new nested comment
            if nesting_lvl == 0 {
                // rm extra '/'
                ret.pop();
            }
            nesting_lvl += 1;
        }

        if 0 < nesting_lvl {
            if is_prev_star && is_slash {
                nesting_lvl = nesting_lvl - 1;
            }
        } else {
            ret.push(c);
        }
        is_prev_slash = is_slash;
        is_prev_star = is_star;
    }

    return ret;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_comments() {
        let input = "This is normal text.";
        assert_eq!(remove_c_multi_comments(input), "This is normal text.");
    }

    #[test]
    fn test_simple_comment() {
        let input = "Start /* comment */ End";
        assert_eq!(remove_c_multi_comments(input), "Start  End");
    }

    #[test]
    fn test_nested_comment_rule() {
        let input = "a/*b/*c*/d*/e";
        assert_eq!(remove_c_multi_comments(input), "ae");
    }

    #[test]
    fn test_multiple_comments() {
        let input = "First /* comment one */ Second /* comment two */ End";
        assert_eq!(remove_c_multi_comments(input), "First  Second  End");
    }

    #[test]
    fn test_comment_at_start() {
        let input = "/* Comment at start */ Text";
        assert_eq!(remove_c_multi_comments(input), " Text");
    }

    #[test]
    fn test_comment_at_end() {
        let input = "Text /* Comment at end */";
        assert_eq!(remove_c_multi_comments(input), "Text ");
    }

    #[test]
    fn test_empty_string() {
        let input = "";
        assert_eq!(remove_c_multi_comments(input), "");
    }

    #[test]
    fn test_no_closing_comment() {
        let input = "Text /* unclosed";
        assert_eq!(remove_c_multi_comments(input), "Text "); // "Text /* unclosed"
    }

    #[test]
    fn test_complex_nesting() {
        // Test case: Outer comment contains inner comments. The outermost pair is removed.

        let input = "Outer /* Inner /* nested */ content /* more */ End";
        assert_eq!(remove_c_multi_comments(input), "Outer "); // "Outer  End"
    }

    #[test]
    fn test_adjacent_comments() {
        let input = "A /* B */ C /* D */ E";
        assert_eq!(remove_c_multi_comments(input), "A  C  E");
    }
}
