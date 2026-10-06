use std::{
    io::{self, Write},
    path::Path,
};

use clap::ArgMatches;

use crate::{
    DEBUG_MODE, consequences::cvss_num_to_label, information::Vulnerability, node::{State, Timeline},
};

pub fn process_report<P: AsRef<Path>>(
    _sub_match: &ArgMatches,
    _stdin: &str,
    state: &mut State,
    path: P,
) {
    /*
        TODO: also store std input ? / or do something with it?
    */




    let timeline_str: String = time_line_to_markdown(state as &State);
    let vulnerability_section: String = vulnerability_report_md(state as &State); 



    let contents: String = format!(
        "# MAIN TITLE\n\n\
        TODO: fill the values and change title. \n\
        Created by: {{authors}}\n\n{{date}}, {{Organization}}\
        \n\
        ## Executive summary\n\
        \n\
        TODO: the executive summary informs to non-technical people about the overall security position. \n\
        \n\n\
        ### Critical findings\n\
        \n\
        TODO: Select the findings to highlight or delete the section\n\
        \n\
        ### Business Impact\n\
        \n\
        TODO: How do the critical findings affect the organization. \n\
        \n\
        ### Recommendations Summary\n\
        \n\
        TODO: A high level overview of the most important remediation measures. \n\
        \n\
        ## Scope amd methodology\n\
        \n\
        TODO: What procedure was used to perform the pentest/read team exercise. \n\
        \n\
        ### Scope Definition\n\
        \n\
        TODO: Define precisely what are the elements to investigate. Also define what is *out* of scope. \n\
        \n\
        ### Testing methodology\n\
        \n\
        TODO: Descrive the approach used (OWASP Top 10, NIST guidelines; or a hybrid methodology). \n\
        \n\
        ### Rules of Engagement \n\
        \n\
        TODO: other rules or constraints. \n\
        \n\
        ## Detailed findings\n\
        \n\
        {vulnerability_section}
        \n\
        ## Technical details \n\
        \n\
        TODO: Technical section where other relevant details and information of the vulnerabilities are provided. \n\
        \n\
        ### Thecnical details \n\
        \n\
        TODO: complete this section or remove it. \n\
        \n\
        ### Configuration errors \n\
        \n\
        TODO: complete this section or remove it. \n\
        \n\
        ### Evidence\n\
        \n\
        TODO: complete this section or remove it. Includes screenshots, logs and other forms of evidence. \n\
        \n\
        ## Conclusion\n\
        \n\
        TODO: complete this section. \n\
        \n\
        ### Priorized recommendation roadmap\n\
        \n\
        TODO: Recommended roadmap for the remediation of the findings. \n\
        \n\
        ## Appendix\n\
        \n\
        {timeline_str}
        \n\
        "
    
    ); 


    match generate_file(path, contents.as_str()) {
        Ok(()) => {
            if DEBUG_MODE {
                println!("Report successfully generated. ");
            }
        }
        Err(e) => eprintln!("There was an error while storing the report: \n{e:?}"),
    }
}

/// Generates a report file with the provided contents.
///
/// # Errors
///
/// This function will return an error if:
/// - There was an error creating/opening the report file.
/// - There was an error writing into the report file.
///
pub fn generate_file<P: AsRef<Path>>(path: P, content: &str) -> Result<(), io::Error> {
    let data: &[u8] = content.as_bytes();

    let mut file: std::fs::File = std::fs::OpenOptions::new()
        .write(true) // Open for writing
        .truncate(true) // Discard previous contents
        .create(true) // Create new file it it does not exist
        .open(path)?; // Open the given file or backpropagate error

    let out: Result<(), io::Error> = file.write_all(data);
    out?; // Backpropagate possible writing errors. 

    return Ok(());
}

fn time_line_to_markdown(state: &State) -> String {
    /*
       To print the timeline of events, we want:
       - We want to make divisions to separate the events by the day they ocurred.
        - To have a list of events sorted.

        (This could probably be better implemented)
    */
    let time_line: &Timeline = &state.time_line; 
    let mut group_by_day: Vec<(chrono::NaiveDate, Vec<usize>)> = Vec::new();

    for (i, node) in time_line.0.iter().enumerate() {
        let date: chrono::NaiveDate = node.time_stamp.date_naive();

        let idx_opt: Option<usize> = group_by_day
            .iter()
            .position(|d: &(chrono::NaiveDate, Vec<usize>)| d.0 == date);

        match idx_opt {
            Some(idx) => {
                let nodes_by_date: &mut (chrono::NaiveDate, Vec<usize>) = &mut group_by_day[idx];
                nodes_by_date.1.push(i);
            }
            None => group_by_day.push((date, vec![i])),
        }
    }
    // Now I have subdivided all nodes into multiple collections depending on the day

    for collection in &mut group_by_day {
        collection.1.sort_by(|&i, &j| {
            let a: chrono::DateTime<chrono::Utc> =
                time_line.0.get(i).expect("Valid index").time_stamp;
            let b: chrono::DateTime<chrono::Utc> =
                time_line.0.get(j).expect("Valid index").time_stamp;
            a.cmp(&b)
        });
    }
    // Now the index of each collecion are sorted by the time the node was created.

    group_by_day.sort_by_key(|x| x.0);

    // Now the groups themselves are sorted.

    let mut ret: String = String::from("### Timeline of events\n\n");
    let mut aux: String = String::new();

    for collection in group_by_day {
        aux.clear();
        aux = format!(" - {}: \n", collection.0.format("%Y-%m-%d"));
        ret.push_str(&aux);

        for i in collection.1 {
            aux.clear();
            let current: &crate::node::Node = time_line.0.get(i).expect("Valid index. ");
            let time: chrono::NaiveTime = current.time_stamp.time();
            aux = format!(
                "     - {}: {}\n",
                time.format("%H:%M"),
                current.category.to_string(state)
            );
            ret.push_str(&aux);
        }
    }

    return ret;
}

fn vulnerability_report_md(state: &State) -> String {

    // TODO: sort vulnerabilities by criticity
    let mut nameless_vuln_count: u32 = 0; 
    let mut ref_vuln_list: Vec<&Vulnerability> = state.information.vulnerabilities.iter().map(|e: &Vulnerability| e ).collect::<Vec<&Vulnerability>>(); 
    ref_vuln_list.sort_unstable_by_key(|v: &&Vulnerability| 
        -v.severity_rating.map(|s: u16| i32::from(s + 1)).unwrap_or_default()
    ) ;

    let mut ret: String = String::new(); 
    for vuln in ref_vuln_list {

        let vuln_descr: &str = vuln.description.as_str(); 

        let vuln_name: String = vuln_descr.lines().next().map_or_else(|| {
            nameless_vuln_count += 1; 
            format!("Nameless vulnerability {nameless_vuln_count}")
        }, |n: &str|n.to_string()); 

        let vuln_descr_fmt: String = format!(
        "\
        #### Description \n\
        \n\
        {}\n\n\
        ", if vuln_descr.is_empty() {"[Empty description]"} else {vuln_descr}); 

        let vuln_loc_fmt: String = if vuln.location.is_empty() {String::new()} else { format!(
        "\
        #### Location \n\
        \n\
        {}\n\n\
        ", vuln.location)}; 

        let vuln_risk_fmt: String = if vuln.risk_analysis.is_empty() {String::new()} else {format!(
        "\
        #### Risk analysis \n\
        \n\
        {}\n\n\
        ", vuln.risk_analysis)}; 

        let vuln_exploit_fmt: String = if vuln.exploit.is_empty() {String::new()} else {format!(
        "\
        #### Exploit / steps to reproduce \n\
        \n\
        {}\n\n\
        ", vuln.exploit)}; 

        let vuln_recomendation_fmt: String = if vuln.recommendation.is_empty() {String::new()} else {format!(
        "\
        #### Recomendation \n\
        \n\
        {}\n\n\
        ", vuln.recommendation)}; 

        let cvss_label: String = vuln.severity_rating
        .map(|s: u16| cvss_num_to_label(f32::from(s) * 0.01, true))
        .map_or(String::new(), |l: &str| format!("\\[{l}] ")); 

        let cve_fmt: String = if vuln.cve.is_empty() {String::new()} else {
            format!(" ({})", vuln.cve)
        }; 

        let affected_versions_fmt: String = if vuln.known_vunlerable_versions.is_empty() {String::new()} 
        else {
            let mut kvs: String = "Known vulnerable versions: ".to_string(); 
            for vers in &vuln.known_vunlerable_versions {
                let line: String = format!("\n - {vers}"); 
                kvs.push_str(&line);
            }
            kvs.push('\n');
            kvs            
        }; 

        //////////////////

        let vuln_str: String = format!(
        "\
        ### {cvss_label}{vuln_name}{cve_fmt} \n\
        {affected_versions_fmt}\
        {}\n\
        {vuln_descr_fmt}\
        {vuln_loc_fmt}\
        {vuln_risk_fmt}\
        {vuln_exploit_fmt}\
        {vuln_recomendation_fmt}\
        ", 
            vuln.severity_rating.map_or(String::new(), |s| format!("CVSS: {:.2}\n", f32::from(s) * 0.01_f32))
    ); 
        ret.push_str(&vuln_str);
    }

    return ret; 
}
