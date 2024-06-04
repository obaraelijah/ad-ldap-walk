use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};

use env_logger::Env;
use log::*;
use structopt::StructOpt;

mod utils;

const MAX_QUERY_USERS: usize = 128;

#[derive(Debug, StructOpt)]
struct CmdlineOpts {
    /// ID to bind with.  This may take the form of an e-mail address
    #[structopt(short = "u", long, value_name = "USERID")]
    bind_user: String,

    /// LDAP server
    #[structopt(short = "s", long, value_name = "HOST")]
    server: String,

    /// LDAP search base
    #[structopt(short = "b", long, value_name = "DN")]
    search_base: String,

    /// Where to save captures
    #[structopt(short = "d", long, value_name = "PATH")]
    state_dir: Option<String>,

    /// User(s) highest up the food chain
    #[structopt(value_name = "USERID")]
    root_users: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct SavedState {
    /**
     * A given employee's manager
     */
    emp_manager: BTreeMap<String, String>,
    /**
     * A given manager's employees
     */
    manager_reports: BTreeMap<String, Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let cmdline = CmdlineOpts::from_args();

    let password: &str = todo!();

    // LDAP connection
    let (conn, mut ldap) = LdapConnAsync::new(format!("ldap://{}", cmdline.server).as_ref())
        .await
        .map_err(|e| anyhow!("Unable to connect to {}: {}", cmdline.server, e))?;

    let _cxnhandle = tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            warn!("LDAP connection error: {}", e);
        }
    });

    ldap.simple_bind(&cmdline.bind_user, &password)
        .await
        .map_err(|e| anyhow!("Unable to bind to {}: {}", cmdline.server, e))?;

    if cmdline.root_users.is_empty() {
        return Err(anyhow!("root user(s) not specified"));
    }

    let state_dir: PathBuf = match &cmdline.state_dir {
        Some(dir) => dir.into(),
        None => format!("{}/.ldap-walk/", std::env::var("HOME").unwrap()).into(),
    };
    let mut people_dir = state_dir.clone();
    people_dir.push("entries");
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| anyhow!("Unable to create directory ({:?}): {}", &state_dir, e))?;

    // Do this in a separate operation just to make for a better error message
    std::fs::create_dir_all(&people_dir)
        .map_err(|e| anyhow!("Unable to create directory ({:?}): {}", people_dir, e))?;

    for root_user in &cmdline.root_users {
        build_trees(
            &state_dir,
            &root_user,
            &mut ldap,
            &cmdline.search_base,
            &people_dir,
        )
        .await
        .map_err(|e| anyhow!("Walking tree for {}: {}", root_user, e))?;
    }

    Ok(())
}

async fn build_trees(
    state_dir: &PathBuf,
    root_user: &str,
    ldap: &mut Ldap,
    search_base: &str,
    people_dir: &PathBuf,
) -> Result<()> {
    let mut state_filepath = state_dir.clone();
    state_filepath.push(format!("{}.json", root_user));
    let mut dump_filepath = state_dir.clone();
    dump_filepath.push(format!("{}-hier.txt", root_user));
    let mut dump_filepath_tmp = state_dir.clone();
    dump_filepath_tmp.push(format!(".{}-hier.txt.tmp", root_user));
    let mut hier_fh = tokio::fs::File::create(&dump_filepath_tmp)
        .await
        .map_err(|e| anyhow!("Unable to create {:?}: {}", &dump_filepath_tmp, e))?;

    let emp_manager: BTreeMap<String, String> = BTreeMap::new();
    let manager_reports: BTreeMap<String, Vec<String>> = BTreeMap::new();

    let mut cur_state = SavedState {
        emp_manager,
        manager_reports,
    };

    // seed the tree the root user
    let mut remaining = VecDeque::new();
    remaining.push_back(root_user.to_owned());

    Ok(())
}

// fn build_query(users: &[String]) -> String {
fn build_query(users: &mut VecDeque<String>) -> String {
    let max = if users.len() > MAX_QUERY_USERS {
        MAX_QUERY_USERS
    } else {
        users.len()
    };
    format!(
        "(|{})",
        users
            .drain(0..max)
            .map(|u| format!("(CN={})", ldap3::ldap_escape(u)))
            .collect::<Vec<String>>()
            .join("")
    )
}


async fn query(ldap: &mut Ldap, search_base: &str, query: &str) -> Result<Vec<SearchEntry>> {
    let (rs, _res) = ldap
        .search(
            search_base,
            Scope::Subtree,
            query,
            // vec!["CN", "directReports", "manager"],
            vec!["*"],
        )
        .await?
        .success()?;
    Ok(rs
        .into_iter()
        .map(SearchEntry::construct)
        .collect::<Vec<SearchEntry>>())
}