use anyhow::{anyhow, Result};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};

use env_logger::Env;
use log::warn;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct CmdlineOpts {
    /// ID to bind with.  This may take the form of an e-mail address
    #[structopt(short = "u", long, value_name = "USERID")]
    bind_user: String,

    /// LDAP server
    #[structopt(short = "s", long, value_name = "HOST")]
    server: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let cmdline = CmdlineOpts::from_args();
    
    let (conn, mut ldap) = LdapConnAsync::new(format!("ldap://{}", cmdline.server).as_ref())
        .await
        .map_err(|e| anyhow!("Unable to connect to {}: {}", cmdline.server, e))?;
    
    let _cxnhandle = tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            warn!("LDAP connection error: {}", e);
        }
    });

    Ok(())
}
