//#![allow(dead_code)]
//#![allow(unused_variables)]
//#![warn(unreachable_code)]

use std::env;
extern crate syslog;

use syslog::{ Facility, Formatter3164 };
use std::process;
//use dotenv::dotenv;
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr };

// I use this to read /etc/noipv6.conf , keep it simple
extern crate dotenv;

use std::path::{ PathBuf };
use std::{ thread, time::Duration };

use anyhow::Result;
use clap::Parser;
use dns_lookup::lookup_host;
use log::{ debug, error, info };

//mod dns_method;
mod get_ipv6_if_addr;
mod get_nat_ip;
mod update;

use percent_encoding::{ utf8_percent_encode, AsciiSet, CONTROLS };
const QUERY_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>');

use update::{ update, UpdateError };

const USER_AGENT: &str = concat!(
    clap::crate_name!(),
    "/",
    clap::crate_version!(),
    " <support@noip.com>"
);

// This is used to handle --import since the `exclusive` and `conflicts_with` options don't seem to
// work in clap 3.0.0-beta.5. Perhaps they will work in the future or when it goes stable. This
// should be revisited.

#[derive(Debug, Parser)]
#[clap(about = "No-IP Dynamic Update Client", version = clap::crate_version!())]
struct Config {
    /// Your www.noip.com username. For better security, use Update Group credentials. https://www.noip.com/members/dns/dyn-groups.php
    #[clap(short, long, env = "NOIP_USERNAME")]
    username: String,

    /// Your www.noip.com password. For better security, use Update Group credentials. https://www.noip.com/members/dns/dyn-groups.php
    #[clap(short, long, env = "NOIP_PASSWORD")]
    password: String,

    /// Comma separated list of groups and hostnames to update. This may be empty when using group
    /// credentials and updating all hosts in the group.
    // use std::vec::Vec to avoid Clap magic
    #[clap(short = 'g', long, env = "NOIP_HOSTNAMES", parse(try_from_str = parse_hostnames))]
    hostnames: Option<std::vec::Vec<String>>,

    /// How often to check for a new IP address. Minimum: every 2 minutes.
    #[clap(
        long,
        env = "NOIP_CHECK_INTERVAL",
        default_value = "5m",
        parse(try_from_str = humantime::parse_duration)
    )]
    check_interval: Duration,

    /// Timeout when making HTTP requests.
    #[clap(
        long,
        env = "NOIP_HTTP_TIMEOUT",
        default_value = "10s",
        parse(try_from_str = humantime::parse_duration)
    )]
    http_timeout: Duration,

    /// Fork into the background
    #[clap(long, env = "NOIP_DAEMONIZE")]
    daemonize: bool,

    /// When daemonizing, become this user.
    #[clap(long, env = "NOIP_DAEMON_USER")]
    daemon_user: Option<String>,

    /// When daemonizing, become this group.
    #[clap(long, env = "NOIP_DAEMON_GROUP")]
    daemon_group: Option<String>,

    /// When daemonizing, write process id to this file.
    #[clap(long, env = "NOIP_DAEMON_PID_FILE", parse(from_os_str))]
    daemon_pid_file: Option<PathBuf>,

    /// Increase logging verbosity. May be used multiple times.
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,

    /// Set the log level. Possible values: Trace, Debug, Info, Warn, Eror, Critical.
    /// Overrides --verbose.
    #[clap(short, long, env = "NOIP_LOG_LEVEL")]
    log_level: Option<LogLevel>,

    /*
    // Why, why why??
    /// Command to run when IP address changes.
    #[clap(short = 'e', long, env = "NOIP_EXEC_ON_CHANGE", parse(from_os_str))]
    exec_on_change: Option<PathBuf>,
*/
    #[clap(short, long, env = "NOIP_INTERFACE")]
    interface: String,

    /// Find the public IP and send an update, then exit. This is a good method to verify correct
    /// credentials.
    #[clap(long)]
    once: bool,
}

#[derive(Debug)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::str::FromStr for LogLevel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use LogLevel::*;
        Ok(match s.to_lowercase().as_str() {
            "trace" => Trace,
            "debug" => Debug,
            "info" => Info,
            "warn" | "warning" => Warning,
            "error" => Error,
            "critical" => Critical,
            _ => anyhow::bail!("unknown log level"),
        })
    }
}

use std::fmt;
impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LogLevel::*;
        match self {
            Trace => f.write_str("trace"),
            Debug => f.write_str("debug"),
            Info => f.write_str("info"),
            Warning => f.write_str("warning"),
            Error => f.write_str("error"),
            Critical => f.write_str("critical"),
        }
    }
}

// May be hostnames or group names
fn parse_hostnames(s: &str) -> Result<Vec<String>> {
    if s.len() >= 4000 {
        anyhow::bail!("hostnames too long");
    }

    let hostnames: Vec<String> = s
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();

    for h in &hostnames {
        // Group names are alphanumeric only
        if h.chars().all(|c| char::is_ascii_alphanumeric(&c)) {
            continue;
        }
        if !is_hostname(h) {
            anyhow::bail!(
                "invalid hostname {}. Hostnames must be a comma separated list of hostnames and group names.",
                h
            );
        }
    }

    Ok(hostnames)
}

fn is_hostname(h: &str) -> bool {
    if h.split('.').count() > 63 {
        return false;
    }

    h.split('.').all(is_label)
}

// Must be all alphanumeric or hyphen. Since these will always be A or AAAA they cannot
// start with `_` like TXT or SRV can.
fn is_label(s: &str) -> bool {
    s.chars().all(|c| (char::is_ascii_alphanumeric(&c) || c == '-')) &&
        // Cannot start with hyphen or be empty
        s
            .chars()
            .next()
            .map_or(false, |c| c != '-') &&
        // Cannot end with hyphen or be empty
        s
            .chars()
            .last()
            .map_or(false, |c| c != '-')
}

// This need to be passed to us from a configuraion file!!
//const INTERFACE: &str = "eth";
// const INTERFACE: &str = "enx7898e81e3d5d";

fn main() -> anyhow::Result<()> {
    // I would like to get my vars from /etc/noipv6.conf
    // into the environment so they get used by Config:parse()
    let version = dotenv::from_path("/etc/noipv6.conf");
    match version {
        Ok(v) => {
            debug!("The conf file was read in: {:?}", v);
        }
        Err(e) => debug!("error parsing header: {e:?}"),
    }

    //for (key, value) in env::vars() {
    //    debug!("{}: {}", key, value);
    //}

    let config = Config::parse();
    // Use this to dump config to json
    // dbg!("Display config: {:?}", &config);

    if config.check_interval < Duration::from_secs(120) {
        anyhow::bail!("--check_interval must be no less than 2 minutes");
    }

    let log_level = config.log_level.as_ref().unwrap_or(match config.verbose {
        0 => &LogLevel::Info,
        1 => &LogLevel::Debug,
        _ => &LogLevel::Trace,
    });

    if config.daemonize {
        // TODO: set up logging to a file
        env_logger::Builder
            ::from_env(env_logger::Env::default().default_filter_or(log_level.to_string()))
            .init();
        daemonize(&config)?;
    } else {
        env_logger::Builder
            ::from_env(env_logger::Env::default().default_filter_or(log_level.to_string()))
            .init();
    }

    debug!("{:?}", config);

    updater(&config)
}

fn daemonize(c: &Config) -> Result<()> {
    use daemonize::Daemonize;

    let mut daemonize = Daemonize::new().working_directory("/");

    if let Some(user) = &c.daemon_user {
        daemonize = match user.parse::<u32>() {
            Err(_) => daemonize.user(user.as_str()),
            Ok(uid) => daemonize.user(uid),
        };
    }

    if let Some(group) = &c.daemon_group {
        daemonize = match group.parse::<u32>() {
            Err(_) => daemonize.group(group.as_str()),
            Ok(gid) => daemonize.group(gid),
        };
    }

    if let Some(pid_file) = &c.daemon_pid_file {
        daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
    }

    daemonize.start()?;

    let cln = line!();
    info!("{cln}: Running in background");

    Ok(())
}

// Log to syslog
fn get_process_name() -> String {
    let this_process = std::env::current_exe().unwrap();
    let this_file = this_process.file_name().unwrap();

    String::from(this_file.to_str().unwrap())
}

fn logger(message: &str) {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: get_process_name(),
        pid: process::id(),
    };
    match syslog::unix(formatter) {
        Err(e) => println!("Unable to connect to syslog: {:?}", e),
        Ok(mut writer) => {
            writer.err(message).expect("Could not write error message");
        }
    }
}

// Explain what we are doing!!

fn get_network_info(my_cfg: &Config) -> (bool, IpAddr, IpAddr) {
    let mut ipv6_if_found: bool = true;
    // If it is empty rust comlians even so I test with a flag if is empty.
    // I think I need to learn more rust.
    let mut ipv6_if_val = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);

    // Get the local ipv6 from the local interface
    // the funtion get_ipv6_if_addr return only the latest global ipv6 address
    // for my needs this is enough.
    let get_my_latest_ipv6 = get_ipv6_if_addr::get_cur_ipv6_addr(&my_cfg.interface);
    match get_my_latest_ipv6 {
        Ok(ipv6_addr) => {
            ipv6_if_val = ipv6_addr;
        }
        Err(_) => {
            let cln = line!();
            info!("{cln}: Local Ipv6 addr not found error!");
            ipv6_if_found = false;
        }
    }
    debug!("");
    debug!("Latest ipv6 from interface: {:?} flag is {:?}", get_my_latest_ipv6, ipv6_if_found);

    // Get the ipv4 address as seen from the outside
    // Should be mutable since we will call it in a loop
    // I assume there is only ONE!!

    let mut ipv4_nat_found: bool = true;
    let mut ipv4_nat_val = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

    let nat_ip = get_nat_ip::get_my_nat_ip_address();
    match nat_ip {
        Ok(text) => {
            // If no ipv4 address I put in a dummy,
            // the flag ipv4_nat_found should protect us!!
            // I think I should use unwrap_or_else , need to learn more error handeling.
            // Ghiora
            ipv4_nat_val = text.parse().unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
            debug!("Got text {:?}, {:?}", text, ipv4_nat_val);
        }
        Err(nat_ip) => {
            ipv4_nat_found = false;
            let cln = line!();
            info!("{cln}: No Ipv4 address found at noip: {:?}", nat_ip);
        }
    }

    // This checks the hostnames are ok
    // QUERY_SET is used to prevent going on with forbidden chars in the hostname.
    // utf8_percent_encode does the actual checking
    // We can have a number of hostnames at one address.
    // for getting the ipv4 and ipv6 adresses by dns one is enough!
    let hostnames = match &my_cfg.hostnames {
        Some(h) => format!("{}", utf8_percent_encode(h.join(",").as_str(), QUERY_SET)),
        None => format!("none"),
    };
    debug!("Updating with url {}", hostnames);

    let dns_ips: Vec<std::net::IpAddr> = lookup_host(&hostnames).unwrap();
    //  There could be 0, 1, 2, or more.
    // I assume I only have one of ipv4 and ipv6,
    // anyone doing a more complicated case
    // will have to be fix this  stuff!!
    // GET THE FIRST IPV6 and IPV4 IF THEY EXIST
    debug!("Number of ips returned: {:?}", dns_ips.len());
    debug!("dns_ips: {:?}", dns_ips);
    debug!(
        "lookup_host results: 
            Dns addresses of {}: ipv6:{:?} ipv4:{:?}",
        &hostnames,
        dns_ips[0],
        dns_ips[1]
    );

    // This initial value here will not be returned by dns!!
    let mut ipv4_dns = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut ipv4_dns_found: bool = false;

    // This initial value here will not be returned by dns!!
    let mut ipv6_dns = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let mut ipv6_dns_found = false;

    for next_addr in dns_ips {
        if next_addr.is_ipv4() {
            ipv4_dns_found = true;
            ipv4_dns = next_addr;
        }
        if next_addr.is_ipv6() {
            ipv6_dns_found = true;
            ipv6_dns = next_addr;
        }
        if ipv4_dns_found && ipv6_dns_found {
            break;
        }
    }

    // gdb shows it in reverese (x86 reversing the 4 bytes crap I guess)
    // For example: p ip 3852724144
    // 176 + 231* (256)  + 163 *(256^2) + 229*(256^3) = 3852724144
    // which converts to : 229.163.231.176
    // when the address really is 176.231.163.229
    // as long as all the numbers are reveresed it does not matter.

    // Now decide what to do using
    //ipv4_nat_found ipv4_nat_val
    //ipv6_if_found ipv6_if_val
    //ipv4_dns_found ipv4_dns
    //ipv6_dns_found ipv6_dns

    let mut update_needed: bool = false;

    // We have an ipv4 from nat
    if ipv4_dns_found && ipv4_nat_found {
        if ipv4_nat_val != ipv4_dns {
            update_needed = true;
        }
    }

    // We have an ipv6 from nat
    if ipv6_dns_found && ipv6_if_found {
        if ipv6_if_val != ipv6_dns {
            update_needed = true;
        }
    }

    debug!("got new ip; ipv4_nat_val={}, ipv4_dns={}", ipv4_nat_val, ipv4_dns);
    debug!("got new ip; ipv6_if_val={}, ipv6_dns={}", ipv6_if_val, ipv6_dns);

    (update_needed, ipv4_nat_val, IpAddr::V6(ipv6_if_val))
}

fn updater(my_cfg: &Config) -> Result<()> {
    let mut retries = 0u8;
    let mut last_error: Option<UpdateError> = None;

    debug!("Starting update loop");

    loop {
        debug!("checking for new ip");
        let (update_needed, ipv4_nat_val, ipv6_if_val) = get_network_info(&my_cfg);

        if update_needed {
            let cln = line!();
            info!("{cln}: update needed; ip={}", ipv4_nat_val);
            let update_ips = vec![ipv4_nat_val, ipv6_if_val];

            match
                update(
                    &my_cfg.username,
                    &my_cfg.password,
                    my_cfg.hostnames.as_ref(),
                    update_ips,
                    my_cfg.http_timeout
                )
            {
                Ok(_changed) => {
                    let cln = line!();
                    info!("{cln}: update succeeded, ip={}", ipv4_nat_val);
                    let cln = line!();
                    info!("{cln}: update succeeded, ipv6={}", ipv6_if_val);
                    
                    logger(& format!("Update succeeded,ipv4={}",ipv4_nat_val.to_string()));
                    logger(& format!("Update succeeded,ipv6={}",ipv6_if_val.to_string()));                    

                    retries = 0;
                    last_error = None;

                    // I DO NOT LIKE THIS!!
                    /*
                    if changed {
                        if let Some(cmd) = &my_cfg.exec_on_change {
                            exec_command(cmd.as_path());
                        }
                    }
                    */
                }
                Err(e) => {
                    error!("update failed; {}", e);
                    last_error = Some(e);
                    retries += 1;
                }
            }
        } else {
            debug!("No need to update; ip={}", ipv4_nat_val);
            debug!("No need to update; ip={}", ipv6_if_val);
        }

        // Run the update only once
        if my_cfg.once {
            debug!("In --once mode, exiting.");
            return match last_error {
                Some(e) => Err(e.into()),
                None => Ok(()),
            };
        }

        // WHAT IS THIS???
        let dur = match last_error {
            Some(ref e) => e.retry_backoff(retries, my_cfg.check_interval),
            None => my_cfg.check_interval,
        };

        let cln = line!();
        info!("{cln}: checking ip again in {}", humantime::format_duration(dur));

       logger(& format!(
            "Checking ip again in {} minutes",
            &humantime::format_duration(dur).to_string()));

            thread::sleep(dur);
    }
}

/*
fn exec_command(cmd: &Path) {
    use std::str::from_utf8;

    let s = cmd.to_string_lossy();

    debug!("running command; exec_on_change={}", s);

    match Command::new(&cmd).output() {
        Ok(output) => {
            if output.status.success() {
                let cln= line!(); info!(
                    "{cln}: command success for `{}`; stdout={}, stderr={}",
                    s,
                    from_utf8(&output.stdout).unwrap_or(""),
                    from_utf8(&output.stderr).unwrap_or("")
                );
            } else {
                error!(
                    "command failed for `{}`; exit={}, stdout={}, stderr={}'",
                    s,
                    output.status.code().unwrap_or(-1),
                    from_utf8(&output.stdout).unwrap_or(""),
                    from_utf8(&output.stderr).unwrap_or("")
                );
            }
        }
        Err(e) => {
            error!("failed to execute cmd `{}`; {:?}", s, e);
        }
    }
}
*/
