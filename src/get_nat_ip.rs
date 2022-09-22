
use reqwest;

const IP_URL: &str = "http://ip1.dynupdate.no-ip.com";

// Might be nice to convert the response which is a string to IpAddrs's..

pub fn get_my_nat_ip_address() -> Result<String, Box<dyn std::error::Error>> {
    let http_client = reqwest::blocking::Client::new();
    let url = IP_URL;

    let response = http_client
        // form a get request with get(url)
        .get(url)
        // send the request and get Response or else return the error
        .send()?
        // get text from response or else return the error
        .text()?;

    // wrapped response in Result
    Ok(response)
}




