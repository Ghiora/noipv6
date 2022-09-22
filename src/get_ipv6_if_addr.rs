extern crate local_ip_address;
use local_ip_address::list_afinet_netifas;
use std::net::IpAddr;
use std::net::Ipv6Addr;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Returned when `local_ip` is unable to find the system's local IP address
    /// in the collection of network interfaces
    #[error("The Local IP Address wasn't available in the network interfaces list/table")]
    LocalIpAddressNotFound,
}

use anyhow::Result;

pub fn get_cur_ipv6_addr(cur_interface: &str) -> Result<Ipv6Addr, Error> {
    let network_interfaces = list_afinet_netifas().unwrap();
    // The lifetime for an ipv6 address on my linux is 48 hours in
    // This can be changed of course.
    //  or 172800 seconds, the first address is as much as I can see on linux the new one.
    //  ip -6 addr list
    // if there is a dhcpv6 address it seems to come first and nvre change.
    // inet6 2a0d:6fe2:5330:6c00::e93  prefixlen 128  scopeid 0x0<global>                 dhcpv6
    // inet6 2a0d:6fe2:5330:6c00:1562:6484:4c03:31ce  prefixlen 64  scopeid 0x0<global>   slac newer
    // inet6 2a0d:6fe2:5330:6c00:e5be:55fa:e63a:b2f3  prefixlen 64  scopeid 0x0<global>   slac oldest

    // Global unicast ipv6 addresses start with 2000 and go up to 3FFF
    //                                          8192  to 16383
    // ( I have only seen the prefix 2a0d 10765 so far.)

    //let  keep_first_ipv6_addr = Ipv6Addr::UNSPECIFIED;

    for (name, ip) in network_interfaces.iter() {
        if name.contains(cur_interface) {
            match *ip {
                IpAddr::V6(ip6) => {
                    if ip6.segments()[0] >= 8192 && ip6.segments()[0] <= 16383 {
                        //Ok(println!("ipv6: {:?}", ip6));
                        return Ok(ip6);
                    }
                }
                IpAddr::V4(_ip4) => (),
                //println!("ipv4: {:?}", _ip4),
                //print!(""),
                //_ => (),
            }
        }
    }

    return Err(Error::LocalIpAddressNotFound);
}