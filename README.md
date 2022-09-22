Noipv6
=================

See INSTALL.md for setup.

### Features

- Supports updating the ipv6 from the machine it is runnig on and the ipv4 seen by NAT.
- A fork of No-IP Linux DUC 3
- Simple design with minimal dependencies
- Do no have to use a configuration file - all config available via environment variables
- DNS-based public IP check
- Allow updating to a specific IP with `--ip-method static:<IP>`
- Run command on IP change

Usage
=====

```
noipv6 Dynamic Update Client

USAGE:
    noipv6 [OPTIONS] --username <USERNAME> --password <PASSWORD>

OPTIONS:
        --check-interval <CHECK_INTERVAL>
            How often to check for a new IP address. Minimum: every 2 minutes
            
            [env: NOIP_CHECK_INTERVAL=]
            [default: 5m]

        --daemon-group <DAEMON_GROUP>
            When daemonizing, become this group
            
            [env: NOIP_DAEMON_GROUP=]

        --daemon-pid-file <DAEMON_PID_FILE>
            When daemonizing, write process id to this file
            
            [env: NOIP_DAEMON_PID_FILE=]

        --daemon-user <DAEMON_USER>
            When daemonizing, become this user
            
            [env: NOIP_DAEMON_USER=]

        --daemonize
            Fork into the background

    -e, --exec-on-change <EXEC_ON_CHANGE>
            Command to run when IP address changes
            
            [env: NOIP_EXEC_ON_CHANGE=]

    -g, --hostnames <HOSTNAMES>
            Comma separated list of groups and hostnames to update. This may be empty when using
            group credentials and updating all hosts in the group
            
            [env: NOIP_HOSTNAMES=]

    -h, --help
            Print help information

        --http-timeout <HTTP_TIMEOUT>
            Timeout when making HTTP requests
            
            [env: NOIP_HTTP_TIMEOUT=]
            [default: 10s]

        --import [<IMPORT>]
            Import config from noip2 and display it as environment variables
            
            [default: /etc/no-ip2.conf]

        --ip-method <IP_METHOD>
            Methods used to discover public IP as a comma separated list. They are tried in order
            until a public IP is found. Failed methods are not retried unless all methods fail.
            
            Possible values are
            - 'aws-metadata': uses the AWS metadata URL to get the Elastic IP
                              associated with your instance.
            - 'dns': Use No-IP's DNS public IP lookup system.
            - 'dns:<nameserver>:<port>:<qname>:<record type>': custom DNS lookup.
            - 'http': No-IP's HTTP method (the default).
            - 'http-port-8245': No-IP's HTTP method on port 8245.
            - 'static:<ip address>': always use this IP address. Helpful with --once.
            - HTTP URL: An HTTP URL that returns only an IP address.
            
            [env: NOIP_IP_METHOD=]
            [default: dns,http,http-port-8245]

    -l, --log-level <LOG_LEVEL>
            Set the log level. Possible values: trace, debug, info, warn, error, critical. Overrides
            --verbose
            
            [env: NOIP_LOG_LEVEL=]

        --once
            Find the public IP and send an update, then exit. This is a good method to verify
            correct credentials

    -p, --password <PASSWORD>
            Your www.noip.com password. For better security, use Update Group credentials.
            https://www.noip.com/members/dns/dyn-groups.php
            
            [env: NOIP_PASSWORD=]

    -u, --username <USERNAME>
            Your www.noip.com username. For better security, use Update Group credentials.
            https://www.noip.com/members/dns/dyn-groups.php
            
            [env: NOIP_USERNAME=]

    -v, --verbose
            Increase logging verbosity. May be used multiple times

    -V, --version
            Print version information
```

Advanced Usage
==============

Daemonize
---------

The most common way to use `noipv6` is with a supervisor such as Systemd. But `noipv6` can run as a daemon on its own.

```
# noipv6 will fork into the background, drop privileges and write the new pid to a file.
noipv6 --daemonize --daemon-user nobody --daemon-group nogroup --daemon-pid-file /var/run/noipv6.pid
```

Perform a single update to a specific IP
----------------------------------------

```
source /etc/noipv6.conf && noipv6 --ip-method static:192.168.1.1 --once
```

Use Custom DNS HTTP Method
------------------------

```
noipv6 --ip-method https://myip.dnsomatic.com
noipv6 --ip-method http://ifconfig.me/ip
```

Use Custom DNS IP Method
------------------------

```
noipv6 --ip-method dns:<nameserver>:<port>:<qname>:<record type>

noipv6 --ip-method dns:resolver1.opendns.com:53:myip.opendns.com:A
noipv6 --ip-method dns:ns1-1.akamaitech.net:53:whoami.akamai.net:A
noipv6 --ip-method dns:ns1.google.com:53:o-o.myaddr.l.google.com:TXT
noipv6 --ip-method dns:a14-64.akam.net:53:whoami.ds.akahelp.net:TXT
```
