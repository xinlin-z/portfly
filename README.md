# Portfly

* [Port Forwarding Intro](#Port-Forwarding-Intro)
* [Installation](#Installation)
* [Usage](#Usage)

A pure Python implementation mimicking SSH Port Forwarding, includes only 
local/remote forwarding, featured by
non-blocking socket, event IO and TCP/UDP forwarding tunnel.

I developed this project due to the unstable newtork connection
between my laptop and cloud dev host. The remote forwarding of port 22
bridged by UDP tunnel saved me.

## Port Forwarding Intro

Basicly, port forwarding is a port mapping technique that you could
"pull" a remote port down to your local host or "push" a local port 
to remote. There are many use cases, such as intranet penetration.

Remote Port Forwarding:

![remote_port_forwarding](/remote.png)

Local Port Forwarding:

![local_port_forwarding](/local.png)

## Installation

```shell
$ pip install portfly
```

## Usage

On server side, you need to setup portfly to listen, even for udp tunnel
due to the initial TCP connection: 

``` shell
$ python -m portfly -s server_listen_ip:port
```

On client side, you control all the details:

```shell
# remote forwarding by tcp is the default
$ python -m portfly -c [-x] [--log {INFO|DEBUG} <settings>
# local forwarding by tcp:
$ python -m portfly -c -L <settings>
# local forwarding by udp:
$ python -m portfly -c -L -u <udpport> <settings>
# remote forwarding by udp:
$ python -m portfly -u <udpport> <settings>
```

The `<settings>` part is just like ssh, which is:

```text
mapping_port:target_ip:target_port+server_ip:target_port
```

The extra `+` can leave the whole parameters unquoted.

Each client process can map only one port to/from server.
But server can be connected by many clients simultaneously.

Enjoy...XD
