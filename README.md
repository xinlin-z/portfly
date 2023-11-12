# portfly

* [Port Forwarding](#Port-Forwarding)
* [Installation](#Installation)
* [Usage](#Usage)

A pure Python implementation of SSH Port Forwarding, includes
remote forwarding and local forwarding, featured by
non-blocking socket, event IO and UDP forwarding path.

## Port Forwarding

Remote Port Forwarding:

![remote_port_forwarding](/remote_port_forwarding.png)

Local Port Forwarding:

![local_port_forwarding](/local_port_forwarding.png)

## Installation

```shell
$ pip install portfly
```

## Usage

On server side, you need to setup portfly to listen, even udp forwarding
path is used: 

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

Have Fun... ^____^

