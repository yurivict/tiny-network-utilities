# tiny-network-utilities
Minimalistic network server implementations to support VM network connectivity

# tiny-dhcp-server
Simple DHCP server for FreeBSD

## What is tiny-dhcp-server?

This is the minimalistic DHCP server implementation for FreeBSD (has some OS-specific parts).

It responds to DHCP requests on several network interfaces, allocates the unique IP address to each client, and assigns itself as the default gateway and DNS.

## What is it good for?

It is originally designed to be able to initialize the virtual machine network (tapN) when VM is connected to the host through the bridged interface.

## Why tiny-dhcp-server is created?

Standard DHCP implementations suffer from excessive bloat. They require non-trivial configuration, maintenance, have thousands of lines of code. tiny-dhcp-server is minimal, doesn't require any configuration at all, and just runs.

## Requirements

* FreeBSD (tested on 10.1)
* Python 3 installed (tested with python34-3.4.3)
* net/py-netifaces package installed for Python 3 (ex: py34-netifaces-0.10.3)

## How do I run it?

Install it into your FreeBSD system by copying files and installing Python3:
```shell
cp tiny-dhcp-server.py /usr/local/bin/tiny-dhcp-server
cp tiny-dhcp-server /usr/local/etc/rc.d/
pkg install --automatic --no-repo-update python34
(cd /usr/ports/net/py-netifaces && PYTHON_VERSION=3.4 make install clean)
```
and enable it in your /etc/rc.conf:
```shell
tiny_dhcp_server_enable="YES"
tiny_dhcp_server_ifaces="em0 tap1 re1"
```
Or run it as a standalone program:
```shell
tiny-dhcp-server.py em0 tap1 re1
```
tiny-dhcp-server expects interfaces to be up and initialized with an IP address.
