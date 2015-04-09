# tiny-dhcp-server
Simple DHCP server for FreeBSD

## What is tiny-dhcp-server?
This is the minimalistic DHCP server implementation for FreeBSD (has some OS-specific parts).

It responds on one specified network interface, allocates the new IP address for each server, and assigns itself as the default gateway and DNS.

## What is it good for?
It is originally designed to be able to initialize the virtual machine network (tapN) when VM is connected to the host through the bridged interface.

## Why tiny-dhcp-server is created?
Standard DHCP implementations suffer from excessive bloat. They require non-trivial configuration, maintenance, have thousands lines of code. tiny-dhcp-server is minimal, doesn't require any configuration, and just runs.

## Requirements
* FreeBSD (tested on 10.1)
* Python 3 installed (tested with python34-3.4.3)
* net/py-netifaces package installed for Python 3 (ex: py34-netifaces-0.10.3)

## How do I run it?
Install it into your FreeBSD system by copying files:<br />
cp tiny-dhcp-server.py /usr/local/bin/tiny-dhcp-server<br />
cp tiny-dhcp-server /usr/local/etc/rc.d/<br />

Or run it as a standalone program:<br />
tiny-dhcp-server.py tap0
