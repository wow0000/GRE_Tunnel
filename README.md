# GRE Tunnel for Windows

This project provides a stable and high performance GRE tunnel for Windows using [WinTun](https://wintun.net) driver.

It does not support advanced features of GRE such as Sequences or Keys.

## More information:

* Packet sent from an IP that isn't the GRE Server will be dropped.
* GRE packets with non-IPv4 packets will be dropped.
* Logs are written next to the client in the *gre.log* file.
* To prevent crashs, only the following protocols are whitelisted: TCP, UDP and ICMP (*gre.cpp:58*)
* Logs won't be written more than 3 times.

## Setup

### First tunnel

```bash
GRETunnel.exe [Public interface IP] [GRE Server IP] [Our IP on the tunnel] [GRE Server IP on the tunnel] (CIDR: Optional, Default: 30) (Adapter name: Optional)
./GRETunnel.exe 192.168.1.127 192.168.1.25 192.168.168.2 192.168.168.1 24
```

# Testings and comparison about WireGuard

## Note
Testing data is outdated. Don't use it as a reference.

## Test setup (client)
* Windows Server 2019 (Build 17763)
* Xeon E-2288G
* 10G/up 1G/down (OVH)
* Bare Metal
* WinTun 0.13
* The GRE server was running Linux on the same hardware/network.
* WireGuard-NT (16 Sept.)

## Results compared to WireGuard
Download/Upload:
* Saturating Upload & Download speeds in both cases (no differences here)

Packets per seconds on small packets (1-5 Bytes):
* WireGuard: 330kpps | \~60mbps
* GRE      : 787kpps | \~120mbps

CPU:
* WireGuard will perform much better than the GRE Tunnel thanks to their kernel driver.

## Interpreted results:

The GRE implementations is much lighter on the server thanks to the lack of encryption and will be much faster on small packets. However, Wireguard still performs better in terms of CPU management on the client and seems to get a better download/upload speed using large packets (The hardware couldn't test over 1Gb/s).

# Acknowledgement

* Gizmo
* Zx2c4 for support about WinTun behavior on malformed packets
* WireGuard for [WinTun](https://wintun.net) on Windows
* [EasyLogging++](https://github.com/amrayn/easyloggingpp)
