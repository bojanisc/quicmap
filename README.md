# quicmap
## (Pretty) fast QUIC service scanner

quicmap is a relatively fast QUIC service scanner that removes the need to use multiple tools to identify QUIC services, protocol version in use as well as supported ALPN's.

### Main features
- Scan arbitrary hosts, IP addresses, networks and ports and identify QUIC services
- Run arbitray number of threads (50 by default)
- Supports binary searching for ALPN's to speed up the process
- Nice progress bar!

### Installation

```
git clone https://github.com/bojanisc/quicmap.git
cd quicmap
pip3 install -r requirements.txt
python3 quicmap.py -h
```

### -h, --help

```                  
usage: quicmap.py [-h] [-p PORTS] [-t TIMEOUT] [-c CONCURRENCY] hosts

quicmap.py - script that does QUIC scanning

positional arguments:
  hosts                 The target host(s), comma separated hosts or IP range(s)

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Port range (e.g., '80', '1-1024', '80,443,1000-2000'). Default is '1-1000'
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for a UDP connection in seconds. Default is 5 seconds.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent connections to spawn. Default is 50.
```

### Examples 

#### 1) Scan Youtube and Facebook for supported procotols

```
python3 quicmap.py -p 443 youtube.com,facebook.com
100%|█████████████████████████████████████████████████████████████████████████████████████████| 2/2 [00:01<00:00,  1.47it/s]
endpoint        : youtube.com
port            : 443
server_versions : 0x1, 0x5aba0aba, 0xff00001d
ALPN            : h3 (HTTP/3)

endpoint        : facebook.com
port            : 443
server_versions : 0xfaceb002, 0xfaceb00e, 0xfaceb011, 0xfaceb013, 0xfaceb010, 0x1, 0xfaceb003
ALPN            : h3 (HTTP/3)
```

If you notice any issues with the software, please open up an issue. 
Pull requests are welcome.

