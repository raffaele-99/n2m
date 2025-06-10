# n2m

vibe coded go tool for making markdown notes from nmap output

## install
```
make install
```

## usage
```
n2m [-o output.md] [-header] <nmap-file1> [nmap-file2] ...

Usage:
  -header
        include a header with the IP address in the output (default: false)
  -o string
        Output markdown file (optional)

Example:
  n2m all-tcp.nmap
  n2m -o 10.10.11.174.md all-tcp.nmap top-1000-tcp-script-scan.nmap udp-1000.nmap
  n2m -header -o results.md *.nmap
```

## intended use case
meant for timeboxed oscp style stuff
```
$ sudo nmap -Pn -T4 -v -p- <target_addr> -oN tcp-first.nmap
$ sudo nmap -Pn -v -sCV -p <open_ports_from_first_pass> <target_addr> -oN tcp-second.nmap
$ sudo nmap -Pn -sU --top-ports 1000 <target_addr> -oN udp-first.nmap
$ n2m *.nmap > ./notes/nmap.md
```
