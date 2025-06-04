# n2m

AI generated tool that creates note templates from nmap results.

For my intended use case it works perfectly, has not been tested outside of that.

## usage
```
n2m [-o output.md] <nmap-file1> [nmap-file2] ...
```

## intended use case

Idea is that you are running a bunch of nmap scans at the start of a box.

```
- nmap <target_addr> -oN top-1000-tcp.nmap
- nmap <target_addr> -p- -oN all-tcp.nmap
- nmap <target_addr> -sC -sV -oN top-1000-script-version.nmap
- nmap <target_addr> -sU -oN top-1000-udp.nmap
```

Once the scan results are done you pass them into n2m and it generates a markdown file containing all your results as well as making headers for each result.

```
$ n2m top-1000-tcp.nmap all-tcp.nmap top-1000-script-version.nmap top-1000-udp.nmap > nmap.md

$ head nmap.md

# 10.10.11.174

# nmap
## All TCP

\`\`\`
# Nmap 7.95 scan initiated Wed Jun  4 10:04:29 2025 as: /usr/lib/nmap/nmap --privileged -p- -oN all-tcp.nmap 10.10.11.174
Nmap scan report for 10.10.11.174
Host is up (0.27s latency).
Not shown: 65516 filtered tcp ports (no-response)
[...]
```

## build

clone repo and `go build -o n2m ./n2m/src/n2m.go`
