# Default 20-port exposure profile

`exposure20` is the default selection for native and Termux random discovery.
The order is a heuristic review queue based on the potential impact of exposed
control planes, remote access and data services. It is not a measured global
exploitation ranking, CVSS score, product fingerprint or finding of vulnerability.
Public web applications can also have critical vulnerabilities; an individual
asset's version, configuration and CVE evidence determine its actual priority.

The shared source is [portprofiles/exposure20.json](../portprofiles/exposure20.json),
embedded in Go binaries and read by the Python generator. Python emits all 20
ports per IP in this order; the native SYN scanner samples ports uniformly from
the selected set. Review order does not change the configured network rate.

| Review order | TCP port | Conventional service hint | Collector action |
| --- | --- | --- | --- |
| 1 | 2375 | Docker API | TCP only |
| 2 | 10250 | Kubelet API | Direct TLS |
| 3 | 6443 | Kubernetes API | Direct TLS |
| 4 | 445 | SMB | TCP only |
| 5 | 3389 | RDP | TCP only |
| 6 | 5985 | WinRM HTTP | TCP only |
| 7 | 5986 | WinRM HTTPS | Direct TLS |
| 8 | 5900 | VNC | TCP only |
| 9 | 22 | SSH | TCP only |
| 10 | 6379 | Redis | TCP only |
| 11 | 27017 | MongoDB | TCP only |
| 12 | 9200 | Elasticsearch HTTP or HTTPS | TCP only |
| 13 | 1433 | Microsoft SQL Server | TCP only |
| 14 | 5432 | PostgreSQL | TCP only |
| 15 | 3306 | MySQL | TCP only |
| 16 | 443 | HTTPS | Direct TLS |
| 17 | 8443 | Alternate HTTPS | Direct TLS |
| 18 | 80 | HTTP | TCP only |
| 19 | 8080 | Alternate HTTP | TCP only |
| 20 | 21 | FTP | AUTH TLS certificate collection |

## Run on Termux

Update and rebuild the collector before using the expanded profile:

```bash
git pull --ff-only
CGO_ENABLED=0 go build -o certscout ./cmd/certscout
mkdir -p results
set -o pipefail
python3 -u tools/random_targets.py --count 100 --port-profile exposure20 \
  | ./certscout service --max-threads=100 --rate-limit=20 --timeout=5s \
      --retries=1 --sni-limit=2 \
  | tee -a results/services.jsonl
```

This produces 2,000 input endpoints. The collector's 20-starts/second cap includes
retries and SNI follow-ups; timeouts and retries can extend runtime. The generator
itself makes no connections. Its masscan exclusions remain active by default;
additional `--excludefile` entries are additive. The raw native scanner still
requires its original packet-capture privileges and platform support.

`--list-ports` prints the effective comma-separated selection and exits. Explicit
ports override the selected profile. Both generators also support
`--port-profile certificates`; the native `--certificate-profile` flag remains.

`tcp_connected: true` records at least one established TCP connection for the
outcome, including a connection whose subsequent TLS exchange failed. The stderr
summary counts these connections separately from certificates and errors; the
counts can overlap. A successful TCP-only outcome is not a certificate error.
`service_hint` and `port_review_order` are derived solely from the conventional
port mapping and do not identify the actual remote application.

TCP-only checks send no application bytes and make no authentication attempts.
Their `ssl.enabled: false` means TLS was not assessed. Some services can use TLS
on these same ports; explicitly select `--protocol=tls` or an endpoint's protocol
field for direct TLS, while service-specific database/RDP TLS upgrades require
other tooling. Certificate-only domain exports ignore these non-certificate
outcomes; retain `services.jsonl` for the complete reachability evidence.

## Selection references

- [CISA internet exposure reduction](https://www.cisa.gov/resources-tools/resources/exposure-reduction) and [management interface guidance](https://www.cisa.gov/news-events/alerts/2023/06/13/cisa-issues-bod-23-02-mitigating-risk-internet-exposed-management-interfaces).
- [Docker remote daemon access](https://docs.docker.com/engine/daemon/remote-access/) explains the potential host-level impact of an unsecured daemon.
- [Kubernetes port reference](https://kubernetes.io/docs/reference/networking/ports-and-protocols/) identifies API/control-plane ports.
- [Redis security](https://redis.io/docs/latest/management/security/) and [Elasticsearch network settings](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/networking-settings) discuss the impact of unprotected public data services.
- [Microsoft WinRM security](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/winrmsecurity) documents its default ports and access controls.

The selection is a maintained heuristic, not an automatic conversion of the
KEV/EPSS report into targets. The existing CVE prioritizer can rank actual
inventory findings when product/version evidence becomes available.
