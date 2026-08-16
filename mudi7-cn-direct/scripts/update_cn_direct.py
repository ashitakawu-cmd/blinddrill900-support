#!/usr/bin/env python3
from ipaddress import ip_network
from pathlib import Path
from urllib.request import Request, urlopen

DOMAIN_SOURCE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list"
GEOIP_SOURCE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list"
ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "cn-direct-full.txt"
SAFE = ROOT / "cn-direct.txt"
GLINET = ROOT / "cn-direct-glinet.txt"
COMBINED = ROOT / "cn-direct-glinet-combined.txt"


def fetch_lines(url: str) -> list[str]:
    req = Request(url, headers={"User-Agent": "mudi7-cn-direct-updater/1.0"})
    text = urlopen(req, timeout=60).read().decode("utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def fetch_domains() -> list[str]:
    rows = fetch_lines(DOMAIN_SOURCE)
    if not rows:
        raise SystemExit("Upstream domain list is empty; refusing to overwrite outputs")
    if not all(line.startswith("+.") for line in rows):
        bad = next(line for line in rows if not line.startswith("+."))
        raise SystemExit(f"Unexpected domain format ({bad!r}); refusing to overwrite outputs")
    domains = [line[2:] for line in rows]
    if len(domains) != len(set(domains)):
        raise SystemExit("Duplicate domains detected; refusing to overwrite outputs")
    if len(domains) < 100_000:
        raise SystemExit(f"Unexpectedly small domain set ({len(domains)}); refusing to overwrite outputs")
    return domains


def fetch_cn_ipv4() -> list[str]:
    rows = fetch_lines(GEOIP_SOURCE)
    if not rows:
        raise SystemExit("Upstream CN IP list is empty; refusing to overwrite outputs")

    ipv4: list[str] = []
    seen: set[str] = set()
    for row in rows:
        try:
            network = ip_network(row, strict=False)
        except ValueError as exc:
            raise SystemExit(f"Unexpected CN IP entry ({row!r}): {exc}") from exc
        if network.version != 4:
            continue
        value = str(network)
        if value not in seen:
            seen.add(value)
            ipv4.append(value)

    if len(ipv4) < 4_000:
        raise SystemExit(f"Unexpectedly small CN IPv4 set ({len(ipv4)}); refusing to overwrite outputs")
    return ipv4


def main() -> None:
    domains = fetch_domains()

    # Exact upstream conversion: strip MetaCubeX '+.' prefix only.
    FULL.write_text("\n".join(domains) + "\n", encoding="utf-8")

    # Previous safer variant: remove only the bare single-label `cn` rule.
    safe = [domain for domain in domains if domain != "cn"]
    SAFE.write_text("\n".join(safe) + "\n", encoding="utf-8")

    # GL.iNet Mudi 7's Subscription URL detector rejects two classes from
    # the current MetaCubeX CN set: single-label entries and entries whose
    # first character is numeric. Keep the maximum domain subset it accepts.
    glinet = [domain for domain in domains if "." in domain and not domain[0].isdigit()]
    if len(glinet) < 90_000:
        raise SystemExit(f"Unexpectedly small GL.iNet-compatible set ({len(glinet)}); refusing to overwrite outputs")
    GLINET.write_text("\n".join(glinet) + "\n", encoding="utf-8")

    # Recommended Mudi 7 list: GL.iNet-compatible CN domains plus all CN
    # IPv4 CIDRs. The IP ranges provide a second DIRECT path for Chinese
    # services whose domain names are rejected by the firmware validator.
    cn_ipv4 = fetch_cn_ipv4()
    combined = glinet + cn_ipv4
    COMBINED.write_text("\n".join(combined) + "\n", encoding="utf-8")

    print(
        f"full_domains={len(domains)} safe_domains={len(safe)} "
        f"glinet_domains={len(glinet)} rejected_domains={len(domains) - len(glinet)} "
        f"cn_ipv4={len(cn_ipv4)} combined={len(combined)}"
    )


if __name__ == "__main__":
    main()
