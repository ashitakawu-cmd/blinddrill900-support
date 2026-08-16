#!/usr/bin/env python3
from pathlib import Path
from urllib.request import Request, urlopen

SOURCE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list"
ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "cn-direct-full.txt"
SAFE = ROOT / "cn-direct.txt"


def fetch_source() -> list[str]:
    req = Request(SOURCE, headers={"User-Agent": "mudi7-cn-direct-updater/1.0"})
    text = urlopen(req, timeout=60).read().decode("utf-8")
    rows = [line.strip() for line in text.splitlines() if line.strip()]
    if not rows:
        raise SystemExit("Upstream list is empty; refusing to overwrite outputs")
    if not all(line.startswith("+.") for line in rows):
        bad = next(line for line in rows if not line.startswith("+."))
        raise SystemExit(f"Unexpected upstream format ({bad!r}); refusing to overwrite outputs")
    return rows


def main() -> None:
    rows = fetch_source()
    domains = [line[2:] for line in rows]

    if len(domains) != len(set(domains)):
        raise SystemExit("Duplicate domains detected; refusing to overwrite outputs")
    if len(domains) < 100_000:
        raise SystemExit(f"Unexpectedly small upstream set ({len(domains)}); refusing to overwrite outputs")

    FULL.write_text("\n".join(domains) + "\n", encoding="utf-8")

    # Recommended Mudi list: exclude the bare single-label `cn` rule.
    # It corresponds to upstream `+.cn` and can be over-broad for services
    # whose international traffic uses a .cn hostname.
    safe = [domain for domain in domains if domain != "cn"]
    SAFE.write_text("\n".join(safe) + "\n", encoding="utf-8")

    print(f"full={len(domains)} safe={len(safe)}")


if __name__ == "__main__":
    main()
