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
PLUS = ROOT / "cn-direct-glinet-combined-plus.txt"

# Extra DIRECT domains for the opt-in "Plus" list.
#
# Design goals:
# - Keep the CN-only baseline unchanged.
# - Bypass AWG for high-volume Apple and Microsoft system/M365 traffic.
# - Keep Microsoft Copilot eligible for AWG by deliberately NOT adding
#   the broad parent microsoft.com or cloud.microsoft suffixes.
# - Make common work apps explicit instead of relying only on CN GeoIP.
EXTRA_DIRECT_DOMAINS = [
    # Apple: App Store, updates, Apple Account, iCloud, push/CDN.
    "apple.com",
    "icloud.com",
    "icloud-content.com",
    "me.com",
    "mzstatic.com",
    "aaplimg.com",
    "cdn-apple.com",
    "apple-cloudkit.com",
    "apple-dns.net",

    # Microsoft: Windows Update / Store / Defender delivery.
    "windowsupdate.com",
    "windowsupdate.microsoft.com",
    "update.microsoft.com",
    "download.microsoft.com",
    "mp.microsoft.com",
    "wns.windows.com",

    # Microsoft 365 / Office / OneDrive / Outlook / Teams.
    # Do not add microsoft.com or cloud.microsoft; those would also catch
    # Copilot and other AI endpoints that should remain on AWG.
    "office.com",
    "office365.com",
    "office.net",
    "officeapps.live.com",
    "online.office.com",
    "office.live.com",
    "officecdn.microsoft.com",
    "cdn.office.net",
    "msocdn.com",
    "onedrive.com",
    "sharepoint.com",
    "sharepointonline.com",
    "outlook.com",
    "live.com",
    "sfx.ms",
    "gfx.ms",
    "svc.ms",
    "onenote.com",
    "onenote.net",
    "outlookmobile.com",
    "acompli.net",
    "microsoft365.com",
    "microsoftonline.com",
    "msauth.net",
    "msauthimages.net",
    "msftauth.net",
    "msftauthimages.net",
    "teams.microsoft.com",
    "teams.cloud.microsoft",
    "outlook.cloud.microsoft",
    "activation.sls.microsoft.com",
    "officeclient.microsoft.com",
    "office15client.microsoft.com",
    "officeredir.microsoft.com",
    "officepreviewredir.microsoft.com",
    "appsforoffice.microsoft.com",
    "onestore.ms",

    # WeCom / WeChat Work.
    "qq.com",
    "weixin.com",
    "qpic.cn",
    "gtimg.com",
    "wxworklive.com",

    # XiamenAir / MF E-home.
    "xiamenair.com",
    "xiamenair.com.cn",

    # DingTalk.
    "dingtalk.com",
    "dingtalk.io",
    "dingtalk.net",
    "dingtalkapps.com",
    "dingtalkcloud.com",
    "dingtalkcs.com",
    "dingrtc.com",
    "aliwork.com",
    "alicdn.com",
    "alicdn.net",
    "aliyuncs.com",

    # Feishu / Lark.
    "feishu.cn",
    "feishu.net",
    "feishuapp.com",
    "feishuapp-cdn.net",
    "feishucdn.com",
    "feishudoc.com",
    "feishuimg.com",
    "feishukacdn.com",
    "feishuhuiyi.com",
    "feishumeetings.com",
    "feishuoffice.com",
    "feishupkg.com",
    "feishuvc.com",
    "feishu-3rd-party-services.com",
    "feishuopenplatformrecord.com",
    "feishuwx.net",
    "larksuite.com",
    "larkoffice.com",
]

FORBIDDEN_PLUS_PARENTS = {
    "microsoft.com",
    "cloud.microsoft",
    "google.com",
    "youtube.com",
    "github.com",
    "openai.com",
    "anthropic.com",
}


def fetch_lines(url: str) -> list[str]:
    req = Request(url, headers={"User-Agent": "mudi7-cn-direct-updater/1.1"})
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


def validate_plus_domains() -> list[str]:
    extra: list[str] = []
    seen: set[str] = set()
    for domain in EXTRA_DIRECT_DOMAINS:
        value = domain.strip().lower()
        if value in seen:
            raise SystemExit(f"Duplicate Plus domain ({value!r}); refusing to overwrite outputs")
        seen.add(value)
        if value in FORBIDDEN_PLUS_PARENTS:
            raise SystemExit(f"Forbidden broad Plus domain ({value!r}); refusing to overwrite outputs")
        if "." not in value or value[0].isdigit():
            raise SystemExit(f"GL.iNet-incompatible Plus domain ({value!r}); refusing to overwrite outputs")
        extra.append(value)
    return extra


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

    # Stable baseline: GL.iNet-compatible CN domains plus all CN IPv4 CIDRs.
    cn_ipv4 = fetch_cn_ipv4()
    combined = glinet + cn_ipv4
    COMBINED.write_text("\n".join(combined) + "\n", encoding="utf-8")

    # Opt-in Plus list: add explicit Apple, Microsoft system/M365 and work-app
    # domain suffixes without broad parent rules that would pull AI services
    # such as Copilot into DIRECT.
    extra = validate_plus_domains()
    glinet_set = set(glinet)
    plus_extra = [domain for domain in extra if domain not in glinet_set]
    plus = glinet + plus_extra + cn_ipv4
    if len(plus) != len(set(plus)):
        raise SystemExit("Duplicate entries detected in Plus output; refusing to overwrite outputs")
    PLUS.write_text("\n".join(plus) + "\n", encoding="utf-8")

    print(
        f"full_domains={len(domains)} safe_domains={len(safe)} "
        f"glinet_domains={len(glinet)} rejected_domains={len(domains) - len(glinet)} "
        f"cn_ipv4={len(cn_ipv4)} combined={len(combined)} "
        f"plus_extra={len(plus_extra)} plus={len(plus)}"
    )


if __name__ == "__main__":
    main()
