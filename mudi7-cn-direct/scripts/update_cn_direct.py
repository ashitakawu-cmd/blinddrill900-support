#!/usr/bin/env python3
from ipaddress import ip_network
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager
from urllib.request import Request, urlopen

UPSTREAM_COMMIT_API = "https://api.github.com/repos/MetaCubeX/meta-rules-dat/commits/meta"
UPSTREAM_RAW_BASE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
DOMAIN_SOURCE_PATH = "geo/geosite/cn.list"
GEOIP_SOURCE_PATH = "geo/geoip/cn.list"
COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "cn-direct-full.txt"
SAFE = ROOT / "cn-direct.txt"
GLINET = ROOT / "cn-direct-glinet.txt"
COMBINED = ROOT / "cn-direct-glinet-combined.txt"
PLUS = ROOT / "cn-direct-glinet-combined-plus.txt"
SIGNED_RUNTIME_PLUS = ROOT / "cn-direct-signed-runtime-plus.txt"
TRANSACTION_DIR = ROOT / ".cn-direct-output-transaction"
MIN_GLINET_DOMAINS = 90_000
TRANSACTION_VERSION = 1
TRANSACTION_PREPARED = "PREPARED"
TRANSACTION_COMMITTED = "COMMITTED"

# MetaCubeX currently emits a small set of bare labels in the CN geosite.
# For the signed runtime, treat them as explicit domain suffix rules only when
# they are on this reviewed allowlist.  Fail closed if upstream adds or removes
# a bare label so a broad suffix can never enter production without review.
SIGNED_RUNTIME_SINGLE_LABELS = frozenset({
    "alibaba",
    "alipay",
    "anquan",
    "baidu",
    "citic",
    "cn",
    "icbc",
    "shouji",
    "sina",
    "sohu",
    "taobao",
    "tmall",
    "unicom",
    "wang",
    "weibo",
    "xihuan",
    "xn--1qqw23a",
    "xn--3bst00m",
    "xn--3ds443g",
    "xn--55qw42g",
    "xn--55qx5d",
    "xn--5tzm5g",
    "xn--6frz82g",
    "xn--6qq986b3xl",
    "xn--8y0a063a",
    "xn--9et52u",
    "xn--9krt00a",
    "xn--czr694b",
    "xn--czrs0t",
    "xn--czru2d",
    "xn--fiq228c5hs",
    "xn--fiq64b",
    "xn--fiqs8s",
    "xn--fiqz9s",
    "xn--fjq720a",
    "xn--g2xx48c",
    "xn--hxt814e",
    "xn--imr513n",
    "xn--io0a7i",
    "xn--kput3i",
    "xn--nyqy26a",
    "xn--otu796d",
    "xn--rhqv96g",
    "xn--ses554g",
    "xn--unup4y",
    "xn--vhquv",
    "xn--vuq861b",
    "xn--xhq521b",
    "xn--zfr164b",
    "yun",
})
SIGNED_RUNTIME_REJECTED_SINGLE_LABELS = frozenset({"full", "ms"})

# Extra DIRECT domains for the opt-in "Plus" list.
#
# Design goals:
# - Keep the CN-only baseline unchanged.
# - Bypass AWG for high-volume Apple and Microsoft system/M365 traffic.
# - Keep Microsoft Copilot eligible for AWG by deliberately NOT adding
#   the broad parent microsoft.com or cloud.microsoft suffixes.
# - Make common China/work apps explicit instead of relying only on CN GeoIP.
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

    # WeChat / QQ / WeCom. Some shared media suffixes are missing from the
    # upstream CN geosite output, so keep them explicit in Plus.
    "qq.com",
    "weixin.com",
    "qpic.cn",
    "qlogo.cn",
    "gtimg.com",
    "gtimg.cn",
    "idqqimg.com",
    "wxworklive.com",

    # Douyin / domestic ByteDance core traffic. Most are already present in
    # the CN baseline; snssdk.com is kept explicit because it is a current
    # ByteDance/Douyin base domain but is absent from the tested CN output.
    "douyin.com",
    "douyincdn.com",
    "amemv.com",
    "pstatp.com",
    "snssdk.com",
    "byteimg.com",
    "bytecdn.com",
    "bytedance.com",
    "bytedance.net",

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


def resolve_upstream_commit() -> str:
    req = Request(
        UPSTREAM_COMMIT_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mudi7-cn-direct-updater/1.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        payload = json.loads(urlopen(req, timeout=60).read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot resolve upstream commit: {exc}") from exc
    commit = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(commit, str) or COMMIT_SHA_PATTERN.fullmatch(commit) is None:
        raise SystemExit("Upstream API returned an invalid commit SHA; refusing to download sources")
    return commit


def upstream_raw_url(commit: str, source_path: str) -> str:
    if COMMIT_SHA_PATTERN.fullmatch(commit) is None:
        raise RuntimeError("Cannot build an upstream URL from an invalid commit SHA")
    return f"{UPSTREAM_RAW_BASE}/{commit}/{source_path}"


def fetch_domains(upstream_commit: str) -> list[str]:
    rows = fetch_lines(upstream_raw_url(upstream_commit, DOMAIN_SOURCE_PATH))
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


def fetch_cn_ipv4(upstream_commit: str) -> list[str]:
    rows = fetch_lines(upstream_raw_url(upstream_commit, GEOIP_SOURCE_PATH))
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


def signed_runtime_domains(domains: list[str]) -> list[str]:
    observed = {domain for domain in domains if "." not in domain}
    expected = SIGNED_RUNTIME_SINGLE_LABELS | SIGNED_RUNTIME_REJECTED_SINGLE_LABELS
    if observed != expected:
        added = sorted(observed - expected)
        removed = sorted(expected - observed)
        raise SystemExit(
            "Upstream single-label set changed; refusing to overwrite outputs "
            f"(added={added!r}, removed={removed!r})"
        )
    return [
        domain
        for domain in domains
        if "." in domain or domain in SIGNED_RUNTIME_SINGLE_LABELS
    ]


def output_destinations() -> list[Path]:
    return [FULL, SAFE, GLINET, COMBINED, PLUS, SIGNED_RUNTIME_PLUS]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_synced(path: Path, data: bytes, mode: int = 0o644) -> None:
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())


def _write_state(state: str) -> None:
    descriptor, raw_temp = tempfile.mkstemp(prefix=".state.", dir=TRANSACTION_DIR)
    temp_path = Path(raw_temp)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write((state + "\n").encode("ascii"))
            handle.flush()
            os.fchmod(handle.fileno(), 0o644)
            os.fsync(handle.fileno())
        os.replace(temp_path, TRANSACTION_DIR / "state")
        _fsync_directory(TRANSACTION_DIR)
    finally:
        temp_path.unlink(missing_ok=True)


def _validate_destinations(destinations: list[Path]) -> None:
    if len(destinations) != len(set(destinations)):
        raise RuntimeError("Output transaction contains duplicate destinations")
    if not destinations:
        raise RuntimeError("Output transaction is empty")
    parent = destinations[0].parent
    if any(destination.parent != parent for destination in destinations):
        raise RuntimeError("All output transaction files must share one directory")
    if TRANSACTION_DIR.parent != parent:
        raise RuntimeError("Output transaction directory must share the output directory")
    if len({destination.name for destination in destinations}) != len(destinations):
        raise RuntimeError("Output transaction contains duplicate filenames")


def _read_existing(path: Path) -> tuple[bytes, int] | None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("This platform cannot safely reject output symbolic links")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RuntimeError(f"Output is a symbolic link: {path.name}") from exc
        raise
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"Output is not a regular file: {path.name}")
        return handle.read(), stat.S_IMODE(info.st_mode)


def _read_manifest(destinations: list[Path]) -> dict:
    try:
        manifest = json.loads((TRANSACTION_DIR / "manifest.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Output transaction manifest is missing or invalid") from exc
    expected_names = [destination.name for destination in destinations]
    entries = manifest.get("outputs")
    if (
        manifest.get("version") != TRANSACTION_VERSION
        or not isinstance(entries, list)
        or [entry.get("name") for entry in entries if isinstance(entry, dict)] != expected_names
        or len(entries) != len(expected_names)
    ):
        raise RuntimeError("Output transaction manifest does not match expected outputs")
    for entry in entries:
        if set(entry) != {"name", "existed", "old_sha256", "old_mode", "new_sha256", "new_mode"}:
            raise RuntimeError("Output transaction manifest has unexpected fields")
        if not isinstance(entry["existed"], bool):
            raise RuntimeError("Output transaction existence marker is invalid")
        if entry["existed"]:
            if not isinstance(entry["old_sha256"], str) or not isinstance(entry["old_mode"], int):
                raise RuntimeError("Output transaction old-file metadata is invalid")
        elif entry["old_sha256"] is not None or entry["old_mode"] is not None:
            raise RuntimeError("Output transaction missing-file metadata is invalid")
        if not isinstance(entry["new_sha256"], str) or not isinstance(entry["new_mode"], int):
            raise RuntimeError("Output transaction new-file metadata is invalid")
    return manifest


def _install_bytes(destination: Path, data: bytes, mode: int) -> None:
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temp_path = Path(raw_temp)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
        _fsync_directory(destination.parent)
    finally:
        temp_path.unlink(missing_ok=True)


def _verify_transaction_files(manifest: dict, destinations: list[Path], version: str) -> None:
    for index, (entry, destination) in enumerate(zip(manifest["outputs"], destinations)):
        if version == "old" and not entry["existed"]:
            if os.path.lexists(destination):
                raise RuntimeError(f"Originally absent output still exists: {destination.name}")
            continue
        expected_hash = entry[f"{version}_sha256"]
        expected_mode = entry[f"{version}_mode"]
        current = _read_existing(destination)
        if current is None:
            raise RuntimeError(f"Expected output is missing: {destination.name}")
        data, mode = current
        if _sha256(data) != expected_hash or mode != expected_mode:
            raise RuntimeError(f"Output verification failed: {destination.name}")
        if version == "old":
            backup = (TRANSACTION_DIR / "old" / f"{index:02d}.old").read_bytes()
            if _sha256(backup) != expected_hash:
                raise RuntimeError(f"Output backup verification failed: {destination.name}")


def _verify_staged_transaction(manifest: dict) -> None:
    for index, entry in enumerate(manifest["outputs"]):
        new_data = (TRANSACTION_DIR / "new" / f"{index:02d}.new").read_bytes()
        if _sha256(new_data) != entry["new_sha256"]:
            raise RuntimeError(f"Staged output verification failed: {entry['name']}")
        if entry["existed"]:
            old_data = (TRANSACTION_DIR / "old" / f"{index:02d}.old").read_bytes()
            if _sha256(old_data) != entry["old_sha256"]:
                raise RuntimeError(f"Output backup verification failed: {entry['name']}")


def _remove_transaction_dir() -> None:
    if not os.path.lexists(TRANSACTION_DIR):
        return
    info = TRANSACTION_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("Output transaction path is not a directory")
    shutil.rmtree(TRANSACTION_DIR)
    _fsync_directory(TRANSACTION_DIR.parent)


def recover_output_transaction(destinations: list[Path]) -> None:
    _validate_destinations(destinations)
    if not os.path.lexists(TRANSACTION_DIR):
        return
    info = TRANSACTION_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("Output transaction path is not a directory")
    state_path = TRANSACTION_DIR / "state"
    if not state_path.exists():
        # No formal file is installed before PREPARED is durable. An
        # interrupted preparation can therefore be discarded safely.
        _remove_transaction_dir()
        return
    state_value = state_path.read_text(encoding="ascii").strip()
    if state_value not in {TRANSACTION_PREPARED, TRANSACTION_COMMITTED}:
        raise RuntimeError("Output transaction state is invalid")
    manifest = _read_manifest(destinations)
    if state_value == TRANSACTION_COMMITTED:
        _verify_transaction_files(manifest, destinations, "new")
        _remove_transaction_dir()
        return

    # Verify every backup before changing any formal output. Recovery is
    # idempotent: if it is interrupted, PREPARED remains and the same exact
    # backups are used again on the next invocation.
    for index, entry in enumerate(manifest["outputs"]):
        if not entry["existed"]:
            continue
        backup = (TRANSACTION_DIR / "old" / f"{index:02d}.old").read_bytes()
        if _sha256(backup) != entry["old_sha256"]:
            raise RuntimeError(f"Output backup verification failed: {entry['name']}")
    for index, (entry, destination) in enumerate(zip(manifest["outputs"], destinations)):
        if entry["existed"]:
            backup = (TRANSACTION_DIR / "old" / f"{index:02d}.old").read_bytes()
            _install_bytes(destination, backup, entry["old_mode"])
        elif os.path.lexists(destination):
            destination.unlink()
            _fsync_directory(destination.parent)
    _verify_transaction_files(manifest, destinations, "old")
    _fsync_directory(destinations[0].parent)
    _remove_transaction_dir()


def write_outputs(outputs: dict[Path, list[str]]) -> None:
    destinations = list(outputs)
    _validate_destinations(destinations)
    if os.path.lexists(TRANSACTION_DIR):
        raise RuntimeError("Unrecovered output transaction exists")
    TRANSACTION_DIR.mkdir(mode=0o700)
    (TRANSACTION_DIR / "old").mkdir(mode=0o700)
    (TRANSACTION_DIR / "new").mkdir(mode=0o700)
    _fsync_directory(TRANSACTION_DIR.parent)
    manifest = {"version": TRANSACTION_VERSION, "outputs": []}
    try:
        for index, (destination, rows) in enumerate(outputs.items()):
            old = _read_existing(destination)
            new_data = ("\n".join(rows) + "\n").encode("utf-8")
            if old is None:
                existed = False
                old_hash = None
                old_mode = None
                new_mode = 0o644
            else:
                old_data, old_mode = old
                existed = True
                old_hash = _sha256(old_data)
                new_mode = old_mode
                _write_synced(TRANSACTION_DIR / "old" / f"{index:02d}.old", old_data, old_mode)
            _write_synced(TRANSACTION_DIR / "new" / f"{index:02d}.new", new_data, new_mode)
            manifest["outputs"].append({
                "name": destination.name,
                "existed": existed,
                "old_sha256": old_hash,
                "old_mode": old_mode,
                "new_sha256": _sha256(new_data),
                "new_mode": new_mode,
            })
        manifest_data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        _write_synced(TRANSACTION_DIR / "manifest.json", manifest_data)
        _fsync_directory(TRANSACTION_DIR / "old")
        _fsync_directory(TRANSACTION_DIR / "new")
        _fsync_directory(TRANSACTION_DIR)
        _verify_staged_transaction(manifest)
        _write_state(TRANSACTION_PREPARED)

        for index, (entry, destination) in enumerate(zip(manifest["outputs"], destinations)):
            new_data = (TRANSACTION_DIR / "new" / f"{index:02d}.new").read_bytes()
            if _sha256(new_data) != entry["new_sha256"]:
                raise RuntimeError(f"Staged output verification failed: {destination.name}")
            _install_bytes(destination, new_data, entry["new_mode"])
        _verify_transaction_files(manifest, destinations, "new")
        for destination in destinations:
            with destination.open("rb") as handle:
                os.fsync(handle.fileno())
        _fsync_directory(destinations[0].parent)
        _write_state(TRANSACTION_COMMITTED)
        _remove_transaction_dir()
    except Exception as original_error:
        try:
            recover_output_transaction(destinations)
        except Exception as recovery_error:
            raise RuntimeError(
                f"Output transaction failed and recovery is incomplete: {recovery_error}"
            ) from original_error
        raise


@contextmanager
def output_transaction_lock():
    descriptor = os.open(TRANSACTION_DIR.parent, os.O_RDONLY)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another output transaction is running") from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _main_locked() -> None:
    upstream_commit = resolve_upstream_commit()
    domains = fetch_domains(upstream_commit)

    # Validate the broadest signed-runtime class before touching any output.
    # If MetaCubeX changes its bare-label set, every existing file stays byte
    # for byte unchanged until that new suffix has been reviewed.
    runtime_domains = signed_runtime_domains(domains)

    # Exact upstream conversion: strip MetaCubeX '+.' prefix only.

    # Previous safer variant: remove only the bare single-label `cn` rule.
    safe = [domain for domain in domains if domain != "cn"]

    # GL.iNet Mudi 7's Subscription URL detector rejects two classes from
    # the current MetaCubeX CN set: single-label entries and entries whose
    # first character is numeric. Keep the maximum domain subset it accepts.
    glinet = [domain for domain in domains if "." in domain and not domain[0].isdigit()]
    if len(glinet) < MIN_GLINET_DOMAINS:
        raise SystemExit(f"Unexpectedly small GL.iNet-compatible set ({len(glinet)}); refusing to overwrite outputs")

    # Stable baseline: GL.iNet-compatible CN domains plus all CN IPv4 CIDRs.
    cn_ipv4 = fetch_cn_ipv4(upstream_commit)
    combined = glinet + cn_ipv4

    # Opt-in Plus list: add explicit Apple, Microsoft system/M365 and common
    # China/work-app domain suffixes without broad parent rules that would
    # pull AI services such as Copilot into DIRECT.
    extra = validate_plus_domains()
    glinet_set = set(glinet)
    plus_extra = [domain for domain in extra if domain not in glinet_set]
    plus = glinet + plus_extra + cn_ipv4
    if len(plus) != len(set(plus)):
        raise SystemExit("Duplicate entries detected in Plus output; refusing to overwrite outputs")

    # The signed router consumer writes the canonical list directly and does
    # not use GL.iNet's Subscription URL validator.  It can therefore carry
    # numeric-leading FQDNs and the reviewed China-related bare suffixes after
    # their dedicated native rtp2/dns_mark rollback tests pass.  Unreviewed
    # bare suffixes fail closed; `full` and Montserrat's `.ms` stay excluded.
    signed_runtime_set = set(runtime_domains)
    signed_runtime_extra = [domain for domain in extra if domain not in signed_runtime_set]
    signed_runtime_plus = runtime_domains + signed_runtime_extra + cn_ipv4
    if len(signed_runtime_plus) != len(set(signed_runtime_plus)):
        raise SystemExit("Duplicate entries detected in signed runtime output; refusing to overwrite outputs")

    write_outputs({
        FULL: domains,
        SAFE: safe,
        GLINET: glinet,
        COMBINED: combined,
        PLUS: plus,
        SIGNED_RUNTIME_PLUS: signed_runtime_plus,
    })

    print(f"upstream_commit={upstream_commit}")
    print(
        f"full_domains={len(domains)} safe_domains={len(safe)} "
        f"glinet_domains={len(glinet)} rejected_domains={len(domains) - len(glinet)} "
        f"cn_ipv4={len(cn_ipv4)} combined={len(combined)} "
        f"plus_extra={len(plus_extra)} plus={len(plus)} "
        f"signed_runtime_domains={len(runtime_domains)} "
        f"signed_runtime_extra={len(signed_runtime_extra)} "
        f"signed_runtime_plus={len(signed_runtime_plus)}"
    )


def main() -> None:
    with output_transaction_lock():
        recover_output_transaction(output_destinations())
        _main_locked()


if __name__ == "__main__":
    main()
