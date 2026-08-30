# Mudi 7 CN DIRECT ruleset

This directory publishes GL.iNet VPN Policy compatible DIRECT exclusion lists for Mudi 7.

## Stable CN-only subscription

Use `cn-direct-glinet-combined.txt` when you want the conservative baseline: matched China domains and China IPv4 destinations use **Non-VPN / DIRECT**, while unmatched traffic can continue through the AWG profile.

The baseline combines:

- the maximum subset of MetaCubeX `geo/geosite/cn.list` accepted by the tested Mudi 7 Subscription URL validator; and
- MetaCubeX China IPv4 CIDRs from `geo/geoip/cn.list` as a fallback for Chinese services whose domain names the firmware refuses to import.

This provides two DIRECT matching paths: domain first, then destination IPv4 range.

## Plus subscription

Use `cn-direct-glinet-combined-plus.txt` when Apple/Microsoft system traffic and common work apps should also bypass AWG.

Plus starts from the same CN-only baseline and adds explicit domain suffixes for:

- Apple core services, App Store, iCloud, software updates and Apple CDN traffic;
- Windows Update/Store/Defender delivery plus Microsoft 365, Office, OneDrive, Outlook and Teams;
- WeCom / WeChat Work;
- XiamenAir / MF E-home;
- DingTalk; and
- Feishu / Lark.

The Plus generator deliberately does **not** add the broad `microsoft.com` or `cloud.microsoft` parent suffixes. This keeps unrelated Microsoft/AI traffic such as Copilot eligible for the normal AWG fallback instead of sweeping all Microsoft traffic into DIRECT.

The original `cn-direct-glinet-combined.txt` remains unchanged in purpose so it can be used as a rollback/A-B-test baseline.

## Signed runtime candidate

`cn-direct-signed-runtime-plus.txt` is for the signed, transactional router
consumer only. It keeps all ordinary FQDNs from the same MetaCubeX source,
including numeric-leading domains, plus 50 explicitly reviewed China-related
single-label suffixes. The non-delegated `full` label and Montserrat `.ms`
country-code suffix are excluded. Any later upstream single-label change makes
the generator stop for review. This file must not replace the
URL-validator-compatible files until the native `rtp2`/`dns_mark` rollback
tests have passed on the target Mudi.

## Other files

- `cn-direct-full.txt`: exact converted upstream CN domain set with only the leading `+.` syntax removed.
- `cn-direct.txt`: full converted domain set with only the bare single-label `cn` entry omitted.
- `cn-direct-glinet.txt`: domain-only set filtered to the formats accepted by the tested Mudi 7 validator.
- `cn-direct-glinet-combined.txt`: stable CN-only domain + IPv4 baseline.
- `cn-direct-glinet-combined-plus.txt`: CN baseline + explicit Apple/Microsoft/work-app DIRECT suffixes.
- `cn-direct-signed-runtime-plus.txt`: signed-consumer candidate with numeric-leading FQDNs and an explicit reviewed single-label allowlist.

## Update behavior

GitHub Actions refreshes and commits the published files on its daily schedule. Push and manual runs test and build only; they do not publish generated changes. The updater refuses to overwrite outputs if the upstream domain/IP sources are empty, unexpectedly small, duplicated where not expected, or change away from their expected formats. The Plus generator also rejects duplicate or deliberately forbidden broad parent rules, and any unreviewed single-label change stops every output before replacement.

The six generated files are installed as one recoverable transaction. Existing files and staged replacements are synced before the transaction enters `PREPARED`; an ordinary write error restores the complete previous set. If the process or host stops during installation, the next run restores the `PREPARED` transaction before downloading new source data. A residual `COMMITTED` transaction is verified and cleaned without rolling the new set back.

## Sources

MetaCubeX/meta-rules-dat:

- `geo/geosite/cn.list`
- `geo/geoip/cn.list`
