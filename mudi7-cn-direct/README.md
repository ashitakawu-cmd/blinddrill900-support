# Mudi 7 CN DIRECT ruleset

This directory publishes GL.iNet VPN Policy compatible China DIRECT exclusion lists for Mudi 7.

## Recommended subscription

Use `cn-direct-glinet-combined.txt` as the subscription source and configure matched targets as **Non-VPN / DIRECT**. Traffic not matched by this list can continue through the AWG profile.

The recommended file combines:

- the maximum subset of MetaCubeX `geo/geosite/cn.list` accepted by the Mudi 7 Subscription URL validator; and
- MetaCubeX China IPv4 CIDRs from `geo/geoip/cn.list` as a fallback for Chinese services whose domain names the firmware refuses to import.

This provides two DIRECT matching paths: domain first, then destination IPv4 range.

## Other files

- `cn-direct-full.txt`: exact converted upstream CN domain set with only the leading `+.` syntax removed.
- `cn-direct.txt`: full converted domain set with only the bare single-label `cn` entry omitted.
- `cn-direct-glinet.txt`: domain-only set filtered to the formats accepted by the tested Mudi 7 validator.
- `cn-direct-glinet-combined.txt`: **recommended for Mudi 7**, combining the compatible domain set with CN IPv4 CIDRs.

## Update behavior

GitHub Actions refreshes the published files every day and can also be run manually. The updater refuses to overwrite outputs if the upstream domain/IP sources are empty, unexpectedly small, duplicated where not expected, or change away from their expected formats.

## Sources

MetaCubeX/meta-rules-dat:

- `geo/geosite/cn.list`
- `geo/geoip/cn.list`
