# Mudi 7 CN DIRECT ruleset

This directory publishes a GL.iNet VPN Policy compatible China-domain exclusion list for Mudi 7.

## Recommended subscription

Use `cn-direct.txt` as the subscription source and configure the matched targets as **Non-VPN / DIRECT**. Traffic not matched by this list can continue through the AWG profile.

`cn-direct.txt` is generated from MetaCubeX `geo/geosite/cn.list`, with the leading `+.` syntax removed so the output is one plain domain per line. The bare single-label `cn` entry is intentionally omitted in the recommended file because it can be too broad for international services that use a `.cn` hostname.

`cn-direct-full.txt` preserves the full converted upstream set, including the bare `cn` entry, for comparison/testing.

## Update behavior

GitHub Actions refreshes both files every day and can also be run manually. The updater refuses to overwrite the published files if the upstream list is empty, unexpectedly small, contains duplicates, or changes away from the expected `+.` format.

## Source

MetaCubeX/meta-rules-dat: `geo/geosite/cn.list`.
