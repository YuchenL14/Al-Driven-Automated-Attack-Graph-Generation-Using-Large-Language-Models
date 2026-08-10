# Provenance of `attack_lookup.json`

The technique and mitigation catalogue the tool chooses from. What a run
proposed cannot be interpreted without knowing what it was choosing between, so
this file records which snapshot is in the repository.

| field | value |
|---|---|
| source | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` |
| ATT&CK release | **not recorded** — see below |
| file written | 2026-07-23 21:32:53 (local file timestamp) |
| SHA-256 | `da15522cce11c057487762e06e9e64b67e97914a198053ca246b25a1c480ddc9` |
| techniques | 697 |
| mitigations | 44 |

## Why the release is not recorded

The source URL points at a branch, not a release. Two runs a month apart
download different catalogues from the same address, and the generator wrote
only the address. The release that produced this snapshot therefore cannot be
established after the fact from the snapshot itself, and labelling it from a
download made today would be a guess presented as a record.

What can be said is that `scripts/update_attack_lookup.py` maps the tactic
phases `stealth` and `defense-impairment` back to Defense Evasion. Those phase
names appear in ATT&CK v19, so the snapshot is v19 or later. That is a bound,
not an identification.

`update_attack_lookup.py` now reads `x_mitre_version` from the bundle's own
`x-mitre-collection` object and writes it, with the retrieval date, into every
snapshot it generates from here on. Refreshing the catalogue will therefore
produce a file that identifies itself; this one cannot be made to.

## Checking the snapshot has not moved

```bash
sha256sum data/attack_lookup.json
```

If the digest differs from the table above, the catalogue changed and any
measurement quoted against the old one has to be re-run, not carried forward.
