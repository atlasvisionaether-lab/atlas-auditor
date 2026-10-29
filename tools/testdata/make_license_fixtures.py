"""Deterministic license test fixtures - TEST ONLY.

Regenerates tools/testdata/licenses/{valid_pro,expired,tampered}.json.
Everything is derived from ONE deterministic seed, so the fixtures are
byte-reproducible across machines:

    seed = sha256(b"atlas-auditor TEST ONLY key seed v1")

The matching public key is embedded in auditor/publickeys.py
("test-key-1"). The private seed lives ONLY here, in test tooling; it
never ships with the package.

Usage: python3 tools/testdata/make_license_fixtures.py
"""

import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from auditor.license import canonical_bytes  # noqa: E402
import ed25519_reference as ed  # noqa: E402

SEED_PHRASE = b"atlas-auditor TEST ONLY key seed v1"
EXPECTED_PUBLIC_B64 = "9keFLzXcMGB5aGCCxWHiKoNNdJgjRNxna/y7XRyP+Tc="
# Canonical anchor: the exact valid_pro signature from the Faz 4 verified
# run (byte-identical reproduction proves seed + canonical form + signer).
EXPECTED_SIG_B64 = ("rQf4aSYTuOyjllK2gYxIsO0b2b8hTZn2tjuqmuiotHvq78FDfS10Q"
                    "OkxNjtPRwnetD8W7qav5e1P4oee+rCECQ==")

OUT_DIR = Path(__file__).resolve().parent / "licenses"


def main() -> int:
    seed = hashlib.sha256(SEED_PHRASE).digest()
    public = ed.secret_to_public(seed)
    public_b64 = base64.b64encode(public).decode("ascii")
    assert public_b64 == EXPECTED_PUBLIC_B64, (
        f"seed produced a different key: {public_b64}; "
        "auditor/publickeys.py and this seed drifted apart")

    valid_license = {
        "tenant_id": "atlas-demo-tenant",
        "features": ["n8n_audit"],
        "expiry": "2030-12-31",
        "key_id": "test-key-1",
    }
    expired_license = dict(valid_license, expiry="2020-01-01")

    # tampered: the license CLAIMS the valid fields, but the signature is
    # computed over a different payload -> verification must fail (P8).
    different_payload = dict(valid_license, tenant_id="atlas-other-tenant")

    sig_valid = ed.sign(seed, canonical_bytes(valid_license))
    sig_valid_b64 = base64.b64encode(sig_valid).decode("ascii")
    assert sig_valid_b64 == EXPECTED_SIG_B64, (
        f"valid_pro signature drifted from the Faz 4 anchor "
        f"(got ...{sig_valid.hex()[-10:]}, expected ...9efab08409)")

    fixtures = {
        "valid_pro": {"license": valid_license,
                      "signature": base64.b64encode(sig_valid).decode("ascii")},
        "expired": {"license": expired_license,
                    "signature": base64.b64encode(
                        ed.sign(seed, canonical_bytes(expired_license))
                    ).decode("ascii")},
        "tampered": {"license": valid_license,
                     "signature": base64.b64encode(
                         ed.sign(seed, canonical_bytes(different_payload))
                     ).decode("ascii")},
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, doc in fixtures.items():
        path = OUT_DIR / f"{name}.json"
        body = "{
"
        body += "  "license": {
"
        lic = doc["license"]
        body += (f"    "tenant_id": "{lic['tenant_id']}",
"
                 f"    "features": [
      "{lic['features'][0]}"
    ],
"
                 f"    "expiry": "{lic['expiry']}",
"
                 f"    "key_id": "{lic['key_id']}"
"
                 "  },
")
        body += f"  "signature": "{doc['signature']}"
"
        body += "}
"
        path.write_text(body, encoding="utf-8")
        print(f"wrote {path}")

    # Sanity: reference verify accepts valid_pro end to end.
    assert ed.verify(public, canonical_bytes(valid_license), sig_valid)
    print("deterministic fixture regeneration PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())