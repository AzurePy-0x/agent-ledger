#!/usr/bin/env python3
"""vendor_sale.py — vendor-side tool: mint a license key after a QRIS payment.

Usage (interactive):
    python3 vendor_sale.py "Nama Pembeli" email@pembeli.x --tier pro-lifetime

Tiers:
    pro-monthly    30-day expiring key   (Rp 75.000 / bln)
    pro-lifetime   no expiry             (Rp 250.000 sekali)

The signing secret lives in ~/.hermes/agent-ledger/.license_secret
(auto-created 0600 on first run). NEVER commit or share that file — anyone
holding it can mint unlimited keys.

After minting, the key is printed ready to paste. The buyer installs with:
    echo "<key>" > ~/.hermes/agent-ledger/license
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, __file__.rsplit("/", 1)[0] or ".")
from license import generate_key, verify_key  # noqa: E402

TIERS = {
    "pro-monthly": ("Rp 75.000 / bulan", lambda: (
        datetime.now(timezone.utc) + timedelta(days=30)).isoformat()),
    "pro-lifetime": ("Rp 250.000 sekali-beli", lambda: None),
}


def main():
    p = argparse.ArgumentParser(description="mint an agent-ledger pro license")
    p.add_argument("name", help="buyer name (goes into the key)")
    p.add_argument("email", help="buyer email/contact (goes into the key)")
    p.add_argument("--tier", default="pro-lifetime", choices=sorted(TIERS))
    args = p.parse_args()

    price, exp_fn = TIERS[args.tier]
    exp = exp_fn()
    key = generate_key(args.name, args.email, tier=args.tier, exp=exp)

    # verify immediately so a typo'd secret never ships a dead key
    payload = verify_key(key)

    print("=" * 60)
    print(f"Pembeli : {payload['name']} <{payload['email']}>")
    print(f"Tier    : {payload['tier']}  ({price})")
    print(f"Expiry  : {payload['exp'] or 'lifetime'}")
    print("-" * 60)
    print(key)
    print("-" * 60)
    print("Kirim key di atas ke pembeli. Cara pasang (untuk pembeli):")
    print(f'  echo "{key[:12]}..." > ~/.hermes/agent-ledger/license')
    print("  echo enforce > ~/.hermes/agent-ledger/policy_mode")
    return 0


if __name__ == "__main__":
    sys.exit(main())
