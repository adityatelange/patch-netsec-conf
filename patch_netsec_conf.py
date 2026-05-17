#!/usr/bin/env python3

"""
Patch an APK's network security config to allow user/system certs and cleartext.
GitHub: https://github.com/adityatelange/patch-netsec-conf

Usage:
    python patch_netsec_conf.py <input.apk>

"""

import argparse
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

GENERIC_NETSEC = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
"""


def guess_netsec_path(apk_path):
    # Strings can appear in plain XML or inside binary AXML string pools.
    markers = [
        b"network-security-config",
        "network-security-config".encode("utf-16le"),
    ]

    with zipfile.ZipFile(apk_path, "r") as zin:
        names = set(zin.namelist())

        content_hits = []
        xml_entries = [n for n in names if n.startswith("res/") and n.endswith(".xml")]

        for name in xml_entries:
            data = zin.read(name)
            if any(marker in data for marker in markers):
                content_hits.append(name)

        if len(content_hits) == 1:
            return content_hits[0]

        candidates = [
            n
            for n in names
            if n.startswith("res/xml/")
            and n.endswith(".xml")
            and ("network" in n.lower() or "netsec" in n.lower())
        ]

    if len(content_hits) > 1:
        raise RuntimeError(
            "Multiple network-security candidates found: "
            + ", ".join(sorted(content_hits))
            + ". Provide --xml-path explicitly."
        )

    if len(candidates) == 1:
        return candidates[0]

    return None


def find_netsec_path(apk_path, xml_path=None):
    if xml_path:
        return xml_path

    guessed = guess_netsec_path(apk_path)
    if guessed:
        print(f"[+] Guessed networkSecurityConfig path -> {guessed}")
        return guessed

    raise RuntimeError(
        "Could not determine XML path automatically. "
        "Provide --xml-path explicitly."
    )


def patch_apk(apk_path, xml_path=None):
    apk_path = Path(apk_path)

    if not apk_path.exists():
        raise FileNotFoundError(apk_path)

    xml_path = find_netsec_path(apk_path, xml_path=xml_path)

    output_apk = apk_path.with_stem(apk_path.stem + "_nons")

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_apk = Path(tmpdir) / "patched.apk"

        with zipfile.ZipFile(apk_path, "r") as zin:
            with zipfile.ZipFile(temp_apk, "w") as zout:

                replaced = False

                for item in zin.infolist():
                    data = zin.read(item.filename)

                    if item.filename == xml_path:
                        print(f"[+] Replacing {xml_path}")
                        data = GENERIC_NETSEC
                        replaced = True

                    zout.writestr(item, data)

                if not replaced:
                    raise RuntimeError("Target XML file not found in APK")

        shutil.move(temp_apk, output_apk)

    print(f"[+] Patched APK written to: {output_apk}")
    print("[!] APK signature is now invalid")
    print("[!] Re-sign the APK before installing")


def print_banner():
    print(
        "patch-netsec-conf - Patch APK network security config to allow user/system certs and cleartext"
    )
    print("GitHub: https://github.com/adityatelange/patch-netsec-conf")
    print()


def main():
    print_banner()

    ap = argparse.ArgumentParser(
        description="Patch an APK's network security config to allow user/system certs and cleartext",
    )
    ap.add_argument("apk_path", help="Input APK file path")
    ap.add_argument(
        "--xml-path",
        help="Path to the target XML inside the APK (e.g. res/xml/network_security_config.xml)",
    )
    args = ap.parse_args()

    inp = Path(args.apk_path)
    if not inp.exists():
        print("Input file not found:", inp)
        sys.exit(1)

    if inp.suffix.lower() != ".apk":
        print("Input file must be an APK:", inp)
        sys.exit(1)

    try:
        patch_apk(str(inp), xml_path=args.xml_path)
    except Exception as e:
        print("[!] Error:", e)
        sys.exit(2)


if __name__ == "__main__":
    main()
