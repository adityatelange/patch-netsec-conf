#!/usr/bin/env python3

"""
Patch an APK's network security config to allow user/system certs and cleartext.
GitHub: https://github.com/adityatelange/patch-netsec-conf

Usage:
    patch-netsec-conf <input.apk>
    python -m patch_netsec_conf <input.apk>

"""

import argparse
import shutil
import sys
import tempfile
import zipfile
from importlib import resources
from pathlib import Path

BINARY_NETSEC_FILENAME = "network_security_config.xml"
PLAINTEXT_NETSEC_FILENAME = "network_security_config_plain.xml"
# file(1) magic signature (lelong 0x00080003):
# - RES_XML_TYPE (0x0003)
# - ResXMLTree_header headerSize (0x0008)
# Reference (file(1) magic rule for Android binary XML):
# https://github.com/file/file/blob/44cfb238c42f6ccaa9440c523dccdc7b72179911/magic/Magdir/android#L179-L185
AXML_FILE_MAGIC_BYTES = b"\x03\x00\x08\x00"


def _load_bundled_bytes(filename):
    """Load a bundled file as bytes via importlib.resources with local fallback."""
    try:
        return resources.files(__package__ or __name__).joinpath(filename).read_bytes()
    except Exception:
        path = Path(__file__).with_name(filename)
        if not path.is_file():
            raise RuntimeError(f"Bundled config file missing: {path}")
        return path.read_bytes()


def _is_binary_axml(data):
    """Heuristic check to determine if the given data is likely a binary AXML file."""
    # Matches file(1) rule: 0 lelong 0x00080003 Android binary XML.
    return data.startswith(AXML_FILE_MAGIC_BYTES)


def _is_plaintext_xml(data):
    """Heuristic check to determine if the given data is plain-text XML."""
    if not data:
        return False

    for encoding in ("utf-8-sig", "utf-16", "utf-16le", "utf-16be"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue

        if text.lstrip().startswith("<"):
            return True
    return False


def pick_replacement_bytes(target_data):
    if _is_binary_axml(target_data):
        print("[+] Target format detected: binary AXML")
        return _load_bundled_bytes(BINARY_NETSEC_FILENAME)

    if _is_plaintext_xml(target_data):
        print("[+] Target format detected: plain-text XML")
        return _load_bundled_bytes(PLAINTEXT_NETSEC_FILENAME)

    raise RuntimeError(
        "Target XML format is neither Android binary AXML nor plain-text XML"
    )


def _detect_netsec_path(apk_path):
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

    detected = _detect_netsec_path(apk_path)
    if detected:
        print(f"[+] Detected networkSecurityConfig path -> {detected}")
        return detected

    raise RuntimeError(
        "Could not determine XML path automatically. " "Provide --xml-path explicitly."
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
                    orig_data = zin.read(item.filename)
                    data = orig_data

                    if item.filename == xml_path:
                        print(f"[+] Replacing {xml_path}")
                        data = pick_replacement_bytes(orig_data)
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
