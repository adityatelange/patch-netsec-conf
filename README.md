# patch-netsec-conf

Patch an APK's Network Security Configuration to allow user/system certificates and cleartext traffic, without a full resource rebuild.

This utility locates the app's `networkSecurityConfig` XML by scanning APK resource entries and replaces it with a permissive configuration that:

- Allows cleartext traffic.
- Trusts both system and user certificate stores.

This is useful when you need to intercept an app's network traffic for analysis and the app restricts trust to a custom set of CAs or disallows cleartext.

## Why this instead of apktool (--net-sec-conf)?

- Works on both Linux and Windows hosts (Python 3.9+).
- Does not decompile all resources or run a full decode/rebuild cycle.
- Patches only the target `networkSecurityConfig` XML entry inside the APK archive, then writes a patched APK copy.
- Reduces build-time overhead and avoids common rebuild issues unrelated to network security config changes.

## Usage

1. Install the tool with `uv` or run it directly.

   ```sh
   uv tool install .
   patch-netsec-conf myapp.apk
   ```

   Or install using pip:

   ```sh
   pip install .
   patch-netsec-conf myapp.apk
   ```

   This produces a new file next to the input:
   - `myapp_nons.apk`

2. Sign the patched APK using your preferred signing tool.

   > Any APK modification invalidates the original signature. You must re-sign before installing.
   > I recommend using [APK Explorer & Editor (AEE)](https://github.com/apk-editor/APK-Explorer-Editor) for this step, as it also handles re-aligning and re-signing in one flow.

   > If you sign manually with `apksigner`, run `zipalign` on the patched APK first (`apksigner` does not align for you). The replaced XML entry changes size, so the original `zipalign` padding no longer lines up with the new archive layout.

## How it works

- Scans XML file contents for `network-security-config` markers (works even when filenames are obfuscated and files are binary AXML).
- Detects the target XML entry format explicitly:
  - Binary AXML if the file starts with Android binary XML magic bytes (`0x00080003`, little-endian).
  - Plain-text XML only if content decodes as XML text (UTF-8/UTF-16) and starts with `<` after trimming.
- Replaces binary targets with the bundled pre-generated binary AXML config from `network_security_config.xml`.
- Replaces plain-text targets with the bundled plain-text permissive config from `network_security_config_plain.xml`.
- Fails with an error if the target entry is neither recognized binary AXML nor plain-text XML (no implicit fallback).

## Options

```sh
$ patch-netsec-conf -h
usage: patch-netsec-conf [-h] [--xml-path XML_PATH] apk_path

Patch an APK's network security config to allow user/system certs and cleartext

positional arguments:
    apk_path    Input APK file path

optional arguments:
    --xml-path XML_PATH
                Path to the target XML inside the APK (e.g. res/xml/network_security_config.xml)
    -h, --help  show this help message and exit
```

## Disclaimer

> This script is intended for educational and testing purposes only. Only run it on APKs you own or have explicit permission to modify. The author is not responsible for misuse.

Patching network security settings may change app behavior and security; use responsibly.
