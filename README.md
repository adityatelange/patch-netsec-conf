# patch-netsec-conf

Patch an APK's Android Network Security Configuration to allow user/system certificates and cleartext.

This utility locates the app's `networkSecurityConfig` XML by scanning APK resource entries and replaces it with a permissive configuration that:

- Allows cleartext traffic.
- Trusts both system and user certificate stores.

This is useful when you need to intercept an app's network traffic for analysis and the app restricts trust to a custom set of CAs or disallows cleartext.

## Usage

1. Install the tool with `uv` or run it directly.

```sh
uv install .
patch-netsec-conf myapp.apk
```

Or run directly:

```sh
python3 patch_netsec_conf.py myapp.apk
```

This produces a new file next to the input:

- `myapp_nons.apk`

2. Sign the patched APK using your preferred signing tool.

> Any APK modification invalidates the original signature. You must re-sign before installing.
> I recommend using [APK Explorer & Editor (AEE)](https://github.com/apk-editor/APK-Explorer-Editor) for this step.

## How it works

- Scans XML file contents for `network-security-config` markers (works even when filenames are obfuscated and files are binary AXML).
- Replaces the target XML with a generic permissive network security config.

## Options

```sh
$ python3 patch_netsec_conf.py -h
usage: patch_netsec_conf.py [-h] [--xml-path XML_PATH] apk_path

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
