# CVE-2020-3153
Cisco AnyConnect < 4.8.02042 privilege escalation through path traversal

## Description
The auto-update feature of Cisco AnyConnect is affected by a path traversal vulnerability. An attacker can exploit this vulnerability to gain system level privileges.

For more details, please refer to:
- [the original advisory](https://www.securify.nl/advisory/SFY20200419/cisco-anyconnect-elevation-of-privileges-due-to-insecure-handling-of-path-names.html)
- [SSD Advisory](https://ssd-disclosure.com/ssd-advisory-cisco-anyconnect-privilege-elevation-through-path-traversal/)
- [my notes](details.md)

## Exploit
This exploit uses  the "hijack of a DLL loaded by a Cisco signed binary" attack scenario described in the original advisory and in SSD's post. However, this exploit uses `vpndownloader.exe`(also a Cisco signed binary that is affected by the same DLL hijacking vulnerability) instead of `cstub.exe`. In addition, I embedded `dbghelp.dll` in Base64 in the C# code to have a standalone exploit.

## Usage
Run `CVE-2020-3153.exe` (in the `CVE-2020-3153/bin/Release` folder) or use the ["msbuild" version](#msbuild-launcher-for-cve-2020-3153)  (in case of Application Whitelisting). A SYSTEM shell will spawn.



## MSBuild launcher for CVE-2020-3153
A MSBuild launcher has been created from the C# program in case of Application Whitelisting or to change path to `vpndownloader.exe` without recompiling the C# code.

Usage: 
`C:\Windows\Microsoft.Net\Framework64\v4.0.30319\MSBuild.exe c:\path\to\CVE-2020-3153.xml`

The CVE-2020-3153.xml file can be found in the `msbuild` folder.

## Tested versions
This exploit has been tested on Windows 7 and Windows 10 with the following Cisco AnyConnect versions (32-bit):
- 4.5.02036
- 4.6.03049
- 4.7.04056
- 4.8.01090

I have not tested any Cisco AnyConnect 64-bit versions. Path to `vpndownloader.exe` may be different. 


## Additional information
- The `cstub.exe` binary in this repository was extracted from AnyConnect Posture module version 4.6.02074.
- The outline of the C# code and the DLL source code are based on Google Project Zero PoC for CVE-2015-6305: [link](https://bugs.chromium.org/p/project-zero/issues/detail?id=460)
- The author of the vulnerability helped me for the successful exploitation on AnyConnect 4.7.x and 4.8.x. I was missing a value for an argument: [link](https://twitter.com/yorickkoster/status/1253663893500694528)





