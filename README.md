# Stand-Alone Windows Hardening (SAWH)
SAWH is a PowerShell script to reduce the attack surface of Windows systems that are not attached to a Windows Active Directory Domain and do not require Windows services to function. Human-Machine Interface (MHI) systems within process environments often only require local access to interact with the system. These systems typically do not need to use services such as Network Browsing, IPv6, SMBv1, NetBIOS, and other Windows services to function properly. Therefore, to reduce the attack surface, many of these services can be disabled. This script provides a configurable way to modify the configuration of a stand-alone system without the need to configure, test, and install Security Templates. [Security Templates and Group Policy Objects (GPO)](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10), of course, are the BEST way to handle system hardening and SAWH should only be used as a stop-gap until your team can plan and test those technologies.

# WARNING

**Use At Your Own Risk!!!! Do not run on production systems without testing.**

Do not run on production systems without testing.

Use at your own risk. Cutaway Security is not responsible for how this script affects your system, your network, your services, or your process. Users accept all responsibility for using this script in testing and production enviornments.

**Use At Your Own Risk!!!! Do not run on production systems without testing.**

# Capabilities
SAWH provides three running modes.

* 'check' - this performs a check of the system and the configuration of the script's actions.
* 'disable' - this modifies the system to disable services and settings following the action verbs configured in the script.
* 'enable' - this modifies the system to enable services and settings following the action verbs configured in the script.

## Considerations
Check is safe. It makes no changes and there is a seperate confirmation prompt when changes will be made to the system.
Disable and Enable use a brute force update to all system interfaces. Modifications are made to all interfaces.

# Usage
* Prepare for rollback by backing up or snapshotting the system completely.
* Download 'sawh.ps1' from this repository.
* Modify any of the configurations verbs to change modifications to your desired configuration.
* Copy the 'sawh.ps1' to your downloads directory
* Start a PowerShell Terminal as Administrator. This is required.
* Change to your downloads directory.
* Allow scripts to run within the scope of this PowerShell process.
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```
* Execute the script and follow the prompts
```powershell
.\sawh.ps1
```
* Follow the prompts
* Test your system's functionality. Rollback if necessary.
* Tell us about your experience on Twitter by tagging [@cutawaysecurity](https://twitter.com/cutawaysecurity)


# Acknowledgements
The following people and teams have assisted with the testing and / or direction of this project. CutSec sincerely appreciates their input and support.

* Tom Liston [@tliston](https://twitter.com/tliston) - Bad Wolf Security, LLC