# Stand-Alone Windows Hardening (SAWH)
SAWH is a PowerShell script to reduce the attack surface of Windows systems that are not attached to a Windows Active Directory Domain and do not require Windows services to function. Human-Machine Interface (MHI) systems within process environments often only require local access to interact with the system. These systems typically do not need to use services such as Network Browsing, IPv6, SMBv1, NetBIOS, and other Windows services to function properly. Therefore, to reduce the attack surface, many of these services can be disabled. This script provides a configurable way to modify the configuration of a stand-alone system without the need to configure, test, and install Security Templates. [Security Templates and Group Policy Objects (GPO)](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10), of course, are the BEST way to handle system hardening and SAWH should only be used as a stop-gap until your team can plan and test those technologies.

# WARNING

***Use At Your Own Risk!!!! Do not run on production systems without testing.***

Use at your own risk. Cutaway Security is not responsible for how this script affects your system, your network, your services, or your process. Users accept all responsibility for using this script in testing and production environments.

***Use At Your Own Risk!!!! Do not run on production systems without testing.***

# Capabilities
## Running Modes
SAWH provides three running modes.

* 'check' - this performs a check of the system and the configuration of the script's actions.
* 'disable' - this modifies the system to disable services and settings following the action verbs configured in the script.
* 'rollback' - this modifies the system to rollback services and settings following the action verbs configured in the script. The rollback is not performed from a stored configuration for the system. The rollback resets the system to a normal default configuration by enabling the Windows services and network adapter settings. NOTE: except for SMBv1, you can roll this setting back manually.

## Configurations
The following configurations can be updated within the script. Your team should review each and determine which should be enabled and which should be disabled. Then, they should test completely before using in production.

* <ins>Interface Mode</ins>: modifies the mode of each network interface. Disabling puts the interfaces into 'Public' mode. Rolling back puts the interfaces into 'Private' mode.
* <ins>NetBIOS</ins>: modifies the settings of each network interface. Disabling disables NetBIOS on each interface. Rolling back enables NetBIOS on each interface.
* <ins>Firewall Rules</ins>: modifies the Windows Host-based Firewall with a rule named "Block Windows Services - SAWH" that controls TCP ports 135, 137, 139, and 445. Enabling creates the rule (if not present) and enables the rule. Rolling back does not remove the rule, it just disables it.
* <ins>Bindings</ins>: Network interfaces have multiple configuration settings that can be controlled. The bindings setting controls the function of all. Each setting has its own setting.
  * <ins>IPv6</ins>: This setting controls the use of IPv6 on all interfaces. Disabling will disable IPv6 on all interfaces. Rolling back will enable IPv6 on all interfaces.
  * <ins>LLTP</ins>: This setting controls the use of Link-Layer Topology Discovery Mapper I/O Driver and the Microsoft LLDP Driver on all interfaces. Disabling will disable LLTP on all interfaces. Rolling back will enable LLTP on all interfaces.
  * <ins>Client</ins>: This setting controls the use of Client for Microsoft Networks and File and Printer Sharing for Microsoft Networks on all interfaces. Disabling will disable these services on all interfaces. Rolling back will enable these services on all interfaces.
  * <ins>NAMP</ins>: This setting controls the use of Microsoft Network Adapter Multiplexor Protocol on all interfaces. Disabling will disable NAMP on all interfaces. Rolling back will enable NAMP on all interfaces.
* <ins>RDP</ins>: This setting controls the use of Terminal Services (RDP) on the system. Disabling will disable the RDP service in registry and also create a firewall rule name "Block RDP - SAWH" that blocks TCP 3389. Rolling back will enable the RDP service in registry and also disable the "Block RDP - SAWH" firewall without removing it.
  * This is the only rule that is disabled by default. This is because many organizations will require RDP to access these stand-alone systems. Update with care and testing.
* <ins>SMB Configuration</ins>: This setting controls the configuration settings for SMB. Disabling will turn off SMB server and Workstation shares and will turn on and require SMB signing and encryption. Rolling back will reset the system to normal SMB default configuration which is to turn on SMB server and Workstation shares and disable SMB signing and encryption.
* <ins>SMBv1</ins>: This setting controls the use of SMBv1. Disabling will disable SMBv1 on the system. ***Rolling back does nothing.*** You don't need SMBv1 for a stand-alone system. Don't enable it. Fire your vendor or integrator if they force you to enable it. If you really need it, you'll figure out how to enable it.
  * Seriously, you don't need SMBv1. Disabling it is extremely important.

## Considerations
Check is safe. It makes no changes and there is a separate confirmation prompt when changes will be made to the system.
Rolling back puts the system's state into an insecure default state. This script does not maintain the system's original configuration. You should run and store the check action in case you need to reconfigure the system to match the original state.

# Usage
Tell us about your experience on Twitter by tagging [@cutawaysecurity](https://twitter.com/cutawaysecurity) or, preferably, in this Github repo so others can help. Be sure to include your Windows version.

## Deploying via removable media
* Prepare for rollback by backing up or taking a virtual snapshot of the system.
* Download 'sawh.ps1' from this repository.
* Modify any of the configurations verbs to change modifications to your desired configuration.
* Copy the 'sawh.ps1' to a trusted removable media and place the file on the target system in the user's Downloads directory.
* Start a PowerShell Terminal as Administrator. **This is required.**
* Change to your downloads directory.
* Allow scripts to run within the scope of this PowerShell process.
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```
* Execute the script.
```powershell
.\sawh.ps1
```
* Follow the prompts.
* Reboot your system.
* Test your system's functionality. Rollback if necessary.

## Deploying via web server
* Prepare for rollback by backing up or taking a virtual snapshot of the system.
* Download 'sawh.ps1' from this repository.
* Modify any of the configurations verbs to change modifications to your desired configuration.
* Start a webserver on your system using Python.
```python
python3 -m http.server 8181
```
* Start a PowerShell Terminal on the target system as Administrator. **This is required.**
* Change to the user's downloads directory.
* Download the SAWH PowerShell script from the Python webserver.
```powershell
(New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps/chaps.ps1') >.\sawh.ps1
```
* Allow scripts to run within the scope of this PowerShell process.
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```
* Execute the script.
```powershell
.\sawh.ps1
```
* Follow the prompts.
* Reboot your system.
* Test your system's functionality. Rollback if necessary.

# Systems Tested
Have you tested one successfully? Let us know.

## Windows Versions
* Windows 10 Enterprise
  * 10.0.17763
* Windows 2016 Server
  * 10.0.14393
## HMI / Software Solutions Tested
* [BITS BACnet Site Auditor](https://www.bac-test.com/bacnet-site-auditor-download/) 

# Acknowledgements
The following people and teams have assisted with the testing and / or direction of this project. CutSec sincerely appreciates their input and support.

* Tom Liston [@tliston](https://twitter.com/tliston) - Bad Wolf Security, LLC
* Ken Lassey, Cornell University

# TODO

* Log output to a local file as well as stdout.
* Firewall rule to block UDP-based Windows service ports.
* Disable other unnecessary Windows services.
* Test user accounts and alert when there are no users that are not members of the Administrators group.
* Determine if you can update system configuration to ensure new interfaces start with these settings?
* Disable remote WMI and remote PowerShell.
* Disable non-Administrators from starting CMD.exe and each version of PowerShell [using hash rules or path rules](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/work-with-software-restriction-policies-rules).
* Add startup/login/shutdown script to check and log configurations.