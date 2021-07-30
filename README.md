# Stand-Alone Windows Hardening (SAWH)
SAWH is a PowerShell script to reduce the attack surface of Windows systems that are not attached to a Windows Active Directory Domain and do not require Windows services to function. Human-Machine Interface (MHI) systems within process environments often only require local access to interact with the system. These systems typically do not need to use services such as Network Browsing, IPv6, SMBv1, NetBIOS, and other Windows services to function properly. Therefore, to reduce the attack surface, many of these services can be disabled. This script provides a configurable way to modify the configuration of a stand-alone system without the need to configure, test, and install Security Templates. [Security Templates and Group Policy Objects (GPO)](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10), of course, are the BEST way to handle system hardening and SAWH should only be used as a stop-gap until your team can plan and test those technologies.

# WARNING

***Use At Your Own Risk!!!! Do not run on production systems without testing.***

Do not run on production systems without testing.

Use at your own risk. Cutaway Security is not responsible for how this script affects your system, your network, your services, or your process. Users accept all responsibility for using this script in testing and production enviornments.

***Use At Your Own Risk!!!! Do not run on production systems without testing.***

# Capabilities
## Running Modes
SAWH provides three running modes.

* 'check' - this performs a check of the system and the configuration of the script's actions.
* 'disable' - this modifies the system to disable services and settings following the action verbs configured in the script.
* 'enable' - this modifies the system to enable services and settings following the action verbs configured in the script.

## Configurations
The following configurations can be updated within the script. Your team should review each and determine which should be enabled and which should be disabled. Then, they should test completely before using in production.

* Interface Mode: modifies the mode of each network interface. Disabling puts the interfaces into 'Public' mode. Enabling puts the interfaces into 'Private' mode.
* NetBIOS: modifies the settings of each network interface. Disabling disables NetBIOS on each interface. Enabling enables NetBIOS on each interface.
* Firewall Rules: modifies the Windows Host-based Firewall with a rule named "Block Windows Services - SAWH" that controls TCP ports 135,137,139,445. Enabling creates the rule (if not present) and enables the rule. Disabling does not remove the rule, it just disables it.
* Bindings: Network interfaces have multiple configuration settings that can be controlled. The bindings setting controls the function of all. Each setting has its own setting.
 * IPv6: This setting controls the use of IPv6 on all interfaces. Disabling will disable IPv6 on all interfaces. Enabling will enable IPv6 on all interfaces.
 * LLTP: This setting controls the use of Link-Layer Topology Discovery Mapper I/O Driver and the Microsoft LLDP Driver on all interfaces. Disabling will disable LLTP on all interfaces. Enabling will enable LLTP on all interfaces.
 * Client: This setting controls the use of Client for Microsoft Networks and File and Printer Sharing for Microsoft Networks on all interfaces. Disabling will disable these services on all interfaces. Enabling will enable these services on all interfaces.
 * NAMP: This setting controls the use of Microsoft Network Adapter Multiplexor Protocol on all interfaces. Disabling will disable NAMP on all interfaces. Enabling will enable NAMP on all interfaces.
 * RDP: This setting controls the use of Terminal Services (RDP) on the system. Disabling will disable the RDP service in registry and also create a firewall rule name "Block RDP - SAWH" that blocks TCP 3389. Enabling will enable the RDP service in registry and also disable the "Block RDP - SAWH" firewall without removing it.
  * This is the only rule that is disabled by default. This is because many organizations will require RDP to access these stand-alone systems. Update with care and testing.
* SMBv1: This setting controls the use of SMBv1. Disabling will disable SMBv1 on the system. ***Enabling does nothing.*** You don't need SMBv1 for a stand-alone system. Don't enable it. Fire your vendor or integrator if they force you to enable it. If you really need it, you'll figure out how to enable it.
 * Seriously, you don't need SMBv1. Disabling it is extremely important.

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
* Tell us about your experience on Twitter by tagging [@cutawaysecurity](https://twitter.com/cutawaysecurity). Be sure to include your Windows version.

# Systems Tested
## Windows Versions
* Windows 10.0.17763

# Acknowledgements
The following people and teams have assisted with the testing and / or direction of this project. CutSec sincerely appreciates their input and support.

* Tom Liston [@tliston](https://twitter.com/tliston) - Bad Wolf Security, LLC