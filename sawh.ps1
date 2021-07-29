<#
	sawh.ps1 - Stand-Alone Windows Hardening (SAWH) is a PowerShell 
	script to disable unnecessary Windows services on stand-alone Windows 
	systems, such as Human Machine Interfaces and stand-alone workstations.
    
	WARNING: Do not run on production systems without testing.
	WARNING: Use at your own risk. Cutaway Security is not responsible for 
	         how this script affects your system, your network, your services,
			 or your process. Users accept all responsibility for using this
			 script in testing and production enviornments.

	Don't forget to run 'Set-ExecutionPolicy Bypass -Scope Process' to start.
	Be sure to reboot afterwards.

	Acknowledgements:
		Tom Liston (@tliston) - Bad Wolf Security, LLC
#>

<#
	License: 
	Copyright (c) 2021, Cutaway Security, Inc. <don@cutawaysecurity.com>
	
	sawh.ps1 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	sawh.ps1 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	Point Of Contact:    Don C. Weber <don@cutawaysecurity.com>
#>

$script_name = 'sawh.ps1'
$warning     = '

###################################################################################
*** Use At Your Own Risk!!!! Do not run on production systems without testing. ***

WARNING: Do not run on production systems without testing.
WARNING: Use at your own risk. Cutaway Security is not responsible for 
         how this script affects your system, your network, your services,
         or your process. Users accept all responsibility for using this
         script in testing and production enviornments.

*** Use At Your Own Risk!!!! Do not run on production systems without testing. ***
###################################################################################

'

####################
# Configuration verbs, modify these to disable modifications
####################
$inf_mode = $true
$netbios  = $true
$fw_rules = $true
$smbv1    = $true
$bindings = $true
$ipv6     = $true
$lltp     = $true
$client   = $true
$namp     = $true

####################
# Action verbs, user input changes these
####################
$disable = $false
$enable  = $false
$check   = $false

####################
# Check for Administrator Role ##############
####################
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
    $neg_str + "[*] You do not have Administrator rights. This script will not run correctly. Exiting" 
	Exit
} else {
    $inf_str +  "[*] Script running with Administrator rights." 
}

####################
# Set whether to enable or disable Windows services
####################
Write-Host "$warning"
Write-Host "[*] $script_name is about to start. Run the following Nmap scan (from a seperate system) and check current statue before proceeding:"
Write-Host '[*] sudo nmap -sT -p 135,137,139,445 <IP Address>'

$action = Read-Host "Do you want to enable or disable Windows services? [enable/disable/check]"
if ($action -eq 'disable') {
    $disable = $true
}
if ($action -eq 'enable') {
    $enable = $true
}
if ($action -eq 'check') {
    $check = $true
}
if ($enable -eq $false -And $disable -eq $false -And $check -eq $false){
	Write-Host "[*] User did not select a valid action. Exiting..."
	Exit
}

####################
# Check Windows Services
####################
if ($check) {
	####################
	# Start Check 
	####################
	Write-Host '[*] Checking Windows Services'
	
	####################
	# Check network interface modes
	####################
	Write-Host '[*] Getting network interface modes'
	Get-NetConnectionProfile
	Write-Host "[*] Modifying network interface mode is set to: $inf_mode"

	####################
	# Get NetBIOS settings
	####################
	Write-Host '[*] Disabling NetBIOS on all Interfaces'
	Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP*
	Write-Host "[*] Modifying NetBIOS is set to: $netbios"

	####################
	# Check for TCP port 135 rule
	####################
	Write-Host '[*] Check for Block Windows Services - SAWH rule using Windows Firewall'
	Get-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -ErrorAction SilentlyContinue
	Write-Host "[*] Modifying Firewall Rules is set to: $fw_rules"

	####################
	# Check Network Adapter Bindings
	####################
	Write-Host '[*] Checking Network Adapter Bindings'
	Get-NetAdapterBinding -InterfaceAlias *
	Write-Host "[*] Modifying Network Adapter Bindings is set to: $bindings"
	Write-Host "[*] Modifying Network Adapter IPv6 Binding is set to: $ipv6"
	Write-Host "[*] Modifying Network Adapter LLTP Bindings is set to: $lltp"
	Write-Host "[*] Modifying Network Adapter Client / Server Bindings is set to: $client"
	Write-Host "[*] Modifying Network Adapter Multiplexor Binding is set to: $namp"

	####################
	# Check SMBv1
	####################
	Write-Host '[*] Checking SMBv1'
	Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
	Write-Host "[*] Modifying SMBv1 is set to: $smbv1"

	####################
	# Check Completed
	####################
	Write-Host '[*] Check Windows Services completed'
	Exit
}

####################
# Confirm System Modifications
####################
Write-Host '*** Use At Your Own Risk!!!! Do not run on production systems without testing. ***'
$confirmation = Read-Host "Are you Sure You Want To Proceed? [n/y]"
if ($confirmation -ne 'y') {
	Write-Host "[*] User selected to exit. Exiting..."
	Exit
} else {
	Write-Host "[*] User selected to continue. Good luck..."
}

####################
# Disable Windows Services
####################
if ($disable) {
	####################
	# Start Disabling 
	####################
	Write-Host '[*] Disabling Windows Services'

	####################
	# Put all interfaces into 'Public' mode
	####################
	if ($inf_mode){
		Write-Host '[*] Putting network interfaces into Public mode'
		Get-NetConnectionProfile
		Set-NetConnectionProfile -Name * -NetworkCategory Public
		Get-NetConnectionProfile
	}

	####################
	# Disable NetBIOS and LMHosts lookup: https://www.tyrol.space/2019/07/12/disable-netbios-and-lmhosts-look-up-via-powershell-and-sccm-configuration-baseline/
	####################
	if ($netbios){
		Write-Host '[*] Disabling NetBIOS on all Interfaces'
		Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP*
		Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP* -Name NetBIOSoptions -Value 2
		Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP*
	}

	####################
	# Block DCOM to TCP port 135
	####################
	if ($fw_rules){
		Write-Host '[*] Block Block Windows Services - SAWH using Windows Firewall'
		$d = Get-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -ErrorAction SilentlyContinue
		if ($d){
			Set-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -Enabled True
		}else{
			New-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -Direction Inbound -LocalPort 135,137,139,445 -Protocol TCP -Action Block
		}
		Get-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -ErrorAction SilentlyContinue
	}

	####################
	# Disable Network Adapter Bindings
	####################
	if ($bindings){
		Write-Host '[*] Disabling Network Adapter Bindings'
		Get-NetAdapterBinding -InterfaceAlias *
		if ($ipv6) { 
			# Disable IPv6
			Disable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_tcpip6 
		}
		if ($lltp) { 
			# Disable Link-Layer Topology Discovery Mapper I/O Driver
			Disable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_lltdio 
			# Disable Microsoft LLDP protocol Driver
			Disable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_lldp 
		}
		if ($client) { 
			# Disable Client for Microsoft Networks
			Disable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_msclient 
			# Disable File and Printer Sharing for Microsoft Networks
			Disable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_server 
		}
		if ($namp) { 
			# Disable Microsoft Network Adapter Multiplexor Protocol
			Disable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_implat 
		}
		Get-NetAdapterBinding -InterfaceAlias *
	}

	####################
	# Disable SMBv1 - This should be last because of reboot prompt
	####################
	if ($smbv1){
		Write-Host '[*] Disabling SMBv1'
		Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
		Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
		Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
	}

	####################
	# Disabling Completed
	####################
	Write-Host '[*] Disable Windows Services completed'
}

####################
# Reset Windows Services - Hard Reset everything 
# *** Use at your own risk ***
# If you aren't sure, do this by hand.
####################
if ($enable) {
	####################
	# Start Enabling 
	####################
	Write-Host '[*] Enabling Windows Services. Be careful, you might be better restoring from backup / snapshot.'

	####################
	# Put all interfaces into 'Private' mode
	####################
	if ($inf_mode){
		Write-Host '[*] Putting network interfaces into Private mode'
		Get-NetConnectionProfile
		Set-NetConnectionProfile -Name * -NetworkCategory Private
		Get-NetConnectionProfile
	}

	####################
	# Disable NetBIOS and LMHosts lookup: https://www.tyrol.space/2019/07/12/disable-netbios-and-lmhosts-look-up-via-powershell-and-sccm-configuration-baseline/
	####################
	if ($netbios){
		Write-Host '[*] Enabling NetBIOS on all Interfaces'
		Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP*
		Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP* -Name NetBIOSoptions -Value 0
		Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP*
	}

	####################
	# Block DCOM to TCP port 135
	####################
	if ($fw_rules){
		Write-Host '[*] Enabling Block Windows Services - SAWH using Windows Firewall'
		Set-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -Enabled True -ErrorAction SilentlyContinue
		Get-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -ErrorAction SilentlyContinue
	}

	####################
	# Enable Network Adapter Bindings
	####################
	if ($bindings){
		Write-Host '[*] Disabling Network Adapter Bindings'
		Get-NetAdapterBinding -InterfaceAlias *
		if ($ipv6) { 
			# Enable IPv6
			Enable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_tcpip6 
		}
		if ($lltp) { 
			# Enable Link-Layer Topology Discovery Mapper I/O Driver
			Enable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_lltdio 
			# Enable Microsoft LLDP protocol Driver
			Enable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_lldp 
		}
		if ($client) { 
			# Enable Client for Microsoft Networks
			Enable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_msclient 
			# Enable File and Printer Sharing for Microsoft Networks
			Enable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_server 
		}
		if ($namp) { 
			# Enable Microsoft Network Adapter Multiplexor Protocol
			Enable-NetAdapterBinding –InterfaceAlias * –ComponentID ms_implat 
		}
		Get-NetAdapterBinding -InterfaceAlias *
	}

	####################
	# Enable SMBv1 - This should be last because of reboot prompt
	####################
	if ($smbv1){
		Write-Host '[*] Enable SMBv1'
		Write-Host '[*] We are not going to enable SMBv1. You do not need it. Do it yourself.'
		# Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol
		Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
	}

	####################
	# Enabling Completed
	####################
	Write-Host '[*] Enabling Windows Services completed'
}

####################
# Completed
####################
Write-Host "[*] $script_name has completed. Run the following Nmap scan (from a seperate system) and check the results:"
Write-Host '[*] sudo nmap -sT -p 135,137,139,445 <IP Address>'
Write-Host '[*] Do not forget to reboot before testing.'
