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

####################
# Global Parameters
####################

# Common Configuration Parameters
$script_name = 'sawh.ps1'
$sysversion  = (Get-CimInstance Win32_OperatingSystem).version
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
$start_state     = $true       # Enable / disable writing the system's state before beginning
$completed_state = $true       # Enable / disable writing the system's state after changes

# Global Configuration verbs, modify these to disable modifications
$inf_mode = $true
$netbios  = $true
$fw_rules = $true
$bindings = $true
$ipv6     = $true
$lltp     = $true
$client   = $true
$namp     = $true
$rdp      = $false   # Disabled by default because this may be required
$smbv1    = $true

# Global Action verbs, user input changes these
$disable  = $false
$rollback = $false
$check    = $false


####################
# Functions
####################

####################
# Administration Functions
####################

# Check for Administrator Role 
####################
function Get-AdminState {
	if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
		Write-Host "[!] You do not have Administrator rights. This script will not run correctly. Exiting" 
		Exit
	} else {
		Write-Host "[*] Script running with Administrator rights." 
	}
}
####################

# Confirm System Modifications
####################
function Get-UserConfirmation {
	Write-Host '*** Use At Your Own Risk!!!! Do not run on production systems without testing. ***'
	$confirmation = Read-Host "Are you Sure You Want To Proceed? [n/y]"
	if ($confirmation -ne 'y') {
		Write-Host "[*] User selected to exit. Exiting..."
		Exit
	} else {
		Write-Host "[*] User selected to continue. Good luck..."
	}
}
####################

####################
# Action Functions
####################

# Network interface modes
####################
function Get-InterfaceModeState {
	Write-Host '[*] Checking Network interface modes'
	(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*'}) | ForEach-Object -Process {Get-NetConnectionProfile -InterfaceAlias $_.Name}

	# Let's give a little whitespace for readability
	Write-Host ''
}

function Set-InterfaceModeState {

	Param(
		# Enable means to change the setting to the default / insecure state.
		$Enable = $false
	)

	if ($inf_mode){
		# Check the physical interfaces, avoid loopbacks, and only act on interfaces that are up
		# NOTE: this will not change anything with intefaces with the status 'Disconnected'
		if (-NOT $Enable) {
			# Put all interfaces into 'Public' mode
			Write-Host '[*] Disable: Putting network interfaces into Public mode'
			(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}) | ForEach-Object -Process {Set-NetConnectionProfile -InterfaceAlias $_.Name -NetworkCategory Public}
		}else{
			# Put all interfaces into 'Private' mode
			Write-Host '[*] Enable / Rollback: Putting network interfaces into Private mode'
			(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}) | ForEach-Object -Process {Set-NetConnectionProfile -InterfaceAlias $_.Name -NetworkCategory Private}
		}
	}else{
		Write-Host '[!] Modification of network interfaces is disabled.'
	}

	# Let's give a little whitespace for readability
	Write-Host ''
}
####################

# NetBIOS
####################
function Get-NetBIOSState{
	# Check the physical interfaces, avoid loopbacks, and only act on interfaces that are up
	# Get their interface GUID to query the specific registry key 
	Write-Host "[*] Checking Interface NetBIOS States"
	(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}) | ForEach-Object -Process {
		$if_guid = $_.InterfaceGuid; 
		$if_nb_setting = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP_$if_guid).NetbiosOptions; 
		$if_name = $_.Name;
		if ($if_nb_setting){$nb_config = 'Enabled'}else{$nb_config = 'Disabled'}
		Write-Host "[*] Interface $if_name : NetBIOS $nb_config [$if_nb_setting]";
	}

	# Let's give a little whitespace for readability
	Write-Host ''
}

function Set-NetBIOSState(){

	Param(
		# Enable means to change the setting to the default / insecure state.
		$Enable = $false
	)
	
	if ($netbios){
		if (-NOT $Enable) {
			# Disable NetBIOS on active interfaces
			(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}) | ForEach-Object -Process {
				$if_guid = $_.InterfaceGuid; 
				$if_nb_setting = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP_$if_guid).NetbiosOptions; 
				$if_name = $_.Name;
				if ($if_nb_setting){
					Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP_$if_guid -Name NetBIOSoptions -Value 0
					Write-Host "[*] Interface $if_name : NetBIOS changed from $if_nb_setting to 0";
				}else{
					Write-Host "[*] Interface $if_name : NetBIOS Already Disabled [$if_nb_setting]";
				}
			}
		}else{
			# Enable NetBIOS on active interfaces
			(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}) | ForEach-Object -Process {
				$if_guid = $_.InterfaceGuid; 
				$if_nb_setting = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP_$if_guid).NetbiosOptions; 
				$if_name = $_.Name;
				if ($if_nb_setting){
					Write-Host "[*] Interface $if_name : NetBIOS Already Enabled [$if_nb_setting]";
				}else{
					Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP_$if_guid -Name NetBIOSoptions -Value 2
					Write-Host "[*] Interface $if_name : NetBIOS changed from $if_nb_setting to 2";
				}
			}
		}
	}else{
		Write-Host '[!] Modification of network interface NetBIOS settings is disabled.'
	}

	# Let's give a little whitespace for readability
	Write-Host ''
}
####################

# Firewall Rules
####################
function Get-SAWHFWRulesState(){
	# Check for the 'Block Windows Services - SAWH'
	# Get their interface GUID to query the specific registry key 
	Write-Host '[*] Checking for Block Windows Services - SAWH rule using Windows Firewall'
	$check_sw_fw_rule = Get-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -ErrorAction SilentlyContinue 
	if ($check_sw_fw_rule){
		if (($check_sw_fw_rule).Enable){
			Write-Host '[*] Block Windows Services - SAWH rule enabled.'
		}else{
			Write-Host '[*] Block Windows Services - SAWH rule disabled.'
		}
		Write-Host '[*] Windows Services - SAWH rule configuration'
		$check_sw_fw_rule
		Write-Host '[*] Windows Services - SAWH rule port settings'
		$check_sw_fw_rule | Get-NetFirewallPortFilter
	}else{
		Write-Host '[*] Block Windows Services - SAWH rule not configured on this system'
	}
	
	# Let's give a little whitespace for readability
	Write-Host ''
}

function Set-SAWHFWRulesState(){
	
	Param(
		# Enable means to change the setting to the default / insecure state.
		$Enable = $false
	)
	
	if ($fw_rules){
		$check_sw_fw_rule = Get-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -ErrorAction SilentlyContinue
		if (-NOT $Enable) { 
			# Disable Windows services by adding firewall rule
			if ($check_sw_fw_rule){
				if (($check_sw_fw_rule).Enable){
					Write-Host '[*] Block Windows Services - SAWH rule already enabled.'
				}else{
					Set-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -Enabled True
					Write-Host '[*] Block Windows Services - SAWH rule enabled.'
				}
			}else{
				# TODO: Add UDP Firewall Rule
				New-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -Direction Inbound -LocalPort 135,137,139,445 -Protocol TCP -Action Block
			}
		}else{
			# Enable Windows services by disabling firewall rule
			if ($check_sw_fw_rule){
				if (($check_sw_fw_rule).Enable){
					Set-NetFirewallRule -DisplayName "Block Windows Services - SAWH" -Enabled False
					Write-Host '[*] Block Windows Services - SAWH rule disabled.'
				}else{
					Write-Host '[*] Block Windows Services - SAWH rule already disabled.'
				}
			}else{				
				Write-Host '[*] Block Windows Services - SAWH rule not configured on this system'
			}
		}	
	}else{
		Write-Host '[!] Modification of firewall rules is disabled.'
	}	

	# Let's give a little whitespace for readability
	Write-Host ''
}
####################

# Interface Bindings
####################
function Get-NetBindingsState(){
	####################
	# Check Network Adapter Bindings
	####################
	Write-Host '[*] Checking Network Adapter Bindings'
	(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}).InterfaceAlias | ForEach-Object -Process {Get-NetAdapterBinding -InterfaceAlias $_}
	
	# Let's give a little whitespace for readability
	Write-Host ''
}

function Set-NetBindingsState(){
	
	Param(
		# Enable means to change the setting to the default / insecure state.
		$Enable = $false
	)

	if ($bindings){
		if (-NOT $Enable) { 
			# Disable selected bindings
			(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}).InterfaceAlias | ForEach-Object -Process {
				if ($ipv6) {
					# Disable IPv6
					Disable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_tcpip6			 
				}
				if ($lltp) {  
					# Disable Link-Layer Topology Discovery Mapper I/O Driver
					Disable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_lltdio 
					# Disable Microsoft LLDP protocol Driver
					Disable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_lldp 
				}
				if ($client) { 
					# Disable Client for Microsoft Networks
					Disable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_msclient 
					# Disable File and Printer Sharing for Microsoft Networks
					Disable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_server 
				}
				if ($namp) { 
					# Disable Microsoft Network Adapter Multiplexor Protocol
					Disable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_implat 
				}
			}
		}else{
			# Enable selected bindings
			(Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}).InterfaceAlias | ForEach-Object -Process {
				if ($ipv6) {
					# Disable IPv6
					Enable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_tcpip6			 
				}
				if ($lltp) {  
					# Disable Link-Layer Topology Discovery Mapper I/O Driver
					Enable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_lltdio 
					# Disable Microsoft LLDP protocol Driver
					Enable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_lldp 
				}
				if ($client) { 
					# Disable Client for Microsoft Networks
					Enable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_msclient 
					# Disable File and Printer Sharing for Microsoft Networks
					Enable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_server 
				}
				if ($namp) { 
					# Disable Microsoft Network Adapter Multiplexor Protocol
					Enable-NetAdapterBinding –InterfaceAlias $_ –ComponentID ms_implat 
				}
			}
		}
	}else{
		Write-Host '[!] Modification of interface bindings is disabled.'
	}	
	
	# Let's give a little whitespace for readability
	Write-Host ''
}
####################

# Terminal Services (RDP)
####################
function Get-TerminalServicesState(){
	# Check for RDP Registry Setting
	Write-Host '[*] Checking RDP Registry Configuration'
	if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections").fDenyTSConnections){
		Write-Host '[*] RDP is Disabled'
	}else{
		Write-Host '[*] RDP is Enabled'
	}

	# Check for the 'Block RDP - SAWH'
	# Get their interface GUID to query the specific registry key 
	Write-Host '[*] Check for Block RDP - SAWH rule using Windows Firewall'
	$check_rdp_fw_rule = Get-NetFirewallRule -DisplayName "Block RDP - SAWH" -ErrorAction SilentlyContinue 
	if ($check_rdp_fw_rule){
		if (($check_rdp_fw_rule).Enable){
			Write-Host '[*] Block RDP - SAWH rule enabled.'
		}else{
			Write-Host '[*] Block RDP - SAWH rule disabled.'
		}
		Write-Host '[*] RDP - SAWH rule configuration'
		$check_rdp_fw_rule
		Write-Host '[*] RDP - SAWH rule port settings'
		$check_rdp_fw_rule | Get-NetFirewallPortFilter
	}else{
		'[*] Block RDP - SAWH rule not configured on this system'
	}
	
	# Let's give a little whitespace for readability
	Write-Host ''
}

function Set-TerminalServicesState(){
	
	Param(
		# Enable means to change the setting to the default / insecure state.
		$Enable = $false
	)

	if ($rdp){
		$rdp_setting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections"
		$check_rdp_fw_rule = Get-NetFirewallRule -DisplayName "Block RDP - SAWH" -ErrorAction SilentlyContinue
		if (-NOT $Enable) { 
			# Disable RDP in registry
			if ($rdp_setting.fDenyTSConnections){
				Write-Host '[*] RDP was already disabled'
			}else{
				Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
				Write-Host '[*] RDP was disabled'
			}
			# Disable RDP in Firewall
			if ($check_rdp_fw_rule){
				if (($check_rdp_fw_rule).Enable){
					Write-Host '[*] Block RDP - SAWH rule already enabled.'
				}else{
					Set-NetFirewallRule -DisplayName "Block RDP - SAWH" -Enabled True
					Write-Host '[*] Block RDP - SAWH rule enabled.'
				}
			}else{
				# TODO: Add UDP Firewall Rule
				New-NetFirewallRule -DisplayName "Block RDP - SAWH" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
			}
		}else{
			# Enable RDP in registry
			if ($rdp_setting.fDenyTSConnections){
				Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
				Write-Host '[*] RDP was enabled'
			}else{
				Write-Host '[*] RDP was already enabled'
			}
			# Enable RDP by disabling firewall rule
			if ($check_rdp_fw_rule){
				if (($check_rdp_fw_rule).Enable){
					Set-NetFirewallRule -DisplayName "Block RDP - SAWH" -Enabled False
					Write-Host '[*] Block RDP - SAWH rule disabled.'
				}else{
					Write-Host '[*] Block RDP - SAWH rule already disabled.'
				}
			}else{				
				Write-Host '[*] Block RDP - SAWH rule not configured on this system'
			}
		}
	}else{
		Write-Host '[!] Modification of Terminal Services (RDP) is disabled.'
	}
	
	# Let's give a little whitespace for readability
	Write-Host ''
}
####################

# Service Message Bus version 1 (SMBv1)
####################
function Get-SMBv1State(){

	####################
	# Check SMBv1
	####################
	Write-Host '[*] Checking SMBv1 Configuration'
	$smb_state = (Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State
	Write-Host "[*] SMBv1 is currently: $smb_state"
	
	# Let's give a little whitespace for readability
	Write-Host ''
}

function Set-SMBv1State(){
	
	Param(
		# Enable means to change the setting to the default / insecure state.
		$Enable = $false
	)

	####################
	# Disable SMBv1 - This should be last because of reboot prompt
	####################
	if ($smbv1){
		$smb_state = (Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State
		if (-NOT $Enable) { 
			if ($smb_state -eq 'Enabled'){
				Write-Host '[*] Disabling SMBv1 - requires reboot'
				Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
			}else{
				Write-Host '[*] SMBv1 already disabled.'
			}
		}else{
			Write-Host '[*] We are not going to enable SMBv1. You do not need it. Do it yourself.'
			# Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol
		}
	}
	
	# Let's give a little whitespace for readability
	Write-Host ''
}

####################
# Print Functions
####################


# Print program beginning message
####################
function Write-ProgStart {
	Write-Host "$warning"
	Write-Host "[*] Started Date/Time: $(get-date -format yyyyMMddTHHmmssffzz)"
	Write-Host "[*] $script_name is about to start. Run the following Nmap scan (from a seperate system) and check current statue before proceeding:"
	Write-Host '[*] sudo nmap -sT -p 135,137,139,445,3389 <IP Address>'
}
####################

# Print program completed message
####################
function Write-ProgComplete {
	Write-Host "[*] Completed Date/Time: $(get-date -format yyyyMMddTHHmmssffzz)"
	Write-Host "[*] $script_name has completed. Run the following Nmap scan (from a seperate system) and check the results:"
	Write-Host '[*] sudo nmap -sT -p 135,137,139,445,3389 <IP Address>'
	Write-Host '[*] Do not forget to reboot before testing.'
}
####################

# Print configuration information
####################
function Write-SAWHConfig {
	Write-Host ""
	Write-Host "################################"
	Write-Host "[*] SAWH Configuration Settings"
	Write-Host "################################"
	Write-Host "[*] Modifying network interface mode is set to: $inf_mode"
	Write-Host "[*] Modifying NetBIOS is set to: $netbios"
	Write-Host "[*] Modifying Firewall Rules is set to: $fw_rules"
	Write-Host "[*] Modifying Network Adapter Bindings is set to: $bindings"
	Write-Host "    [*] Modifying Network Adapter IPv6 Binding is set to: $ipv6"
	Write-Host "    [*] Modifying Network Adapter LLTP Bindings is set to: $lltp"
	Write-Host "    [*] Modifying Network Adapter Client / Server Bindings is set to: $client"
	Write-Host "    [*] Modifying Network Adapter Multiplexor Binding is set to: $namp"
	Write-Host "[*] Modifying Terminal Services (RDP) is set to: $rdp"
	Write-Host "[*] Modifying SMBv1 is set to: $smbv1"
	Write-Host "################################"
	Write-Host ""
}
####################

# Print System State
####################
function Write-SystemState {
	Get-InterfaceModeState
	Get-NetBIOSState
	Get-SAWHFWRulesState
	Get-NetBindingsState
	Get-TerminalServicesState
	Get-SMBv1State
}
####################


####################
# Main
####################
Get-AdminState
Write-ProgStart

# Determine what user wants to do
####################
$action = Read-Host "Do you want to check, disable, or rollback Windows services? [check/disable/rollback]"
# Set user input.
if ($action -eq 'check') {
    $check = $true
}
if ($action -eq 'disable') {
    $disable = $true
}
if ($action -eq 'rollback') {
    $rollback = $true
}
# Check user input. Fail if it isn't exactly what we expected
if ($rollback -eq $false -And $disable -eq $false -And $check -eq $false){
	Write-Host "[!] User did not select a valid action. Exiting..."
	Exit
}

# Run check function
####################
if ($check){
	Write-SAWHConfig
	Write-SystemState
	Exit
}

# Run action functions
####################
# Write state before we start?
if ($start_state) { Write-SystemState }

# Run disable function
####################
if ($disable){
	# Get user confirmation before proceeding
	Get-UserConfirmation

	Set-InterfaceModeState
	Set-NetBIOSState
	Set-SAWHFWRulesState
	Set-NetBindingsState
	Set-TerminalServicesState
	Set-SMBv1State
}

# Run enable function
####################
if ($enable){
	# Get user confirmation before proceeding
	Get-UserConfirmation

	Set-InterfaceModeState -Enabled $true
	Set-NetBIOSState -Enabled $true
	Set-SAWHFWRulesState -Enabled $true
	Set-NetBindingsState -Enabled $true
	Set-TerminalServicesState -Enabled $true
	Set-SMBv1State -Enabled $true

}

# Write state after completion?
if ($completed_state) { Write-SystemState }

# All done, say goodbye
Write-ProgComplete