#!/bin/bash
# 
#  ACT Tool Extraction Script for Linux
#
#  
#  REVISION HISTORY:
# ------------------------------------------------------------------------------------
#  Version	 Date			Author			  Activity			
# ------------------------------------------------------------------------------------
#  1.2		01/08/2024	  Patel, Mayur		Script Created 				
#  1.3		05/26/2026	  Patel, Mayur		Linux compatibility updates, rkhunter and daily cron checks
#  1.4		06/11/2026	  Audit Update		Added ISACA Linux/Unix audit coverage: GRUB, partitioning,
#  					            /boot, services/run-levels, SSH keys, DenyHosts/Fail2ban,
#  					            patches, USB, SELinux/AppArmor, IPv6, user activity (ac/last),
#  					            password reuse/expiry/lock/strength, empty-password check,
#  					            firewall, sysctl/ICMP, NTP/chrony, expanded log review
#
#
#
# Notice:
# ------------------------------------------------------------------------------------
#	The purpose of this  read only  script is to download data that can be analyzed as part of our audit.  
#	We expect that you will follow your company s regular change management policies and procedures prior to running the script.
#
#	  
#
# ------------------------------------------------------------------------------------



###### Declaration of variables
ERRFILE="`uname -n`_errors.txt"
SCRIPTFLOW="`uname -n`_scriptflow.txt"
FOLDER="`uname -n`_`uname`_data.tar"
TARFILE="`uname -n`_ACTT_Output_Linux.tar"
mkdir ./$FOLDER
cd ./$FOLDER

echo $ERRFILE $SCRIPTFLOW $FOLDER $TARFILE 

sleep 10
echo "|^|" > ACTT_CONFIG_FIELDTERMINATOR.actt

##### Function to remove the terporary files created by this script
CLEARALL()
{
	tput smso;tput blink;
	echo "   Script Inturrupted. Exiting the script on a signal.";
	tput rmso;
	rm -f *.txt *.actt
echo "  Cleaning up the temporary files. Please wait ...  "
sleep 5
}

opt='y'
while test $opt = 'y';do

#### Code to trap the signals
trap ' CLEARALL; exit 1' 1 2 3 15 24

##### To check the OS on which the script is running
ver=`uname`
ver1="Linux"
if [[ "$ver" == *"$ver1"* ]]; then
echo "Script Starting on Linux." >> $SCRIPTFLOW
clear
echo "Script Starting on Linux. Please hit enter to continue"
read STRN
else
clear
echo "This Script is for Linux system and this OS is not Linux." >> $SCRIPTFLOW
echo "This Script is for Linux system and this OS is not Linux. If you hit enter the extraction will continue"
read STRN
fi

##### Check for root priviledge
if [ `id -u` == 0 ]; then
echo "This script is being run as root" >> $SCRIPTFLOW
else
echo "Script not run as root" >> $SCRIPTFLOW
clear
echo "ABORT Initiated due to insufficient privilege...Please run this script with root privilege."
read STRN
exit 1
fi

##### Extraction of System Information
echo "Extraction of system information  " | tee $SCRIPTFLOW
echo "SettingName nvarchar(max)|^|SettingValue nvarchar(max)"  > ACTT_CONFIG_SETTINGS.actt
echo "Extraction Script Version|^|1.4" >> ACTT_CONFIG_SETTINGS.actt
#echo "Opeating System|^|`uname`" >> ACTT_CONFIG_SETTINGS.actt
echo "Extract Application Version|^|ACTT LINUX" >> ACTT_CONFIG_SETTINGS.actt
if [ -f /etc/os-release ]; then
	. /etc/os-release
	echo "Operating System Version|^|$PRETTY_NAME" >> ACTT_CONFIG_SETTINGS.actt
elif [ -f /etc/redhat-release ]; then
	echo "Operating System Version|^|`cat /etc/redhat-release`" >> ACTT_CONFIG_SETTINGS.actt
else
	echo "Operating System Version|^|`uname -sr`" >> ACTT_CONFIG_SETTINGS.actt
fi
echo "Extraction Script Start Time|^|`date +\"%D %I:%M:%S %p\"`" >> ACTT_CONFIG_SETTINGS.actt
echo "Extraction completed. Output file is \"ACTT_CONFIG_SETTINGS.actt\" " | tee -a $SCRIPTFLOW



#####1,2 Extraction of /etc/passwd and /etc/shadow files
echo "Extraction of /etc/passwd file " 
if [ -f /etc/passwd ]; then
	passlen=`awk -F: '($1 ~ "root") {print $2}' /etc/passwd`
	if [ "$passlen" == x ]; then
		if [ -f /etc/shadow ]; then
		cat /etc/passwd > etc_passwd.txt
		echo "Extraction completed. Output file is \"etc_passwd.txt\" " | tee -a $SCRIPTFLOW
		echo "Extraction of /etc/shadow file" | tee -a $SCRIPTFLOW
		awk -F: '{
		if ($2 == "*" || $2 == "!!")
			print $1":"$2":"$3":"$4":"$5":"$6":"$7":"$8":"$9
		else
			print $1":"length($2)":"$3":"$4":"$5":"$6":"$7":"$8":"$9}' /etc/shadow > etc_shadow.txt
		echo "Extraction completed. Output file is \"etc_shadow.txt\" " | tee -a $SCRIPTFLOW
		else
		echo "  /etc/shadow file does not exist in the  system"  >> $ERRFILE
		fi
	else
		awk -F: '{
		if ($2 == "*" || $2 == "!!")
			print $1":"$2":"$3":"$4":"$5":"$6":"$7
		else
			print $1":"length($2)":"$3":"$4":"$5":"$6":"$7}' /etc/passwd > etc_passwd.txt
		echo "Extraction completed. Output file is \"etc_passwd.txt\" " | tee -a $SCRIPTFLOW
	fi
else
	echo "  /etc/passwd file does not exist in the system"  >> $ERRFILE
fi

#####3 Extraction of /etc/group file
echo "Extraction of /etc/group file " | tee -a $SCRIPTFLOW
if [ -f /etc/group ]; then
cat /etc/group > etc_group.txt 2>> $ERRFILE
else
echo "/etc/group does not exist in the system" > $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_group.txt\" " | tee -a $SCRIPTFLOW

#####4 Extraction of /etc/securetty file
echo "Extraction of /etc/securetty file " | tee -a $SCRIPTFLOW
if [ -f /etc/securetty ];then
cat /etc/securetty > etc_securetty.txt 2>> $ERRFILE
else
echo "/etc/securetty file does not exist in the system" >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_securetty.txt\" " | tee -a $SCRIPTFLOW

####5 Extraction of /etc/sudoers file
echo "Extraction of /etc/sudoers file " | tee -a $SCRIPTFLOW
if [ -f /etc/sudoers ]; then
cat /etc/sudoers > etc_sudoers.txt 2>> $ERRFILE
else
echo "/etc/sudoers file does not exist in the system"  >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_sudoers.txt\" " | tee -a $SCRIPTFLOW

####6 Extraction of /etc/login.defs command
echo " Extraction of /etc/login.defs file " | tee -a $SCRIPTFLOW
if [ -f /etc/login.defs ]; then
cat /etc/login.defs > etc_login_defs.txt
else
echo "/etc/login.defs file does not exist in the system " >> $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_login_defs.txt\" " | tee -a $SCRIPTFLOW

####7 Extraction of /etc/pam.d/login command
echo " Extraction of /etc/pam.d/login file " | tee -a $SCRIPTFLOW
if [ -f /etc/pam.d/login ]; then
cat /etc/pam.d/login > etc_pamd_login.txt
else
echo "/etc/pam.d/login file does not exist in the system " >> $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_pamd_login.txt\" " | tee -a $SCRIPTFLOW

####8 Extraction of /etc/pam.d/system-auth command
echo " Extraction of /etc/pam.d/system-auth file " | tee -a $SCRIPTFLOW
if [ -f /etc/pam.d/system-auth ]; then
cat /etc/pam.d/system-auth > etc_pamd_system_auth.txt
else
echo "/etc/pam.d/system-auth file does not exist in the system " >> $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_pamd_system_auth.txt\" " | tee -a $SCRIPTFLOW

####9,10 Extraction of services from /etc/xinetd.conf file and files from /etc/xinetd.d directory
echo "Extraction of service files from /etc/xinetd.d directory " | tee -a $SCRIPTFLOW
echo "Extraction of /etc/xinetd.conf file " | tee -a $SCRIPTFLOW
if [ -f /etc/xinetd.conf ];then
echo "/etc/xinetd.conf: "
cat /etc/xinetd.conf > etc_xinetd_conf.txt
else
echo "/etc/xinetd.conf does not exist in the system " >> $ERRFILE
fi
if [ -d /etc/xinetd.d ]; then
ls /etc/xinetd.d/*| while read FILE
do
echo "$FILE:"
cat $FILE
done >> etc_xinetd_files.txt
else
echo "/etc/xinetd.d directory does not exist in the system " >> $ERRFILE
fi
echo "Extraction completed. Ouput file is \"etc_xinetd_files.txt\" " | tee -a $SCRIPTFLOW

#####11 Extraction of /var/log/sudolog file
echo "Extraction of sudolog file "
if [ -f /var/log/sudo.log ]; then
cat /var/log/sudo.log > var_log_sudolog.txt 2>> $ERRFILE
else
echo "/var/log/sudo.log file does not exist"  >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_log_sudolog.txt\" " | tee -a $SCRIPTFLOW

#####12 Extraction of /var/log/secure file -- same as Sulog in Solaris
echo "Extraction of secure file "
if [ -f /var/log/secure ]; then
cat /var/log/secure > var_log_secure.txt 2>> $ERRFILE
else
echo "/var/log/secure file does not exist"  >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_log_secure.txt\" " | tee -a $SCRIPTFLOW

#####13 Extraction of /etc/hosts.equiv file
echo "Extraction of /etc/hosts.equiv file "
if [ -f /etc/hosts.equiv ]; then
cat /etc/hosts.equiv > etc_hosts_equiv.txt 2>> $ERRFILE
else
echo "/etc/hosts.equiv file does not exist"  >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_hosts_equiv.txt\" " | tee -a $SCRIPTFLOW

#####14 Extraction of .rhosts files from users' home directories
echo "Extraction of .rhosts files " | tee -a $SCRIPTFLOW
while read line
do
homes=`echo $line|cut -d: -f6 2>> $ERRFILE`
users=`echo $line|cut -d: -f1 2>> $ERRFILE`
	if [ -f $homes/.rhosts ];then
	echo "  .rhosts file found in user \"$users\" home directory - $homes:"
	cat $homes/.rhosts 2>> $ERRFILE
	else
	echo " .rhosts file does not exist in user \"$users\" home directory - $homes" >> $ERRFILE 
	fi
done </etc/passwd > rhosts.txt
echo "Extraction completed. Output file is \"rhosts.txt\" " | tee -a $SCRIPTFLOW

#####14.1 20/Mar/2016 Extraction of .shosts  files from users' home directories
echo "Extraction of .shosts files " | tee -a $SCRIPTFLOW
find / -xdev -name .shosts -print -exec ls -la {} \; -exec cat {} \; > shosts.txt 2>> $ERRFILE
echo "Extraction completed. Output file is \"shosts_Sh.txt\" " | tee -a $SCRIPTFLOW

#####15 Extraction of at.allow file
echo "Extraction of at.allow file "
if [ -f /etc/at.allow ]; then
	cat /etc/at.allow > etc_at_allow.txt 2>> $ERRFILE
else
	echo "/etc/at.allow file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_at_allow.txt\" " | tee -a $SCRIPTFLOW

#####16 Extraction of at.deny file
echo "Extraction of at.deny file "
if [ -f /etc/at.deny ]; then
	cat /etc/at.deny > etc_at_deny.txt 2>> $ERRFILE
else
	echo "/etc/at.deny file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_at_deny.txt\" " | tee -a $SCRIPTFLOW

#####17 Extraction of cron.deny file
echo "Extraction of cron.deny file "
if [ -f /etc/cron.deny ]; then
	cat /etc/cron.deny > etc_cron_deny.txt 2>> $ERRFILE
else
	echo "/etc/cron.deny file does not exist " >> $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_cron_deny.txt\" " | tee -a $SCRIPTFLOW

#####18 Extraction of cron.allow file
echo "Extraction of cron.allow file "
if [ -f /etc/cron.allow ]; then
	cat /etc/cron.allow > etc_cron_allow.txt 2>> $ERRFILE
else
	echo "/etc/cron.allow file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_cron_allow.txt\" " | tee -a $SCRIPTFLOW

#####19 Extraction of cron job files
echo "Extraction of cron job files " | tee -a $SCRIPTFLOW
> var_spool_cron_crontabs.txt
for cron_dir in /var/spool/cron /var/spool/cron/crontabs /var/cron/tabs
do
	if [ -d "$cron_dir" ]; then
		echo "$cron_dir:" >> var_spool_cron_crontabs.txt
		ls -la "$cron_dir" | grep -v "total" >> var_spool_cron_crontabs.txt 2>> $ERRFILE
	else
		echo "$cron_dir directory does not exist " >> $ERRFILE
	fi
done
echo "Extraction completed. Output file is \"var_spool_cron_crontabs.txt\" " | tee -a $SCRIPTFLOW

#####19.1 Extraction of daily cron jobs
echo "Extraction of daily cron jobs " | tee -a $SCRIPTFLOW
> etc_cron_daily_jobs.txt
if [ -f /etc/anacrontab ]; then
	echo "/etc/anacrontab:" >> etc_cron_daily_jobs.txt
	cat /etc/anacrontab >> etc_cron_daily_jobs.txt 2>> $ERRFILE
else
	echo "/etc/anacrontab file does not exist " >> $ERRFILE
fi
if [ -f /etc/crontab ]; then
	echo "/etc/crontab:" >> etc_cron_daily_jobs.txt
	cat /etc/crontab >> etc_cron_daily_jobs.txt 2>> $ERRFILE
else
	echo "/etc/crontab file does not exist " >> $ERRFILE
fi
if [ -d /etc/cron.daily ]; then
	echo "/etc/cron.daily listing:" >> etc_cron_daily_jobs.txt
	ls -la /etc/cron.daily >> etc_cron_daily_jobs.txt 2>> $ERRFILE
	for FILE in /etc/cron.daily/*
	do
		if [ -f "$FILE" ]; then
			echo "$FILE:" >> etc_cron_daily_jobs.txt
			cat "$FILE" >> etc_cron_daily_jobs.txt 2>> $ERRFILE
		fi
	done
else
	echo "/etc/cron.daily directory does not exist " >> $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_cron_daily_jobs.txt\" " | tee -a $SCRIPTFLOW

#####20 Extraction of at job files
echo "Extraction of at job files " | tee -a $SCRIPTFLOW
> var_spool_cron_atjobs.txt
for at_dir in /var/spool/cron/atjobs /var/spool/at /var/spool/atjobs
do
	if [ -d "$at_dir" ]; then
		echo "$at_dir:" >> var_spool_cron_atjobs.txt
		ls -la "$at_dir" | grep -v "total" >> var_spool_cron_atjobs.txt 2>> $ERRFILE
	else
		echo "$at_dir directory does not exist " >> $ERRFILE
	fi
done
echo "Extraction completed. Output file is \"var_spool_cron_atjobs.txt\" " | tee -a $SCRIPTFLOW

#####21 Extraction of access permissions of critical files
echo "Extracting permissions of critical files " | tee -a $SCRIPTFLOW
for dir in "/ /bin /sbin /usr/bin /usr /etc /var"
do ls -l $dir 2>> $ERRFILE; done > file_perms.txt
echo "Extraction completed. Output file is \"file_perms.txt\" " | tee -a $SCRIPTFLOW

#####22 Extraction of installed softwares history
echo "Installed softwares history " | tee -a $SCRIPTFLOW
if command -v rpm >/dev/null 2>&1; then
	rpm -qai > software_history.txt 2>> $ERRFILE
elif command -v dpkg-query >/dev/null 2>&1; then
	dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Status}\n' > software_history.txt 2>> $ERRFILE
elif command -v apk >/dev/null 2>&1; then
	apk info -vv > software_history.txt 2>> $ERRFILE
else
	echo "No supported package inventory command found" > software_history.txt
	echo "No supported package inventory command found" >> $ERRFILE
fi
echo "Extraction completed. Output file is \"software_history.txt\" " | tee -a $SCRIPTFLOW

#####23 Extraction of /etc/syslog.conf file
echo "Extraction of syslog.conf fiile " | tee -a $SCRIPTFLOW
if [ -f /etc/syslog.conf ]; then
cat /etc/syslog.conf > etc_syslog_conf.txt 2>> $ERRFILE
else
echo "/etc/syslog.conf file does not exist in the system" >> $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_syslog_conf.txt\" " | tee -a $SCRIPTFLOW

#####24 Extracting the first 100 lines of /var/log/messages file
if [ -f /var/log/messages ];then
cat /var/log/messages > var_log_messages.txt
else
	echo "/var/log/messages does not exist"
fi

#####25 Extraction of /etc/ssh/sshd_config
echo "Extraction of /etc/ssh/sshd_config file "
if [ -f /etc/ssh/sshd_config ]; then
cat /etc/ssh/sshd_config > etc_ssh_sshd_config.txt 2>> $ERRFILE
else
echo "/etc/ssh/sshd_config does not exist in the system " >> $ERRFILE
fi
echo "Extraction completed. Output file is \"etc_ssh_sshd_config.txt\" " | tee -a $SCRIPTFLOW

#####26 Extraction of /var/log/cron file
echo "Extraction of /var/log/cron file "
if [ -f /var/log/cron ]; then
	cat /var/log/cron > var_log_cron.txt 2>> $ERRFILE
else
	echo "/var/log/cron file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"var_log_cron.txt\" " | tee -a $SCRIPTFLOW

#####27 Extraction of ftpusers file
echo "Extraction of ftpusers file "
if [ -f /etc/ftpusers ]; then
	cat /etc/ftpusers > etc_ftpusers.txt 2>> $ERRFILE
else
	echo "/etc/ftpusers file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_ftpusers.txt\" " | tee -a $SCRIPTFLOW
###### 18/Mar/2016: Update for VSFTPD folder
echo "Extraction of ftpusers file "
if [ -f /etc/vsftpd/ftpusers ]; then
	cat /etc/vsftpd/ftpusers > etc_vsftpd_ftpusers.txt 2>> $ERRFILE
else
	echo "/etc/vsftpd/ftpusers file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_vsftpd_ftpusers.txt\" " | tee -a $SCRIPTFLOW


##########28 Script to extract access permissions of the files located in /etc/cron.d & /var/spool/cron/crontabs directories ##########

echo "  File permissions of /var/adm/cron, /var/spool/cron/crontabs & /var/spool/cron/atjobs directories" | tee -a  $SCRIPTFLOW
> cron_perms.txt
for cron_path in /var/spool/cron /var/spool/cron/crontabs /var/cron/tabs /var/spool/cron/atjobs /var/spool/at /var/spool/atjobs /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/crontab /etc/anacrontab /etc/at.allow /etc/at.deny
do
	if [ -e "$cron_path" ]; then
		ls -la "$cron_path" >> cron_perms.txt 2>> $ERRFILE
	else
		echo "$cron_path does not exist " >> $ERRFILE
	fi
done
echo "  Extraction Completed. Output file is \"cron_perms.txt\" " | tee -a  $SCRIPTFLOW

##########29 Script to extract the umask values from all '.profile' files of the users ##########

echo "   Extraction of umask values from user's home directories"
while read line; do
home=`echo $line|cut -d ":" -f6`
if [ -f $home/.profile ]; then
	name=`echo $line|cut -d ":" -f1`
	u_value=`cat $home/.profile |awk '/umask/ {print $2}'`
	if [ x"$u_value" != 'x' ]; then echo "$name $u_value";fi
fi
done < /etc/passwd > user_mask.txt 2>> $ERRFILE
echo "  Extraction completed. Output file is \"user_mask.txt\" " | tee -a $SCRIPTFLOW

#####30 Extraction of /etc/profile file
echo "Extraction of /etc/profile file " | tee -a $SCRIPTFLOW
if [ -f /etc/profile ]; then
cat /etc/profile > etc_profile.txt 2>> $ERRFILE
else
echo "/etc/profile file does not exist"  >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_profile.txt\" " | tee -a $SCRIPTFLOW

#####31 Extraction of /etc/services file
echo "Extraction of /etc/services file "
if [ -f /etc/services ]; then
cat /etc/services > etc_services.txt 2>> $ERRFILE
else
echo "/etc/services file does not exist"  >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_services.txt\" " | tee -a $SCRIPTFLOW

#####32 Extraction of /etc/protocols file
echo "Extraction of /etc/protocols file "
if [ -f /etc/protocols ]; then
cat /etc/protocols > etc_protocols.txt 2>> $ERRFILE
else
echo "/etc/protocols file does not exist "  >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_protocols.txt\" " | tee -a $SCRIPTFLOW

#####33 Extraction of listening_ports.txt file
echo "Extraction of listening_ports.txt file\n" | tee -a $SCRIPTFLOW

if command -v ss >/dev/null 2>&1; then
	ss -tulpn >> listening_ports.txt 2>> $ERRFILE
elif command -v netstat >/dev/null 2>&1; then
	netstat -tulpn >> listening_ports.txt 2>> $ERRFILE
else
	echo "Neither ss nor netstat command found" > listening_ports.txt
	echo "Neither ss nor netstat command found" >> $ERRFILE
fi


##########34 Script to extract /etc/vsftpd/vsftpd.conf file 
echo "Extraction of /etc/vsftpd/vsftpd.conf file "
if [ -f /etc/vsftpd/vsftpd.conf ]; then
	cat /etc/vsftpd/vsftpd.conf > etc_vsftpdconf.txt 2>> $ERRFILE
else
	echo "/etc/vsftpd/vsftpd.conf file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_vsftpdconf.txt\" " | tee -a $SCRIPTFLOW

##### 35 Extraction of at.deny file
echo "Extraction of ldap.conf file "
if [ -f /etc/openldap/ldap.conf ]; then
	cat /etc/openldap/ldap.conf > etc_openldap_ldap.txt 2>> $ERRFILE
else
	echo "/etc/openldap/ldap.conf file does not exist " >> $ERRFILE 
fi
echo "Extraction completed. Output file is \"etc_openldap_ldap.txt\" " | tee -a $SCRIPTFLOW

#####36 Extraction of rkhunter configuration, status, and scheduled jobs
echo "Extraction of rkhunter configuration and status " | tee -a $SCRIPTFLOW
{
	echo "rkhunter command:"
	if command -v rkhunter >/dev/null 2>&1; then
		command -v rkhunter
		rkhunter --version 2>> $ERRFILE
	else
		echo "rkhunter command not found"
	fi

	echo ""
	echo "rkhunter running processes:"
	ps -ef | grep "[r]khunter" 2>> $ERRFILE

	echo ""
	echo "rkhunter package:"
	if command -v rpm >/dev/null 2>&1; then
		rpm -q rkhunter 2>> $ERRFILE
	elif command -v dpkg-query >/dev/null 2>&1; then
		dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Status}\n' rkhunter 2>> $ERRFILE
	elif command -v apk >/dev/null 2>&1; then
		apk info -e rkhunter 2>> $ERRFILE
	else
		echo "No supported package query command found"
	fi

	echo ""
	echo "rkhunter systemd service/timer status:"
	if command -v systemctl >/dev/null 2>&1; then
		systemctl list-unit-files 'rkhunter*' 2>> $ERRFILE
		systemctl status rkhunter.service rkhunter.timer --no-pager 2>> $ERRFILE
	else
		echo "systemctl command not found"
	fi

	echo ""
	echo "rkhunter cron references:"
	grep -R "rkhunter" /etc/cron* /var/spool/cron /var/cron/tabs 2>> $ERRFILE
} > rkhunter_status.txt

> rkhunter_config.txt
for FILE in /etc/rkhunter.conf /etc/default/rkhunter /etc/sysconfig/rkhunter
do
	if [ -f "$FILE" ]; then
		echo "$FILE:" >> rkhunter_config.txt
		cat "$FILE" >> rkhunter_config.txt 2>> $ERRFILE
	else
		echo "$FILE file does not exist " >> $ERRFILE
	fi
done
if [ -d /etc/rkhunter.conf.d ]; then
	for FILE in /etc/rkhunter.conf.d/*
	do
		if [ -f "$FILE" ]; then
			echo "$FILE:" >> rkhunter_config.txt
			cat "$FILE" >> rkhunter_config.txt 2>> $ERRFILE
		fi
	done
else
	echo "/etc/rkhunter.conf.d directory does not exist " >> $ERRFILE
fi

if [ -f /var/log/rkhunter.log ]; then
	cat /var/log/rkhunter.log > var_log_rkhunter.txt 2>> $ERRFILE
else
	echo "/var/log/rkhunter.log file does not exist " >> $ERRFILE
fi
echo "Extraction completed. Output files are \"rkhunter_status.txt\", \"rkhunter_config.txt\", and \"var_log_rkhunter.txt\" " | tee -a $SCRIPTFLOW


# =====================================================================================
# ===== ISACA LINUX/UNIX AUDIT ADDITIONS (v1.4) -- all read-only status extraction =====
# =====================================================================================

#####37 Physical / BIOS security (manual note + scriptable artifacts)
echo "Recording physical/BIOS security note " | tee -a $SCRIPTFLOW
{
	echo "NOTE: BIOS password, boot-device restrictions (CD/DVD/USB/floppy) and"
	echo "physical access controls cannot be read by software and MUST be verified"
	echo "manually/by interview against the organization's hardening standard."
	echo ""
	echo "DMI / hardware identification (dmidecode):"
	if command -v dmidecode >/dev/null 2>&1; then
		dmidecode -t system -t bios 2>> $ERRFILE
	else
		echo "dmidecode command not found"
	fi
} > physical_bios_note.txt
echo "Extraction completed. Output file is \"physical_bios_note.txt\" " | tee -a $SCRIPTFLOW

#####38 GRUB bootloader password protection
echo "Extraction of GRUB bootloader configuration " | tee -a $SCRIPTFLOW
> grub_config.txt
for FILE in /boot/grub/menu.lst /boot/grub/grub.conf /boot/grub2/grub.cfg /boot/grub/grub.cfg /etc/grub.conf /etc/default/grub
do
	if [ -f "$FILE" ]; then
		echo "$FILE:" >> grub_config.txt
		cat "$FILE" >> grub_config.txt 2>> $ERRFILE
		echo "" >> grub_config.txt
	else
		echo "$FILE does not exist " >> $ERRFILE
	fi
done
if [ -d /etc/grub.d ]; then
	echo "/etc/grub.d listing:" >> grub_config.txt
	ls -la /etc/grub.d >> grub_config.txt 2>> $ERRFILE
	echo "password directives in /etc/grub.d:" >> grub_config.txt
	grep -RHi "password" /etc/grub.d >> grub_config.txt 2>> $ERRFILE
else
	echo "/etc/grub.d directory does not exist " >> $ERRFILE
fi
echo "Extraction completed. Output file is \"grub_config.txt\" " | tee -a $SCRIPTFLOW

#####39 Disk partitioning and filesystem layout
echo "Extraction of disk partitioning / filesystem layout " | tee -a $SCRIPTFLOW
{
	echo "/etc/fstab:"
	if [ -f /etc/fstab ]; then cat /etc/fstab 2>> $ERRFILE; else echo "/etc/fstab does not exist"; fi
	echo ""
	echo "Mounted filesystems (mount):"
	mount 2>> $ERRFILE
	echo ""
	echo "Disk free / filesystem usage (df -hT):"
	df -hT 2>> $ERRFILE
	echo ""
	echo "Block devices (lsblk):"
	if command -v lsblk >/dev/null 2>&1; then lsblk -f 2>> $ERRFILE; else echo "lsblk not found"; fi
	echo ""
	echo "Block device attributes (blkid):"
	if command -v blkid >/dev/null 2>&1; then blkid 2>> $ERRFILE; else echo "blkid not found"; fi
} > disk_partitioning.txt
echo "Extraction completed. Output file is \"disk_partitioning.txt\" " | tee -a $SCRIPTFLOW

#####40 /boot directory read-only status
echo "Extraction of /boot directory mount/permission status " | tee -a $SCRIPTFLOW
{
	echo "/boot directory listing:"
	ls -ld /boot 2>> $ERRFILE
	echo ""
	echo "/boot fstab entry (look for 'ro' option):"
	grep -E "[[:space:]]/boot[[:space:]]" /etc/fstab 2>> $ERRFILE
	echo ""
	echo "/boot current mount options:"
	mount 2>> $ERRFILE | grep -E " /boot " 2>> $ERRFILE
} > boot_dir_status.txt
echo "Extraction completed. Output file is \"boot_dir_status.txt\" " | tee -a $SCRIPTFLOW

#####41 Installed packages -> enabled services and run levels
echo "Extraction of enabled services and run levels " | tee -a $SCRIPTFLOW
{
	echo "Current runlevel / default target:"
	if command -v runlevel >/dev/null 2>&1; then runlevel 2>> $ERRFILE; fi
	if command -v systemctl >/dev/null 2>&1; then systemctl get-default 2>> $ERRFILE; fi
	echo ""
	echo "Services enabled at boot (chkconfig --list, level 3 'on'):"
	if command -v chkconfig >/dev/null 2>&1; then
		chkconfig --list 2>> $ERRFILE | grep '3:on' 2>> $ERRFILE
		echo "--- full chkconfig --list ---"
		chkconfig --list 2>> $ERRFILE
	else
		echo "chkconfig command not found"
	fi
	echo ""
	echo "systemd unit files (enabled/disabled state):"
	if command -v systemctl >/dev/null 2>&1; then
		systemctl list-unit-files --type=service --no-pager 2>> $ERRFILE
		echo ""
		echo "Currently running services:"
		systemctl list-units --type=service --state=running --no-pager 2>> $ERRFILE
	else
		echo "systemctl command not found"
	fi
} > services_runlevels.txt
echo "Extraction completed. Output file is \"services_runlevels.txt\" " | tee -a $SCRIPTFLOW

#####42 SSH passwordless login (authorized_keys inventory)
echo "Extraction of SSH authorized_keys inventory " | tee -a $SCRIPTFLOW
> ssh_authorized_keys.txt
while read line
do
	homes=`echo $line | cut -d: -f6`
	users=`echo $line | cut -d: -f1`
	for keyfile in "$homes/.ssh/authorized_keys" "$homes/.ssh/authorized_keys2"
	do
		if [ -f "$keyfile" ]; then
			echo "User \"$users\" key file - $keyfile:" >> ssh_authorized_keys.txt
			ls -la "$keyfile" >> ssh_authorized_keys.txt 2>> $ERRFILE
			# Record fingerprints/comments only (full key bodies are public keys, but keep listing concise)
			awk '{print $1, $NF}' "$keyfile" >> ssh_authorized_keys.txt 2>> $ERRFILE
			echo "" >> ssh_authorized_keys.txt
		fi
	done
done < /etc/passwd
echo "Extraction completed. Output file is \"ssh_authorized_keys.txt\" " | tee -a $SCRIPTFLOW

#####43 DenyHosts and Fail2ban intrusion prevention
echo "Extraction of DenyHosts / Fail2ban / hosts.deny status " | tee -a $SCRIPTFLOW
> denyhosts_fail2ban.txt
{
	echo "/etc/hosts.deny:"
	if [ -f /etc/hosts.deny ]; then cat /etc/hosts.deny 2>> $ERRFILE; else echo "does not exist"; fi
	echo ""
	echo "/etc/hosts.allow:"
	if [ -f /etc/hosts.allow ]; then cat /etc/hosts.allow 2>> $ERRFILE; else echo "does not exist"; fi
	echo ""
	echo "DenyHosts configuration:"
	for FILE in /etc/denyhosts.conf /etc/denyhosts.cfg
	do
		if [ -f "$FILE" ]; then echo "$FILE:"; cat "$FILE" 2>> $ERRFILE; fi
	done
	echo ""
	echo "Fail2ban presence / status:"
	if command -v fail2ban-client >/dev/null 2>&1; then
		fail2ban-client status 2>> $ERRFILE
	else
		echo "fail2ban-client command not found"
	fi
	echo ""
	echo "Fail2ban configuration files:"
	for FILE in /etc/fail2ban/jail.conf /etc/fail2ban/jail.local /etc/fail2ban/fail2ban.conf
	do
		if [ -f "$FILE" ]; then echo "$FILE:"; cat "$FILE" 2>> $ERRFILE; echo ""; fi
	done
	if [ -d /etc/fail2ban/jail.d ]; then
		echo "/etc/fail2ban/jail.d listing:"; ls -la /etc/fail2ban/jail.d 2>> $ERRFILE
	fi
} > denyhosts_fail2ban.txt
echo "Extraction completed. Output file is \"denyhosts_fail2ban.txt\" " | tee -a $SCRIPTFLOW

#####44 Updated patches / pending updates
echo "Extraction of pending patch / update status " | tee -a $SCRIPTFLOW
{
	if command -v dnf >/dev/null 2>&1; then
		echo "dnf check-update:"
		dnf check-update 2>> $ERRFILE
	elif command -v yum >/dev/null 2>&1; then
		echo "yum check-update:"
		yum check-update 2>> $ERRFILE
	elif command -v apt >/dev/null 2>&1; then
		echo "apt list --upgradable:"
		apt list --upgradable 2>> $ERRFILE
	elif command -v zypper >/dev/null 2>&1; then
		echo "zypper list-updates:"
		zypper list-updates 2>> $ERRFILE
	else
		echo "No supported package manager found for update check"
	fi
} > pending_updates.txt
if [ -f /var/log/yum.log ]; then
	cat /var/log/yum.log > var_log_yum.txt 2>> $ERRFILE
elif [ -f /var/log/dnf.log ]; then
	cat /var/log/dnf.log > var_log_yum.txt 2>> $ERRFILE
else
	echo "/var/log/yum.log and /var/log/dnf.log do not exist " >> $ERRFILE
fi
echo "Extraction completed. Output files are \"pending_updates.txt\" and \"var_log_yum.txt\" " | tee -a $SCRIPTFLOW

#####45 USB device restriction status
echo "Extraction of USB device restriction status " | tee -a $SCRIPTFLOW
{
	echo "modprobe.d entries referencing usb-storage:"
	if [ -d /etc/modprobe.d ]; then
		grep -RHi "usb-storage" /etc/modprobe.d 2>> $ERRFILE
		echo "--- /etc/modprobe.d listing ---"
		ls -la /etc/modprobe.d 2>> $ERRFILE
	else
		echo "/etc/modprobe.d directory does not exist"
	fi
	echo ""
	echo "usb-storage module currently loaded (lsmod):"
	if command -v lsmod >/dev/null 2>&1; then lsmod 2>> $ERRFILE | grep -i usb_storage 2>> $ERRFILE; else echo "lsmod not found"; fi
	echo ""
	echo "Connected USB devices (lsusb):"
	if command -v lsusb >/dev/null 2>&1; then lsusb 2>> $ERRFILE; else echo "lsusb not found"; fi
} > usb_status.txt
echo "Extraction completed. Output file is \"usb_status.txt\" " | tee -a $SCRIPTFLOW

#####46 SELinux / AppArmor mandatory access control status
echo "Extraction of SELinux / AppArmor status " | tee -a $SCRIPTFLOW
{
	echo "SELinux configuration (/etc/selinux/config):"
	if [ -f /etc/selinux/config ]; then cat /etc/selinux/config 2>> $ERRFILE; else echo "does not exist"; fi
	echo ""
	echo "getenforce:"
	if command -v getenforce >/dev/null 2>&1; then getenforce 2>> $ERRFILE; else echo "getenforce not found"; fi
	echo ""
	echo "sestatus:"
	if command -v sestatus >/dev/null 2>&1; then sestatus 2>> $ERRFILE; else echo "sestatus not found"; fi
	echo ""
	echo "AppArmor status (Debian/Ubuntu/SUSE):"
	if command -v aa-status >/dev/null 2>&1; then aa-status 2>> $ERRFILE; else echo "aa-status not found"; fi
} > selinux_apparmor_status.txt
echo "Extraction completed. Output file is \"selinux_apparmor_status.txt\" " | tee -a $SCRIPTFLOW

#####47 IPv6 status
echo "Extraction of IPv6 status " | tee -a $SCRIPTFLOW
{
	echo "/etc/sysconfig/network (NETWORKING_IPV6 / IPV6INIT):"
	if [ -f /etc/sysconfig/network ]; then cat /etc/sysconfig/network 2>> $ERRFILE; else echo "does not exist"; fi
	echo ""
	echo "sysctl IPv6 disable settings:"
	if command -v sysctl >/dev/null 2>&1; then
		sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 2>> $ERRFILE
	else
		echo "sysctl not found"
	fi
	echo ""
	echo "IPv6 addresses currently configured:"
	if command -v ip >/dev/null 2>&1; then ip -6 addr 2>> $ERRFILE; else echo "ip command not found"; fi
} > ipv6_status.txt
echo "Extraction completed. Output file is \"ipv6_status.txt\" " | tee -a $SCRIPTFLOW

#####48 User activity monitoring (psacct/acct, last, lastlog, lastb)
echo "Extraction of user activity monitoring data " | tee -a $SCRIPTFLOW
{
	echo "psacct / acct service status:"
	if command -v systemctl >/dev/null 2>&1; then
		systemctl status psacct.service acct.service --no-pager 2>> $ERRFILE
	fi
	if command -v chkconfig >/dev/null 2>&1; then
		chkconfig --list 2>> $ERRFILE | grep -Ei "psacct|acct" 2>> $ERRFILE
	fi
	echo ""
	echo "Login history (last -Fa, capped):"
	if command -v last >/dev/null 2>&1; then last -Fa 2>> $ERRFILE | head -n 200; else echo "last not found"; fi
	echo ""
	echo "Last login per user (lastlog):"
	if command -v lastlog >/dev/null 2>&1; then lastlog 2>> $ERRFILE; else echo "lastlog not found"; fi
	echo ""
	echo "Failed login attempts (lastb, capped):"
	if command -v lastb >/dev/null 2>&1; then lastb 2>> $ERRFILE | head -n 200; else echo "lastb not found"; fi
} > user_activity.txt
echo "Extraction completed. Output file is \"user_activity.txt\" " | tee -a $SCRIPTFLOW

#####49 Time statistics of users (ac)
echo "Extraction of user connect-time statistics (ac) " | tee -a $SCRIPTFLOW
{
	if command -v ac >/dev/null 2>&1; then
		echo "Total connect time (ac):"
		ac 2>> $ERRFILE
		echo ""
		echo "Connect time by day (ac -d):"
		ac -d 2>> $ERRFILE
		echo ""
		echo "Connect time per user (ac -p):"
		ac -p 2>> $ERRFILE
	else
		echo "ac command not found (acct/psacct package not installed)"
	fi
} > user_time_stats.txt
echo "Extraction completed. Output file is \"user_time_stats.txt\" " | tee -a $SCRIPTFLOW

#####50 Password reuse / history configuration
echo "Extraction of password reuse / history configuration " | tee -a $SCRIPTFLOW
> password_history.txt
for FILE in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth
do
	if [ -f "$FILE" ]; then
		echo "$FILE:" >> password_history.txt
		cat "$FILE" >> password_history.txt 2>> $ERRFILE
		echo "" >> password_history.txt
	else
		echo "$FILE does not exist " >> $ERRFILE
	fi
done
{
	echo "Old-password store (/etc/security/opasswd) presence & permissions:"
	if [ -f /etc/security/opasswd ]; then
		ls -la /etc/security/opasswd 2>> $ERRFILE
		echo "(content not extracted: contains password hashes)"
	else
		echo "/etc/security/opasswd does not exist"
	fi
	echo ""
	echo "Lines containing 'remember=' (password reuse limit):"
	grep -RHi "remember=" /etc/pam.d 2>> $ERRFILE
} >> password_history.txt
echo "Extraction completed. Output file is \"password_history.txt\" " | tee -a $SCRIPTFLOW

#####51 Password expiration (chage) and account lock/unlock status
echo "Extraction of password expiry (chage) and account lock status " | tee -a $SCRIPTFLOW
> password_aging_lock.txt
echo "===== Per-user password expiry (chage -l) =====" >> password_aging_lock.txt
if command -v chage >/dev/null 2>&1; then
	while read line
	do
		uname=`echo $line | cut -d: -f1`
		echo "--- $uname ---" >> password_aging_lock.txt
		chage -l "$uname" >> password_aging_lock.txt 2>> $ERRFILE
	done < /etc/passwd
else
	echo "chage command not found" >> password_aging_lock.txt
fi
echo "" >> password_aging_lock.txt
echo "===== Account lock/unlock status (passwd -Sa) =====" >> password_aging_lock.txt
if command -v passwd >/dev/null 2>&1; then
	passwd -Sa >> password_aging_lock.txt 2>> $ERRFILE
else
	echo "passwd command not found" >> password_aging_lock.txt
fi
echo "Extraction completed. Output file is \"password_aging_lock.txt\" " | tee -a $SCRIPTFLOW

#####52 Accounts with empty passwords
echo "Extraction of empty-password account check " | tee -a $SCRIPTFLOW
{
	echo "Accounts with empty password field in /etc/shadow:"
	if [ -f /etc/shadow ]; then
		awk -F: '($2==""){print $1}' /etc/shadow 2>> $ERRFILE
		echo "(blank above = none found)"
	else
		echo "/etc/shadow does not exist"
	fi
	echo ""
	echo "Accounts with empty password field in /etc/passwd:"
	if [ -f /etc/passwd ]; then
		awk -F: '($2==""){print $1}' /etc/passwd 2>> $ERRFILE
	fi
} > empty_passwords.txt
echo "Extraction completed. Output file is \"empty_passwords.txt\" " | tee -a $SCRIPTFLOW

#####53 Password strength (PAM pwquality / cracklib)
echo "Extraction of password strength configuration " | tee -a $SCRIPTFLOW
> password_strength.txt
for FILE in /etc/security/pwquality.conf /etc/pam.d/system-auth /etc/pam.d/common-password
do
	if [ -f "$FILE" ]; then
		echo "$FILE:" >> password_strength.txt
		cat "$FILE" >> password_strength.txt 2>> $ERRFILE
		echo "" >> password_strength.txt
	else
		echo "$FILE does not exist " >> $ERRFILE
	fi
done
if [ -d /etc/security/pwquality.conf.d ]; then
	echo "/etc/security/pwquality.conf.d listing:" >> password_strength.txt
	ls -la /etc/security/pwquality.conf.d >> password_strength.txt 2>> $ERRFILE
fi
echo "pam_pwquality / pam_cracklib references:" >> password_strength.txt
grep -RHi -E "pam_pwquality|pam_cracklib" /etc/pam.d >> password_strength.txt 2>> $ERRFILE
echo "Extraction completed. Output file is \"password_strength.txt\" " | tee -a $SCRIPTFLOW

#####54 Firewall status (iptables / ip6tables / firewalld / nftables)
echo "Extraction of firewall configuration " | tee -a $SCRIPTFLOW
{
	echo "===== iptables (IPv4) =====" 
	if command -v iptables >/dev/null 2>&1; then iptables -L -n -v 2>> $ERRFILE; else echo "iptables not found"; fi
	echo ""
	echo "===== ip6tables (IPv6) =====" 
	if command -v ip6tables >/dev/null 2>&1; then ip6tables -L -n -v 2>> $ERRFILE; else echo "ip6tables not found"; fi
	echo ""
	echo "===== firewalld =====" 
	if command -v firewall-cmd >/dev/null 2>&1; then
		firewall-cmd --state 2>> $ERRFILE
		firewall-cmd --list-all-zones 2>> $ERRFILE
	else
		echo "firewall-cmd not found"
	fi
	echo ""
	echo "===== nftables =====" 
	if command -v nft >/dev/null 2>&1; then nft list ruleset 2>> $ERRFILE; else echo "nft not found"; fi
	echo ""
	echo "===== ufw (Debian/Ubuntu) =====" 
	if command -v ufw >/dev/null 2>&1; then ufw status verbose 2>> $ERRFILE; else echo "ufw not found"; fi
} > firewall_status.txt
echo "Extraction completed. Output file is \"firewall_status.txt\" " | tee -a $SCRIPTFLOW

#####55 ICMP / broadcast and kernel network hardening (sysctl)
echo "Extraction of sysctl / ICMP-broadcast hardening parameters " | tee -a $SCRIPTFLOW
{
	echo "/etc/sysctl.conf:"
	if [ -f /etc/sysctl.conf ]; then cat /etc/sysctl.conf 2>> $ERRFILE; else echo "does not exist"; fi
	echo ""
	echo "/etc/sysctl.d listing:"
	if [ -d /etc/sysctl.d ]; then ls -la /etc/sysctl.d 2>> $ERRFILE; fi
	echo ""
	echo "Live ICMP / network hardening values:"
	if command -v sysctl >/dev/null 2>&1; then
		sysctl net.ipv4.icmp_echo_ignore_all net.ipv4.icmp_echo_ignore_broadcasts \
			net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.accept_redirects \
			net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter 2>> $ERRFILE
	else
		echo "sysctl not found"
	fi
} > sysctl_hardening.txt
echo "Extraction completed. Output file is \"sysctl_hardening.txt\" " | tee -a $SCRIPTFLOW

#####56 NTP / chrony time synchronization
echo "Extraction of NTP / chrony time synchronization status " | tee -a $SCRIPTFLOW
{
	echo "===== ntp.conf =====" 
	if [ -f /etc/ntp.conf ]; then cat /etc/ntp.conf 2>> $ERRFILE; else echo "/etc/ntp.conf does not exist"; fi
	echo ""
	echo "===== chrony.conf =====" 
	for FILE in /etc/chrony.conf /etc/chrony/chrony.conf
	do
		if [ -f "$FILE" ]; then echo "$FILE:"; cat "$FILE" 2>> $ERRFILE; fi
	done
	echo ""
	echo "ntpd enabled at boot (chkconfig):"
	if command -v chkconfig >/dev/null 2>&1; then chkconfig --list ntpd 2>> $ERRFILE; fi
	echo ""
	echo "NTP peers (ntpq -p):"
	if command -v ntpq >/dev/null 2>&1; then ntpq -p 2>> $ERRFILE; else echo "ntpq not found"; fi
	echo ""
	echo "NTP sync status (ntpstat):"
	if command -v ntpstat >/dev/null 2>&1; then ntpstat 2>> $ERRFILE; echo "ntpstat exit status: $?"; else echo "ntpstat not found"; fi
	echo ""
	echo "chrony sources (chronyc sources):"
	if command -v chronyc >/dev/null 2>&1; then chronyc sources 2>> $ERRFILE; chronyc tracking 2>> $ERRFILE; else echo "chronyc not found"; fi
	echo ""
	echo "timedatectl:"
	if command -v timedatectl >/dev/null 2>&1; then timedatectl 2>> $ERRFILE; else echo "timedatectl not found"; fi
} > ntp_status.txt
echo "Extraction completed. Output file is \"ntp_status.txt\" " | tee -a $SCRIPTFLOW

#####57 Expanded log review (auth, kern, cron, mail, boot, mysqld, yum) + syslog config
echo "Extraction of expanded system log files " | tee -a $SCRIPTFLOW
> log_review_inventory.txt
for LOG in /var/log/auth.log /var/log/kern.log /var/log/cron.log /var/log/maillog /var/log/mail.log /var/log/boot.log /var/log/mysqld.log /var/log/dpkg.log
do
	if [ -f "$LOG" ]; then
		echo "$LOG present:" >> log_review_inventory.txt
		ls -la "$LOG" >> log_review_inventory.txt 2>> $ERRFILE
		# capture a bounded tail so the audit has recent evidence without huge files
		echo "--- last 200 lines of $LOG ---" >> log_review_inventory.txt
		tail -n 200 "$LOG" >> log_review_inventory.txt 2>> $ERRFILE
		echo "" >> log_review_inventory.txt
	else
		echo "$LOG does not exist " >> $ERRFILE
	fi
done
echo "Extraction completed. Output file is \"log_review_inventory.txt\" " | tee -a $SCRIPTFLOW

#####58 Logging daemon configuration (rsyslog / journald) + login records
echo "Extraction of logging daemon configuration " | tee -a $SCRIPTFLOW
> logging_config.txt
for FILE in /etc/rsyslog.conf /etc/systemd/journald.conf
do
	if [ -f "$FILE" ]; then
		echo "$FILE:" >> logging_config.txt
		cat "$FILE" >> logging_config.txt 2>> $ERRFILE
		echo "" >> logging_config.txt
	else
		echo "$FILE does not exist " >> $ERRFILE
	fi
done
if [ -d /etc/rsyslog.d ]; then
	echo "/etc/rsyslog.d listing:" >> logging_config.txt
	ls -la /etc/rsyslog.d >> logging_config.txt 2>> $ERRFILE
	for FILE in /etc/rsyslog.d/*
	do
		if [ -f "$FILE" ]; then echo "$FILE:" >> logging_config.txt; cat "$FILE" >> logging_config.txt 2>> $ERRFILE; echo "" >> logging_config.txt; fi
	done
fi
{
	echo "Login records summary (wtmp via last, capped):"
	if command -v last >/dev/null 2>&1; then last -n 100 2>> $ERRFILE; else echo "last not found"; fi
} >> logging_config.txt
echo "Extraction completed. Output file is \"logging_config.txt\" " | tee -a $SCRIPTFLOW

##### Listing of .txt files and their number of lines 
echo "FileName Nvarchar(max)|^|RecordCount NUMERIC"  > ACTT_CONFIG_RECORDCOUNT.actt
for i in `ls *.txt`
do
LINES=`awk 'END{print NR}' $i`
echo "$i|^|$LINES" >> ACTT_CONFIG_RECORDCOUNT.actt 
done
echo "Extraction Script End Time|^|`date +\"%D %I:%M:%S %p\"`" >> ACTT_CONFIG_SETTINGS.actt

##### Code to move  all the generated files to a folder and then to archive

tar -cf $TARFILE *
#compress $TARFILE
cp $TARFILE ./..
chmod 777 *
cd ..

##### Cleaning up the temp files and/or directories created within the script
rm -r ./$FOLDER
opt='n'
done
