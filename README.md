<table align="center"><tr><td align="center" width="9999">
<align="center" width="150">

# Backdoorfinder
</td></tr></table>

## What is Backdoorfinder?

Cybercriminals commonly find endpoints exposed to network attacks to install backdoors by taking advantage of vulnerable components. Once installed, detection is difficult as files tend to be highly obfuscated.Once an attacker has access to a system through a backdoor, they can potentially modify files, steal personal information, install unwanted software, and even take control of the entire computer. 

Backdoorfinder is a tool that can be used to identify potential ports and processes that are vulnerable for attacks.

This tool identifies
1) Processes that are exposed for network attack
2) Processes that establishes suspicious outbound network activity
3) Suspicious chrome extensions
4) Processes which has no binary
5) Identify if USB devices are connected and any file is created/updated/deleted
6) Top 10 processes which has the largest resident memory
7) Identify applications running on your endpoint along with the versions

### Download and Install:

Requires Python3, Osquery. Osquery exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

Step 1 : Install Python according to your OS
	
Step 2 : Install osquery https://osquery.io/downloads/ according to your OS 

Step 3: Copy all the source code using git clone
Git clone https://github.com/subasgit/backdoorfinder.git 

Step 4: Run requirements.txt file to install the dependencies pip3 install -r requirements.txt

Step 5:(Optional)Some functions have options to check Threat intelligence for the maliciousness of the remote IP address. I integrated with APIVOID to perform that lookup. If you prefer not to use that, then you don't need to do this step

How to get API VOID API Key? https://www.apivoid.com/api/ip-reputation/
Click Register Now and obtain APIKey. Initially you get 25 free API credits. Please review the pricing details.

 
### How to run the script

Before running the scripts, run configure.py to configure the variables like api key,file path 
where you want to store the output files and OS you are running the script on
 
```
python3 configure.py
```
 To run the entire script  
```
python3 generate_backdoor_report.py
```
To explore the options
```
python3 generate_backdoor_report.py -h
```
If you want to continuously run in your endpoint, you can specify the duration and freq of the run. 
For example, if you want to run the script every 5 mins for 1 hr then, run
```
python3 generate_backdoor_report.py -duration 60 -freq 5
```
or you can run specific functions like 
```
python3 generate_backdoor_report.py -spu -duration 60 -freq 5
```
    
### Identify processes that exposes TCP/UDP ports for network attacks

function  : processes_exposed_network_attack
```
python3 generate_backdoor_report.py -ena
```
Very often Malware listens on port to provide command and control (C&C) or direct shell access for an attacker.
Running this query periodically and diffing with the last known good results will help the security team to identify 
malicious processes running in any endpoints.

If you happen to see process listening on port 0, it means applications requesting operation system to find a dynamic 
port number range to connect. Network traffic from the internet to local hosts listening on port 0 might be generated 
by network attackers or incorrectly programmed applications. When your hosts responds to this message, it will help 
attackers to learn the behaviour and potential vulnerabilities of your hosts/endpoint.

These processes and ports are written in CSV file along with the time the script is executed in process_exposed_network_attack.csv

### Identify processes that establishes suspicious outbound network activity

function  :  suspicious_process_to_unknown_ports
```
python3 generate_backdoor_report.py -spu
```
This function looks for processes with IP traffic to ports not in 80 and 443. Security teams can use this function to
identify processes that do not fit within expected whitelisted processes that usually establishes connection to 
unknown ports. Those processes could potentially be communicating with command and control center making your 
hosts/endpoint vulnerable for attacks.

We can cross verify the credibility score of the external IP address that the processes establishes 
connection with API VOID lookup.Along with the detection rate, all the details of external IP are also returned and 
written in CSV file.This involves key information like detection rate, country, ISP hosting it and anonymity details 
like whether it a Web proxy, VPN address or its a tor network.

If you don't have the API key then please enter none and we list all potentially suspicious 
processes running in your hosts/endpoint. 

These processes and ports are written in CSV file along with the time the script is executed in suspicious_process_to_unknown_ports.csv
 
Scope: I'll add support for VirusTotal lookup as well at later point.

### Identify malicious processes which is running with its binary deleted

function : processes_running_binary_deleted
```
python3 generate_backdoor_report.py -bd
```

This function looks for malicious process running with its original binary file deleted on the disk. Frequently 
attackers will run malicious processes like this. This also checks for memory used by this process and how much
bytes are read/written on the disk

These processes and ports are written in CSV file along with the time the script is executed in binary_deleted_process.csv

### Identfify suspicious browser extensions for chrome

function : suspicious_chrome_extensions
```
python3 generate_backdoor_report.py -ce
```

This function looks for suspicious browser extensions that allows access to modify data copied and pasted into 
clipboard, allows access to all URL the endpoint visited and allows to access all cookies. This extensions which
has permissions more than its supposed to have are in high risk category. Google periodically identifies
suspicious chrome extensions and removes it.But once installed in the endpoint, it can silently listen to all activities
So running this function will cross check if the extensions are still legitimate and gets served in chrome
web store.

These processes and ports are written in CSV file along with the time the script is executed in suspicious_chrome_extensions.csv

### Identify file created/updated/deleted by connecting a external USB device

function :  find_usb_connected
```
python3 generate_backdoor_report.py -usb
```

This function identifies files that are copied to or from external USB device that is plugged to the endpoint using 
File Integrity monitor(FIM).This function is compatable only with Mac as of now and can provide a
basic level of data loss protection.file integrity monitoring (FIM) uses inotify (Linux) and FSEvents(Mac OS X) 
to monitor files and directories for changes. As files/directories are written, read and deleted, 
events are created. When USB is connected to macOS, it automatically mounts to /VOLUMES directory. Any changes 
to that directory is monitored by FIM. This actions are captured along with disk_events and mounts table
to identify the files that's copied/updated from USB device.

These processes and ports are written in CSV file along with the time the script is executed in files_written_in_USB.csv

### Identify top 10 processes which has the largest resident memory

function : check_processes_large_resident_memory
```
python3 generate_backdoor_report.py -lmem
```

Resident memory is the memory occupied by a process in main memory. Ideally processes occupying large resident memory 
should be cross checked with known whitelisted process to see if any malicious processes are running in your system
This function also checks if the process transfer bytes in the network 

These processes and ports are written in CSV file along with the time the script is executed in large_memory_resident_size_process.csv

### Find applications versions to cross check for Vulnerability

function : check_application_versions
```
python3 generate_backdoor_report.py -appcheck
```
This function lists all application running on the endpoint along with its version. This could be used to check if your
application is vulnerable to any attacks

These processes and ports are written in CSV file along with the time the script is executed in application_and_versions.csv

### Writing the process output to csv file 

function: convert_to_csv

This function will create new csv file for every procedure that calls this. We need to send the file name and parameters
to write to the file as part of the arguments.

If this is the first time this script is run, it will create new file under the directory where you execute this
script and populate the parameters that is passed on to it. If the file exists, then new parameters are appended on
to the csv file. Each time this function is called by a procedure, it appends with iteration number. This will help in
filtering the latest runs

### Writing the process output in json format

function: convert_csv_to_json

This function will create a json file from the CSV file. Supporting different formats to enhance the
flexibility to integrate with other applications


### Checks disk bytes written and read by the process

function: check_processes_disksize

This function can be used to check disk bytes written and read at any point of time. This would add value to see if system 
resources are consumed heavily by any process.

### Checks CPU utilized by a process

function: check_processes_cpu

This function returns the CPU utilized by a process. This could potentially identify if established process is using
lot of CPU

### Check network traffic read and written by the process

function: check_network_traffic

This function could be used by any main functions to parse the network traffic used by specific process. Any process
which is actively sending traffic out or receiving traffic can be identified with this function. This function can be 
used only if endpoint is mac.

### Add configuration parameters like apikey, file paths and OS type

File : Configure.py

This python script needs to be run first to collect neccessary information to run your generate_backdoor_report.py. 
This is one time run to set your variables 

Function : get_api_key

This function will prompt the user to enter the api key if he has any. Input will be stored in configure.txt

Function : get_file_path

This function gives the flexibility to store the file at the location you intent to. Input will be stored in 
configure.txt If user dont have any preference of file path, file will be stored in the directory where the script 
is executed. 

Function : check_hardware_vendor

This function is to get the OS running. There are few commands which are OS specific, so its important to identify the OS

### 


