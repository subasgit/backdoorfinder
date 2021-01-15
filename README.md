<table align="center"><tr><td align="center" width="9999">
<align="center" width="150">

# Backdoorfinder
</td></tr></table>

### What is Backdoorfinder?

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
If you have api key generated from APIVOID or want to store the output file to a different location, then please run the following command and input
the details before running the tool
 
```
python3 configure.py
```
### Why we need this?   
#### Identify processes that exposes TCP/UDP ports for network attacks

function  : processes_**e**xposed_**n**etwork_**a**ttack
```
python3 generate_backdoor_report.py -ena
```
This function identifies processes and ports that are actively listening in and transferring bytes out to the network
Very often Malware listens on port to provide command and control (C&C) or direct shell access for an attacker. If you happen to see a process listening on port 0, it means applications requesting an operating system to find a dynamic port number range to connect. Most of the network traffic connecting to local hosts listening on port 0 are not bad, but network attackers or incorrectly programmed applications can use those ports to connect to. When your hosts respond to this message, it will help attackers to learn the behaviour and potential vulnerabilities of your laptop.

These processes and ports are written in CSV file with details on CPU, memory, traffic in and out of the hosts in  process_exposed_network_attack.csv
 

#### Identify processes that establishes suspicious outbound network activity

function  :  **s**uspicious_**p**rocess_to_**u**nknown_ports
```
python3 generate_backdoor_report.py -spu
```
This process identifies the malicious score of the  remote IP address connected and monitors CPU,memory and outbound network traffic from these processes.

Credibility of remote addresses  can be checked for maliciousness through threat analysis engines like APIVOID. Along with credibility check, remote IPs country, ISP hosting it and anonymity details like whether it is a Web proxy, VPN address or its Tor network  can be also checked.This is an optional feature to check if a remote IP address is malicious. Details on how to get API keys from APIVOID are listed in the Download and Install section. If the api key is not provided, then more details on the remote IP address will not be available.

We can also check if more CPU and Memory used by the process or more disk bytes read and written  from the process or if network traffic originated in and out the process. The more important piece here is the network traffic originated out of the process. There could be legitimate processes transferring bytes out to the network. Incase you see suspiciously more traffic that you know if not expected out of that process, then you might want to check on that process
These output is written in CSV file along with the time the script is executed in suspicious_process_to_unknown_ports.csv

This function ignores traffic connected to port 80 and 443.This doesn't mean that traffic through those ports are always safe. Unless we have a secondary check to verify if the process is safe to connect to port 80 and 443, it will be too noisy with  browsing traffic. So for now checking if processes establishing traffic to port 80 and 443  is not  in the scope of this tool.

#### Identify malicious processes which is running with its binary deleted

function : processes_running_**b**inary_**d**eleted
```
python3 generate_backdoor_report.py -bd
```
This function looks for a malicious process running with its original binary file deleted on the disk. 

Frequently, attackers will leave a malicious process running but delete the original binary on disk. This query returns any process whose original binary has been deleted, which could be an indicator of a suspicious process.This also checks for cpu, memory used by this process,how many bytes are read/written on the disk and also if there is active outbound or inbound network traffic to these processes.

Output of this file is written in binary_deleted_process.csv. 

#### Identfify suspicious browser extensions for chrome

function : suspicious_**c**hrome_**e**xtensions
```
python3 generate_backdoor_report.py -ce
```

Browser extensions are an integral part of many users’ browsers.Few browser extensions require access to almost everything your browser sees. They can see sites visited, keystrokes, and even passwords. In addition, browser extensions come from many publishers from well known browser publishers to little-known third-party vendors. So it's hard to tell what’s a legitimately a useful extension. So not every browser extension is safe.
This function will list all chrome extensions which have a more wide open permission list that allows access to modify data copied and pasted into clipboard, allows access to all URLs, the sites visited and allows access to all cookies. This extensions which has permissions more than its supposed to have are in high risk category.
Extensions which are malicious could have been identified and removed from Chrome store but once it's downloaded in your laptop, it does what it intends to do. So this tool will identify and cross verify if the extensions are still legitimate.

These processes and ports are written in CSV file along with the time the script is executed in suspicious_chrome_extensions.csv

#### Identify file created/updated/deleted by connecting a external USB device

function :  find_**usb**_connected
```
python3 generate_backdoor_report.py -usb
```

This function identifies files that are copied to or from external USB device that is plugged to the endpoint.
This function is compatable only with Mac as of now and can provide a basic level of data loss protection.

File integrity monitoring (FIM) uses inotify (Linux) and FSEvents(Mac OS X) to monitor files and directories for changes. 
As files/directories are written, read and deleted, events are created. When USB is connected to macOS, it automatically mounts 
to /VOLUMES directory. Any changes to that directory is monitored by FIM. So any file copied or updated from USB devices are monitored and reported.

These files modified and its actions are written in files_written_in_USB.csv

#### Identify top 10 processes which has the largest resident memory

function : check_processes_**l**arge_resident_**mem**ory
```
python3 generate_backdoor_report.py -lmem
```

Resident memory is the memory occupied by a process in main memory. Ideally processes occupying large resident memory 
should be cross checked with known whitelisted process to see if any malicious processes are running in your system
This function also checks if the process transfer bytes in the network 

These processes along with details on CPU, memory, traffic in and out of the hosts are written in large_memory_resident_size_process.csv

#### Find applications versions to cross check for Vulnerability

function : **check**_**app**lication_versions
```
python3 generate_backdoor_report.py -checkapp
```
This function lists all application running on the endpoint along with its version. This could be used to check if your
application is vulnerable to any attacks

These application and version output are written in application_and_versions.csv

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

### 


