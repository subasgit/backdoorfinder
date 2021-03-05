# Backdoorfinder

![Twitter](https://img.shields.io/twitter/url?url=https%3A%2F%2Fgithub.com%2Fsubasgit%2Fbackdoorfinder)


## Getting Started
This is a tool to find potential backdoor/security holes in your endpoint(laptop/desktop/server). These instructions will help you install and run in your local system. This is primarily tested on macOS but supported on Ubuntu and Windows too.

### Prerequisites:

Requires Python3, Osquery. Osquery exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

Step 1 : Install Python according to your OS
	
Step 2 : Install osquery https://osquery.io/downloads/ according to your OS 

Step 3: Copy all the source code using git clone
Git clone https://github.com/subasgit/backdoorfinder.git 

Step 4: Run requirements.txt file to install the dependencies pip3 install -r requirements.txt
        If windows run, pip3 install -r requirements_for_windows.txt

Step 5:(Optional)Some functions have options to check Threat intelligence for the maliciousness of the remote IP address. 
I integrated with APIVOID and Virustotal to perform that lookup. If you prefer not to use that, then you don't need to do this step

How to get API VOID API Key? https://www.apivoid.com/api/ip-reputation/
Click Register Now and obtain APIKey. Initially you get 25 free API credits. Please review the pricing details.

How to get VirusTotal Key? https://www.virustotal.com/gui/join-us
Please read the restrictions of public api key and use it likewise
 
## Installation

Before running the scripts, run configure.py to configure the variables like api key,file path 
where you want to store the output files.
![ezgif-6-2f114f418fb7](https://user-images.githubusercontent.com/71156714/110165823-5640d800-7da8-11eb-98d1-8561eefa180c.gif)

 	
```
python3 configure.py
```

## Usage 
Now you are all set! You can run the whole script or run only specific functions you are interested in

![Scriptflow](https://user-images.githubusercontent.com/71156714/110165669-1b3ea480-7da8-11eb-8f2d-17f0e9d4a7cd.jpeg)

To explore the options to run
```
python3 generate_backdoor_report.py -h
```
You can run all functions by 

```
python3 generate_backdoor_report.py
``` 

Each of the functions will create CSV and JSON files. 

If interested in any specific functions, you can run that function alone 

Identify processes exposed to network attack -> Writes to process_exposed_network_attack.csv

```
python3 generate_backdoor_report.py -ena
```

Identify suspicious process to unknown_ports -> Writes to suspicious_process_to_unknown_ports.csv

```
python3 generate_backdoor_report.py -spu
```

Identify malicious process running with binary deleted -> Writes to binary_deleted_process.csv

```
python3 generate_backdoor_report.py -bd
```

Identify Suspicious Chrome extensions -> Writes to suspicious_chrome_extensions.csv

```
python3 generate_backdoor_report.py -ce
```

Identify top 10 processes that has large resident memory -> Writes to large_memory_resident_size_process.csv

```
python3 generate_backdoor_report.py -lmem
```

Identify various applications running and its versions -> Writes to application_and_versions.csv

```
python3 generate_backdoor_report.py -appcheck
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

    
### Identify processes exposed to network attack
 
This function identifies processes and ports that are actively listening in, its CPU, memory and whether its 
transferring bytes out in the network	
Very often Malware listens on port to provide command and control (C&C) or direct shell access for an attacker. 
This function will give us a fair idea on what processes in our laptops are actively listening in. Some applications
like Google chrome are expected to be connected to the servers that host the websites you're browsing right now. 
By just finding this process alone we can't be sure that this has any potential malicious intent. 
So I added additional checks to identify active network bytes in and out of the laptop or if any processes have high
CPU or memory utilization. This can potentially spot applications/processes that are not intended to transfer bytes
or having high cpu or memory usage.

The output of this function is written in a CSV format with details on CPU, memory, traffic in and out of the hosts. 


### Identify suspicious process to unknown_ports

This function identifies whether the remotely connected address of the processes is malicious.  If it's malicious, it 
can make your hosts/endpoints vulnerable for attacks. Additional checks on CPU, memory and network bytes transferred 
from this process also provides secondary validation

This function looks for processes with IP traffic to ports not in 80 and 443. Security teams can use this function to
identify processes that do not fit within expected whitelisted processes that usually establishes connection to 
unknown ports. Those processes could potentially be communicating with command and control center making your 
hosts/endpoint vulnerable for attacks.

Credibility of remote addresses can be checked by integration with threat intelligence api like APIVoid and VirusTotal. 
Along with credibility check, remote IPs country, ISP hosting it and anonymity details like whether it is a Web proxy, 
VPN address or its Tor network can be also checked. We need to register and get API keys to check if the connected 
remote IP address is malicious or not. Details on how to get API keys from APIVoid are listed in the 
Download and Install section. This is an optional feature, so if the api key is not provided, then more insights into
remote IP addresses will not be available.

We can also check the CPU,Memory, disk bytes read and written  from the process and also network traffic originated 
in and out the process. Apart from malicious checks of remote IP addresses , the other important piece here is the 
network traffic originated out of the process. There could be legitimate processes transferring bytes out to the 
network. In case you see suspiciously more traffic that is not expected out of a process or a connection, then you 
might want to check on that process.

This output is written in CSV format along with the time the script is executed
 

### Identify malicious process running with binary deleted

 This function looks for malicious process running with its original binary file deleted on the disk. Frequently 
attackers will run malicious processes like this. This also checks for memory used by this process and how much
bytes are read/written on the disk

These processes and ports are written in CSV file along with the time the script is executed 

### Identify Suspicious Chrome extensions

This command will list all chrome extensions which have a more wide open permission list that allows access to, 
modify data copied and pasted into clipboard,
all URLs visited
all cookies. 
These extensions which have more permissions than it is supposed to have are in a high risk category.
Browser extensions are an integral part of many users’ browsers. Few browser extensions require access to almost 
everything your browser sees. They can see sites visited, keystrokes, and even passwords. In addition, browser 
extensions come from many publishers from well known browser publishers to little-known third-party vendors. So it's 
hard to tell what’s a legitimately useful extension.

Oftentimes the extensions that are identified as malicious is removed from the Chrome store.  But once downloaded, 
the end user has no automatic way to know that the extensions are blacklisted and it's not available in the Chrome 
store anymore. So this tool will identify extensions that have wide open permissions and cross verify if the 
extensions are still legitimate.

Lot of times, we might not know that these extensions are installed in our laptop. This check could help you identify 
it and you can remove it if it’s not needed. You can run this often and add extensions that's not harmful in allow lists

These processes and ports are written in CSV file along with the time the script is executed 

### Identify top 10 processes that has large resident memory

Resident memory is the memory occupied by a process in main memory. Ideally processes occupying large resident memory 
should be cross checked with known whitelisted process to see if any malicious processes are running in your system
This function also checks if the process transfer bytes in the network 

### Identify various applications running and its versions

This function lists all application running on the endpoint along with its version. This could be used to check if your
application is vulnerable to any attacks

### Writing processes which are transferring bytes outbound -> to a CSV file
function : write_process_transfer_bytes_to_csv -> process_transferring_bytes.csv

This function will create a separate CSV file and write all process which is sending traffic out of the 
box. It will be empty if no such processes are found.There will be expected and known good processes which will genuinely send traffic out among some unknown processes.
But this subset will give a good idea on processes which have frequent outbound traffic flows.

### Writing processes which is connecting to remote suspicious IP address to a CSV file
function : write_malicious_remote_ip_to_csv -> process_connecting_to_suspicious_ip.csv

This function will create a separate CSV file when a process establishes connection to remote suspicious IP address.
This processes needs to be investigated and blocked.This csv file will be empty if no such processes are found


### Writing the process output to CSV file 

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

### Add configuration parameters like apikey and file paths

File : Configure.py

This python script needs to be if you have api key that you need to input or store the files in your locations. 
This is one time run to set your variables 

Function : get_api_key

This function will prompt the user to enter the api key if he has any. Input will be stored in configure.txt

Function : get_file_path

This function gives the flexibility to store the file at the location you intent to. Input will be stored in 
configure.txt If user dont have any preference of file path, file will be stored in the directory where the script 
is executed. 

### 


