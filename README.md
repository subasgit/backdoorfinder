# backdoorfinder
## Tool to find potential backdoor/security holes in your endpoint

### Prerequisites:

Requires Python3, Osquery. 
osquery exposes an operating system as a high-performance relational database. 
This allows you to write SQL-based queries to explore operating system data. 
With osquery, SQL tables represent abstract concepts such as running processes, 
loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.
 
### How to run the script

Run requirements.txt file to install the dependencies
    pip3 install -r requirements.txt
    
Before running the scripts, run configure.py to configure the variables like apikey and filepath
    python3 configure.py

Run the main script now.
If you want to run all functions of backdoor one time, you can just run 
    python3 generate_backdoor_report.py 

To run specific functions, you can do python3 generate_backdoor_report.py -h to check options to run specific functions
    delay : You can specify delay between the runs in seconds. This can be used in combination with other options as well.
    freq  : Specify the time you need to run the script in minutes. For example, you can run the script every 5 mins 
            for 1 hr by specifying the option like -delay 300 -freq 60 
    ena   : Find processes exposed to network attack
    spu   : Find suspicious process to unknown_ports
    bd    : Find malicious process running with binary deleted
    
    
### Finding processes that exposes TCP/UDP ports for network attacks

function  : processes_exposed_network_attack

Very often Malware listens on port to provide command and control (C&C) or direct shell access for an attacker.
Running this query periodically and diffing with the last known good results will help the security team to identify 
malicious processes running in any endpoints.

If you happen to see process listening on port 0, it means applications requesting operation system to find a dynamic 
port number range to connect. Network traffic from the internet to local hosts listening on port 0 might be generated 
by network attackers or incorrectly programmed applications. When your hosts responds to this message, it will help 
attackers to learn the behaviour and potential vulnerabilities of your hosts/endpoint.

These processes and ports are written in CSV file along with the time the script is executed

### Finding processes that establishes suspicious outbound network activity

function  :  suspicious_process_to_unknown_ports

This function looks for processes with IP traffic to ports not in 80 and 443. Security teams can use this function to
identify processes that do not fit within expected whitelisted processes that usually establishes connection to 
unknown ports. Those processes could potentially be communicating with command and control center making your 
hosts/endpoint vulnerable for attacks.

We can cross verify the credibility score of the external IP address that the processes establishes 
connection with API VOID lookup.Along with the detection rate, all the details of external IP are also returned and 
written in CSV file.This involves key information like detection rate, country, ISP hosting it and anonymity details 
like whether it a Web proxy, VPN address or its a tor network.

If you don't have the API key then please enter none and we list all potentially suspicious 
processes running in your hosts/endpoint. The processes written in CSV can be tracked based on the date and time the 
script is executed.


How to get API VOID API Key?
https://www.apivoid.com/api/ip-reputation/ 

Click Register Now and obtain APIKey. Initially you get 25 free API credits. Please review the pricing details.

Scope: I'll add support for VirusTotal lookup as well at later point.

### Finding malicious processes which is running with its binary deleted

function : processes_running_binary_deleted

This function looks for malicious process running with its original binary file deleted on the disk. Frequently 
attackers will run malicious processes like this. This also checks for memory used by this process and how much
bytes are read/written on the disk

These processes and ports are written in CSV file along with the time the script is executed 

### Writing the process output to csv file 

function: convert_to_csv

This function will create new csv file for every procedure that calls this. We need to send the file name and parameters
to write to the file as part of the arguments.

If this is the first time this script is run, it will create new file under the directory where you execute this
script and populate the parameters that is passed on to it. If the file exists, then new parameters are appended on
to the csv file. Each time this function is called by a procedure, it appends with iteration number. This will help in
filtering the latest runs

### Checks memory and bytes written and read by the process

function: check_processes_memory

This function can be used to check process memory, bytes written and read. This would add value to see if system 
resources are consumed heavily by any process.

### Check network traffic read and written by the process
function: check_network_traffic

This function could be used by any main functions to parse the network traffic used by specific process. Any process
which is actively sending traffic out or receiving traffic can be identified with this function. This function can be 
used only if endpoint is mac.

### Add configuration parameters like apikey and file paths

File : Configure.py

This python script needs to be run first to collect neccessary information to run your generate_backdoor_report.py. 
This is one time run to set your variables 

Function : get_api_key

This function will prompt the user to enter the api key if he has any. Input will be stored in configure.txt

Function : get_file_path

This function gives the flexibility to store the file at the location you intent to. Input will be stored in 
configure.txt If user dont have any preference of file path, file will be stored in the directory where the script 
is executed. 




