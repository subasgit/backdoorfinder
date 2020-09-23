# backdoorfinder
## Tool to find potential backdoor/security holes in your endpoint

### Prerequisites:

Requires Python3, Osquery. 
osquery exposes an operating system as a high-performance relational database. 
This allows you to write SQL-based queries to explore operating system data. 
With osquery, SQL tables represent abstract concepts such as running processes, 
loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

Install Osquery
Based on your operating system, install osquery from  https://osquery.io/downloads/official/4.4.0

and to install osquery python module run the following:

```pip3 install osquery```

Alternatively, to install from this repo, run the following:
python setup.py build
python setup.py install

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