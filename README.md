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

pip install osquery

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



