import os
import osquery
import requests
import time
from datetime import date
import ipaddress
import subprocess
import pandas


def processes_exposed_network_attack(hw_type):
    """Very often Malware listens on port to provide command and control (C&C) \
    or direct shell access for an attacker.Running this query periodically and diffing \
    with the last known good results will help the security team to identify malicious \
    running in any endpoints"""
    instance = osquery.SpawnInstance()
    instance.open()  # This may raise an exception
    process_list = []

    # Find processes that is listening on 0.0.0.0 and exposing ur network for attack
    result = instance.client.query("SELECT DISTINCT process.name, listening.port, process.pid FROM processes AS \
                                   process JOIN listening_ports AS listening ON process.pid = listening.pid WHERE \
                                   listening.address = '0.0.0.0'")
    response = result.response
    # Parse today's date and time
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    # List all that process
    for entry in response:
        process = {}
        process['date'] = d1
        process['current_time'] = current_time
        process['name'] = entry['name']
        process['port'] = entry['port']
        # Get the bytes read , written and memory used
        process['pid'] = entry['pid']
        process['memory'], process['disk_bytes_read'], process['disk_bytes_written'] = \
            check_processes_disksize(entry['pid'])
        process['cpu_usage'] = check_processes_cpu(entry['pid'])
        process_list.append(process)
    if "Apple" in hw_type:
        final_process_list = check_network_traffic(process_list)
    else:
        return process_list
    return final_process_list

def suspicious_process_to_unknown_ports(api_key):
    """ Lists processes with IP traffic to remote ports not in (80, 443) and this can potentially \
    identify suspicious outbound network activity. We can cross verify this external IP address \
    with API VOID if its connected to known malicious IP address and list only those process.\
    If no API key is available all processes that meets the above criteria will be listed"""
    instance = osquery.SpawnInstance()
    instance.open()
    # Query local host for processes established to port other than 80 and 443
    result_ip = instance.client.query(
        "select s.pid, p.name, local_address, remote_address, family, protocol, local_port, remote_port \
        from process_open_sockets s join processes p on s.pid = p.pid where remote_port not in (80, 443) \
        and remote_address != '127.0.0.1' and s.state = 'ESTABLISHED'")
    print(result_ip)
    process_list = []
    response = result_ip.response
    # Parse today's date and time
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    for entry in response:
        process = {}
        process['date'] = d1
        process['current_time'] = current_time
        process['name'] = entry['name']
        process['local_address'] = entry['local_address']
        process['local_port'] = entry['local_port']
        process['remote_address'] = entry['remote_address']
        process['remote_port'] = entry['remote_port']
        process['pid'] = entry['pid']
        print('Process {} has established connection from {} port {} to {} port {}'.format(entry['name'],
                                                                                           entry['local_address'],
                                                                                           entry['local_port'],
                                                                                           entry['remote_address'],
                                                                                           entry['remote_port']))

        # Check memory and CPU usage of each process
        process['memory'], process['disk_bytes_read'], process['disk_bytes_written'] = \
            check_processes_disksize(entry['pid'])
        process['cpu_usage'] = check_processes_cpu(entry['pid'])

        # Check whether the remote_address is a known malicious IP address if API Key is provided
        if api_key != 'none' and api_key != 'None':
            if not ipaddress.ip_address(entry['remote_address']).is_private:
                payload = {'key': api_key, 'ip': entry['remote_address']}
                r = requests.get(url='https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/', params=payload)
                print(r.json)
                if "error" not in r.json():
                    print(r.json())
                    output = r.json()
                    process['is_private'] = 'false'
                    process['detections'] = output['data']['report']['blacklists']['detections']
                    process['detection_rate'] = output['data']['report']['blacklists']['detection_rate']
                    process['country'] = output['data']['report']['information']['country_name']
                    process['isp'] = output['data']['report']['information']['isp']
                    process['is_proxy'] = output['data']['report']['anonymity']['is_proxy']
                    process['is_webproxy'] = output['data']['report']['anonymity']['is_webproxy']
                    process['is_vpn'] = output['data']['report']['anonymity']['is_vpn']
                    process['is_hosting'] = output['data']['report']['anonymity']['is_hosting']
                    process['is_tor'] = output['data']['report']['anonymity']['is_tor']
            else:
                process['is_private'] = 'true'
                process['detections'] = process['detection_rate'] = process['country'] = process['isp'] = \
                    process['is_proxy'] = process['is_webproxy'] = process['is_vpn'] = process['is_hosting'] = \
                    process['is_tor'] = "N\A"
        process_list.append(process)
    final_process_list = check_network_traffic(process_list)
    return final_process_list


def processes_running_binary_deleted():
    """Find processes running with binary deleted"""
    instance = osquery.SpawnInstance()
    instance.open()
    process_list = []
    # Parse today's date and time
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    # Find Processes whose binary has been deleted from the disk
    result_process = instance.client.query("SELECT name, path, pid FROM processes WHERE on_disk = 0")
    response = result_process.response
    for entry in response:
        process = {}
        print('{} is running without binary file'.format(entry['name']))
        process['date'] = d1
        process['current_time'] = current_time
        process['name'] = entry['name']
        process['pid'] = entry['pid']
        process['path'] = entry['path']
        process['memory'], process['disk_bytes_read'], process['disk_bytes_written'] = \
            check_processes_disksize(entry['pid'])
        process['cpu_usage'] = check_processes_cpu(entry['pid'])
        process_list.append(process)
    final_process_list = check_network_traffic(process_list)
    return final_process_list


def find_suspicious_chrome_extensions():
    """Detecting Chrome extensions which are at high risk"""
    instance = osquery.SpawnInstance()
    instance.open()
    process_list = []

    # Parse today's date and time
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    result_process = instance.client.query(
        "SELECT uid,name,identifier,permissions,optional_permissions from chrome_extensions WHERE \
        chrome_extensions.uid IN (SELECT uid FROM users) AND (permissions LIKE('%clipboardWrite%') \
        OR permissions LIKE ('%<all_urls>%') OR permissions LIKE ('%tabs%') \
        OR permissions LIKE ('%cookies%') OR permissions like ('%://*/%'))")
    response = result_process.response
    for entry in response:
        process = {}
        process['date'] = d1
        process['current_time'] = current_time
        process['name'] = entry['name']
        process['identifier'] = entry['identifier']
        url = "https://chrome.google.com/webstore/detail/{}".format(entry['identifier'])
        request = requests.get(url)
        if request.status_code == 200:
            print('Web site exists')
            process['is_website_exist'] = 'yes'
        else:
            print('Web site does not exist')
            process['is_website_exist'] = 'no'
        process['permissions'] = entry['permissions']
        process['optional_permissions'] = entry['optional_permissions']
        process_list.append(process)
    return process_list


def find_usb_connected():
    """Find USB connected to the endpoint and new files created/modified/deleted"""
    instance = osquery.SpawnInstance()
    instance.open()
    process_list = []
    # Parse today's date and time
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    result_process = instance.client.query("SELECT action, uid, SUBSTR(target_path, 18) AS path, \
                                            SUBSTR(md5, 0, 8) AS hash, time FROM file_events WHERE sha1 <> '' \
                                            AND target_path NOT LIKE '%DS_Store'")
    response = result_process.response
    for entry in response:
        process = {}
        process['date'] = d1
        process['current_time'] = current_time
        process['name'] = entry['target_path']
        process['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry['time']))
        process['action'] = entry['action']
        process['filepath'] = entry['path']
        process_list.append(process)
    return process_list


def check_processes_large_resident_memory():
    """Find Processes that has the largest resident memory"""
    instance = osquery.SpawnInstance()
    instance.open()
    process_list = []
    # Parse today's date and time
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    # Find Processes which has the largest resident memory
    result_process = instance.client.query("select pid, name, uid, resident_size from processes \
                                            order by resident_size desc limit 10")
    response = result_process.response
    for entry in response:
        process = {}
        process['date'] = d1
        process['current_time'] = current_time
        process['name'] = entry['name']
        process['pid'] = entry['pid']
        process['resident_size'] = entry['resident_size']
        process_list.append(process)
    final_process_list = check_network_traffic(process_list)
    return final_process_list


def check_application_versions():
    instance = osquery.SpawnInstance()
    instance.open()
    process_list = []
    # Parse today's date and time
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    # Find Processes which has the largest resident memory
    result_process = instance.client.query("select name,bundle_version,\
                        category from apps")
    response = result_process.response
    for entry in response:
        for entry in response:
            process = {}
            process['date'] = d1
            process['current_time'] = current_time
            process['name'] = entry['name']
            process['bundle_version'] = entry['bundle_version']
            process['category'] = entry['category']
            process_list.append(process)
    return process_list

def check_processes_disksize(pid):
    """Find the disk read and write by a process"""
    instance = osquery.SpawnInstance()
    instance.open()
    result = instance.client.query("select resident_size,disk_bytes_read,disk_bytes_written from processes \
            where pid='%s'" % pid)
    response = result.response
    for entry in response:
        return [entry['resident_size'], entry['disk_bytes_read'], entry['disk_bytes_written']]


def check_processes_cpu(pid):
    """Find the CPU utilized by the process"""
    instance = osquery.SpawnInstance()
    instance.open()
    result = instance.client.query("SELECT pid, uid, name, \
    ROUND(((user_time + system_time) / (cpu_time.tsb - cpu_time.itsb)) * 100, 2)\
    AS percentage FROM processes, (SELECT (SUM(user) + SUM(nice) + SUM(system) + SUM(idle) * 1.0) \
    AS tsb,SUM(COALESCE(idle, 0)) + SUM(COALESCE(iowait, 0)) AS itsb FROM cpu_time) AS cpu_time where\
                                   pid='%s'" % pid)
    response = result.response
    for entry in response:
        return entry['percentage'] + '%'


def check_network_traffic(process_list):
    """ Checks network traffic in and out of the process"""
    cmd = 'nettop -L 5'
    output = subprocess.check_output(cmd, shell=True)
    final_output = output.decode("utf-8")
    nettop_entries = final_output.split('\n')
    export_process_list = process_list[:]
    for process in process_list:
        cmd1 = process['name'] + "." + process['pid']
        match_list = [x for x in nettop_entries if cmd1 in x]
        first_line = match_list[0].split(',')
        fifth_line = match_list[4].split(',')
        process['traffic_in_bytes'] = (int(fifth_line[4]) - int(first_line[4])) / 5
        process['traffic_out_bytes'] = (int(fifth_line[5]) - int(first_line[5])) / 5
        export_process_list.append(process)
    return export_process_list


def convert_to_csv(file_name, parameters):
    """Writes the parameters parsed to CSV file """
    if not bool(parameters):
        return 0
    if not os.path.exists(file_name):
        with open(file_name, 'a+', newline='') as write_obj:
            # Find the longest header file and select the headers for csv
            length = 0
            for param in parameters:
                new_length = len(param)
                if new_length > length:
                    length = new_length
                    final_list = param
            # Adding header in the csv file
            # Adding the number of iteration
            write_obj.write('iteration')
            for key in final_list:
                write_obj.write("," + key)
            write_obj.write("\n")

    # Find the last line in CSV file and increase the iteration number for further run
    with open(file_name, "r") as f1:
        last_line = f1.readlines()[-1]
        first_item = last_line.split(',')[0]
        if 'iteration' in first_item:
            iteration_value = 1
        else:
            iteration_value = int(first_item) + 1

    with open(file_name, 'a+', newline='') as write_obj:
        # Adding entries
        for process in parameters:
            # Append Iteration value
            write_obj.write(str(iteration_value))
            for key, value in process.items():
                write_obj.write("," + str(value))
            write_obj.write("\n")


def convert_csv_to_json(csv_file_path):
    """Converts CSV to json file"""
    df = pandas.read_csv(csv_file_path)
    json_file = csv_file_path.strip('.csv')+".json"
    df.to_json(json_file, orient='records')