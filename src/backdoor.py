import os
import osquery
import requests
import time
from datetime import date
import ipaddress
import subprocess
import pandas
import json


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
        return final_process_list
    else:
        return process_list


def suspicious_process_to_unknown_ports(hw_type, api_key, api_key_type):
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
        # Check memory and CPU usage of each process
        process['memory'], process['disk_bytes_read'], process['disk_bytes_written'] = \
            check_processes_disksize(entry['pid'])
        process['cpu_usage'] = check_processes_cpu(entry['pid'])
        process_list.append(process)
    # Check whether the remote_address is a known malicious IP address if API Key is provided
    if 'none' not in api_key:
        if 'apivoid' in api_key_type:
            process_list = check_apivoid(api_key, process_list)
        else:
            process_list = check_vt(api_key, process_list)

    if "Apple" in hw_type:
        final_process_list = check_network_traffic(process_list)
        return final_process_list
    else:
        return process_list


def processes_running_binary_deleted(hw_type):
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
        process['date'] = d1
        process['current_time'] = current_time
        process['name'] = entry['name']
        process['pid'] = entry['pid']
        process['path'] = entry['path']
        process['memory'], process['disk_bytes_read'], process['disk_bytes_written'] = \
            check_processes_disksize(entry['pid'])
        process['cpu_usage'] = check_processes_cpu(entry['pid'])
        process_list.append(process)
    if "Apple" in hw_type:
        final_process_list = check_network_traffic(process_list)
        return final_process_list
    else:
        return process_list


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
            process['is_website_exist'] = 'yes'
        else:
            process['is_website_exist'] = 'no'
        process['permissions'] = entry['permissions']
        process['optional_permissions'] = entry['optional_permissions']
        process_list.append(process)
    return process_list


def check_processes_large_resident_memory(hw_type):
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
    if "Apple" in hw_type:
        final_process_list = check_network_traffic(process_list)
        return final_process_list
    else:
        return process_list


def check_application_version():
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


def check_apivoid(api_key, process_list, export_process_list=None):
    # Check to find the detection rate of remote IP address in apivoid
    export_process_list = []
    for process in process_list:
         if not ipaddress.ip_address(process['remote_address']).is_private:
            payload = {'key': api_key, 'ip': process['remote_address']}
            r = requests.get(url='https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/', params=payload)
            if "error" not in r.json():
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
                export_process_list.append(process)
            else:
                process['is_private'] = 'false'
                process['detections'] = process['detection_rate'] = process['country'] = process['isp'] = \
                    process['is_proxy'] = process['is_webproxy'] = process['is_vpn'] = process['is_hosting'] = \
                    process['is_tor'] = 'License Error'
                export_process_list.append(process)
         else:
            process['is_private'] = 'true'
            process['detections'] = process['detection_rate'] = process['country'] = process['isp'] = \
                process['is_proxy'] = process['is_webproxy'] = process['is_vpn'] = process['is_hosting'] = \
                process['is_tor'] = 'N/A'
            export_process_list.append(process)
    return export_process_list

def check_vt(apikey, process_list, export_process_list=None):
    print(apikey)
    headers = {"Accept-Encoding": "gzip, deflate","User-Agent": "gzip,  My Python requests"}
    headers["X-Apikey"] = apikey.strip()
    export_process_list = []
    for process in process_list:
        if not ipaddress.ip_address(process['remote_address']).is_private:
            url = ('https://www.virustotal.com/api/v3/ip_addresses/%s' % process['remote_address'])
            response_dict = {}
            try:
                response_dict = requests.get(url, headers=headers).json()
                json_object = json.dumps(response_dict, indent=4)
                if 'last_analysis_results' in json_object:
                    process['detections'] = response_dict['data']['attributes']['last_analysis_stats']['malicious']
                    process['country'] = response_dict['data']['attributes']['country']
                else:
                    process['detections'] = 'License Quota exceeded'
                    process['country'] = 'License Quota exceeded'
            except Exception as e:
                process['detections'] = 'N/A'
                process['country'] = 'N/A'
        else:
            process['detections'] = 'N/A'
            process['country'] = 'N/A'
        export_process_list.append(process)
    return export_process_list


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
        if match_list:
            first_line = match_list[0].split(',')
            fifth_line = match_list[4].split(',')
            process['traffic_in_bytes'] = (int(fifth_line[4]) - int(first_line[4])) / 5
            process['traffic_out_bytes'] = (int(fifth_line[5]) - int(first_line[5])) / 5
            export_process_list.append(process)
    return export_process_list

def write_process_transfer_bytes_to_csv(file_name, parameters):
    if not bool(parameters):
        return 0
    if not os.path.exists(file_name):
        with open(file_name, 'a+', newline='') as write_obj:
            write_obj.write('date')
            write_obj.write(',current_time')
            write_obj.write(',name')
            write_obj.write(',pid')
            write_obj.write(',traffic_out_bytes')
            write_obj.write("\n")
    with open(file_name, 'a+', newline='') as write_obj:
        # Adding entries
        for process in parameters:
            try:
                if int(process['traffic_out_bytes']) > 0:
                    write_obj.write(str(process['date'] + ','))
                    write_obj.write(str(process['current_time'] + ','))
                    write_obj.write(str(process['name'] + ','))
                    write_obj.write(str(process['pid'] + ','))
                    write_obj.write(str(process['traffic_out_bytes']))
                    write_obj.write("\n")
            except Exception:
                pass


def write_suspicious_remote_ip_to_csv(file_name, parameters):
    # This function will write if any of your process is connected to remote\
    # malicious IP address
    if not bool(parameters):
        return 0
    if not os.path.exists(file_name):
        with open(file_name, 'a+', newline='') as write_obj:
            write_obj.write('date')
            write_obj.write(',current_time')
            write_obj.write(',name')
            write_obj.write(',pid')
            write_obj.write(',traffic_out_bytes')
            write_obj.write(',detections')
            write_obj.write("\n")
    with open(file_name, 'a+', newline='') as write_obj:
        # Adding entries
        for process in parameters:
            try:
                if int(process['detections']) > 0:
                    write_obj.write(str(process['date'] + ','))
                    write_obj.write(str(process['current_time'] + ','))
                    write_obj.write(str(process['name'] + ','))
                    write_obj.write(str(process['pid'] + ','))
                    write_obj.write(str(process['traffic_out_bytes']))
                    write_obj.write(str(process['detections']))
                    write_obj.write("\n")
            except Exception:
                pass


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
    df = pandas.read_csv(csv_file_path, error_bad_lines=False)
    json_file = csv_file_path.rstrip('.csv') + ".json"
    df.to_json(json_file, orient='records')

def check_hardware_vendor():
    """Find the hardware vendor of the system"""
    instance = osquery.SpawnInstance()
    instance.open()
    result = instance.client.query("SELECT hardware_vendor from system_info")
    response = result.response
    return response[0]['hardware_vendor']
