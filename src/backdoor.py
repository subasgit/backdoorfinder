import os
import osquery
import requests
import time
from datetime import date


def processes_exposed_network_attack():
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
        process_list.append(process)
        # print(process_list)
    return process_list


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
        print('Process {} has established connection from {} port {} to {} port {}'.format(entry['name'],
                                                                                           entry['local_address'],
                                                                                           entry['local_port'],
                                                                                           entry['remote_address'],
                                                                                           entry['remote_port']))

        # Check whether the remote_address is a known malicious IP address if API Key is provided
        if api_key != 'none' and api_key != 'None':
            payload = {'key': api_key, 'ip': entry['remote_address']}
            r = requests.get(url='https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/', params=payload)
            if "error" not in r.json():
                print(r.json())
                output = r.json()
                detection_rate = output['data']['report']['blacklists']['detections']
                country = output['data']['report']['information']['country_name']
                if detection_rate > 5:
                    print('{} is a malicious address belongs to {} with a detection rate of {}'.format(
                        entry['remote_address'], country, detection_rate))
                    process_list.append(process)
                    # print(process_list)
                else:
                    print('{} is not a malicious address belongs to {}'.format(entry['remote_address'], country))
        else:
            process_list.append(process)
    return process_list


def convert_to_csv(file_name, parameters):
    # This function writes the output in CSV file
    if not bool(parameters):
        return 0
    if not os.path.exists(file_name):
        with open(file_name, 'a+', newline='') as write_obj:
            # Adding header for csv file
            for key in parameters[0]:
                write_obj.write(key + ",")
            write_obj.write("\n")

    with open(file_name, 'a+', newline='') as write_obj:
        # Adding entries
        for process in parameters:
            print(process)
            for key, value in process.items():
                write_obj.write(value + ",")
            write_obj.write("\n")
