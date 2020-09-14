import os
import osquery


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
    # List all that process
    for entry in response:
        process = {'name': entry['name'], 'port': entry['port']}
        process_list.append(process)
        print(process_list)
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
