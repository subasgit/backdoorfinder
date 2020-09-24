import backdoor


def write_to_csv_processes_exposed_network_attack():
    """ Find processes that is listening on 0.0.0.0 and exposing ur network for attack and write it in csv file """
    process_list = backdoor.processes_exposed_network_attack()
    print(process_list)
    with open("configure.txt", 'r') as f1:
        for line in f1:
            if "file path" in line:
                file_location = line.split("= ", 1)[1]
            else:
                value = "none"
                file_location = "default"
    # Write it to CSV file
    if file_location != "default":
        final_file_path = file_location+"/process_exposed_network_attack.csv"
    else:
        final_file_path = "process_exposed_network_attack.csv"

    backdoor.convert_to_csv(final_file_path, process_list)
    print("Processes exposed to network attacks are written in process_exposed_network_attack.csv")


def write_to_csv_suspicious_process_to_unknown_ports():
    """ Find suspicious processes from your hosts connecting to unknown ports. If you want to verify \
    if the connected external IP address is malicious, then you can create an account in \
    API VOID and provide the API key to cross verify if the IP address is really malicious.\
    You can skip that check if you don't want to cross check the maliciousness of the IP by typing none """
    # Create a new API key in API VOID and enter it here. If you don't want to check, enter none
    with open("configure.txt", 'r') as f1:
        for line in f1:
            if "api_key" in line:
                value = line.split("=", 1)[1]
            elif "file path" in line:
                file_location = line.split("= ", 1)[1]
            else:
                value = "none"
                file_location = "default"
    process_list = backdoor.suspicious_process_to_unknown_ports(value)
    print(process_list)
    # Write it to CSV file
    if file_location != "default":
        final_file_path = file_location+"/suspicious_process_to_unknown_ports.csv"
    else:
        final_file_path = "suspicious_process_to_unknown_ports.csv"

    backdoor.convert_to_csv(final_file_path, process_list)
    print("Suspicious process connecting to unknown ports are written in suspicious_process_to_unknown_ports.csv ")


if __name__ == "__main__":
    # Find processes that is exposed for potential network attacks
    write_to_csv_processes_exposed_network_attack()

    # Find suspicious process connecting to unknown ports
    write_to_csv_suspicious_process_to_unknown_ports()
