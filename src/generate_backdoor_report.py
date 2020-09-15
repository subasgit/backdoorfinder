import backdoor


def write_to_csv_processes_exposed_network_attack():
    """ Find processes that is listening on 0.0.0.0 and exposing ur network for attack and write it in csv file """
    process_list = backdoor.processes_exposed_network_attack()
    print(process_list)
    # Write it to CSV file
    backdoor.convert_to_csv('process_exposed_network_attack.csv', process_list)
    print("Processes exposed to network attacks are written in process_exposed_network_attack.csv")


def write_to_csv_suspicious_process_to_unknown_ports():
    """ Find suspicious processes from your hosts connecting to unknown ports. If you want to verify \
    if the connected external IP address is malicious, then you can create an account in \
    API VOID and provide the API key to cross verify if the IP address is really malicious.\
    You can skip that check if you don't want to cross check the maliciousness of the IP by typing none """
    # Create a new API key in API VOID and enter it here. If you don't want to check, enter none
    api_key = input("Enter your api_key: ")
    process_list = backdoor.suspicious_process_to_unknown_ports(api_key)
    print(process_list)
    # Write it to CSV file
    backdoor.convert_to_csv('suspicious_process_to_unknown_ports.csv', process_list)
    print("Suspicious process connecting to unknown ports are written in suspicious_process_to_unknown_ports.csv ")


if __name__ == "__main__":
    # Find processes that is exposed for potential network attacks
    write_to_csv_processes_exposed_network_attack()

    # Find suspicious process connecting to unknown ports
    write_to_csv_suspicious_process_to_unknown_ports()
