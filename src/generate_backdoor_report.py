import backdoor
import argparse
import sys


def write_to_csv_processes_exposed_network_attack():
    """ Find processes that is listening on 0.0.0.0 and exposing ur network for attack and write it in csv file """

    # Get the apikey value and file location from configure.txt
    final_file_path = read_configure_file('file_location', value='process_exposed_network_attack.csv')

    # Get the processes exposed to network attacks
    process_list = backdoor.processes_exposed_network_attack()

    # Write it to CSV file
    backdoor.convert_to_csv(final_file_path, process_list)
    print("Processes exposed to network attacks are written in process_exposed_network_attack.csv")


def write_to_csv_suspicious_process_to_unknown_ports():
    """ Find suspicious processes from your hosts connecting to unknown ports. If you want to verify \
    if the connected external IP address is malicious, then you can create an account in \
    API VOID and provide the API key to cross verify if the IP address is really malicious.\
    You can skip that check if you don't want to cross check the maliciousness of the IP by typing none """
    # Create a new API key in API VOID and enter it here. If you don't want to check, enter none

    # Get the apikey value and file location from configure.txt
    api_key = read_configure_file('api_key')
    final_file_path = read_configure_file('file_location', value='suspicious_process_to_unknown_ports.csv')

    # Get the suspicious process to unknown ports
    process_list = backdoor.suspicious_process_to_unknown_ports(api_key)

    # Write it to CSV file
    backdoor.convert_to_csv(final_file_path, process_list)
    print("Suspicious process connecting to unknown ports are written in suspicious_process_to_unknown_ports.csv ")


def write_to_csv_process_running_binary_deleted():
    """ Find processes running on the endpoint whose binary has been deleted from disk"""
    # Processes that are running whose binary has been deleted from the disk
    process_list = backdoor.processes_running_binary_deleted()
    # Write it to CSV file
    final_file_path = read_configure_file('file_location', value='binary_deleted_process.csv')
    backdoor.convert_to_csv(final_file_path, process_list)


def read_configure_file(parameter, value=''):
    """This function will read parameters from configure.txt file and return the required value"""
    if parameter == 'file_location':
        with open("configure.txt", 'r') as f1:
            for line in f1:
                if "file path" in line:
                    file_location = line.split("= ", 1)[1]
                    break
            if 'default' in file_location:
                final_file_path = value
            else:
                final_file_path = file_location + '/'+value
        return final_file_path
    if parameter == 'api_key':
        with open("configure.txt", 'r') as f1:
            for line in f1:
                if "api_key" in line:
                    value = line.split("=", 1)[1]
                    break
                else:
                    value = "none"
        return value


def get_arguments_options(args=sys.argv[1:]):
    """Parse arguments from command line and run specific functions"""
    parser = argparse.ArgumentParser(description="Select from functions below")
    parser.add_argument("-i", "--input", help="ena -> Find processes exposed to network attack;\
                                                 sup -> Find suspicious process to unknown_ports;\
                                              bd -> Find processes running with binary deleted")
    option = parser.parse_args(args)
    return option


if __name__ == "__main__":
    if len(sys.argv) == 1:
        write_to_csv_processes_exposed_network_attack()
        write_to_csv_suspicious_process_to_unknown_ports()
        write_to_csv_process_running_binary_deleted()

    options = get_arguments_options(sys.argv[1:])
    if options.input == 'ena':
        # Find processes that is exposed for potential network attacks
        write_to_csv_processes_exposed_network_attack()
    if options.input == 'sup':
        # Find suspicious process connecting to unknown ports
        write_to_csv_suspicious_process_to_unknown_ports()
    if options.input == 'bd':
        write_to_csv_process_running_binary_deleted()