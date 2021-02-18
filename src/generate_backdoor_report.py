import backdoor
import argparse
import sys
import time


def write_to_csv_processes_exposed_network_attack():
    """ Find processes that is listening on 0.0.0.0 and exposing ur network for attack and write it in csv file """

    # Get the apikey value and file location from configure.txt
    final_file_path = read_configure_file('file_location', value='process_exposed_network_attack.csv')
    suspicious_process_file_path = read_configure_file('file_location', value='process_transferring_bytes.csv')

    # Get the processes exposed to network attacks
    process_list = backdoor.processes_exposed_network_attack(hw_type)

    if process_list:
        # Write it to CSV file
        backdoor.convert_to_csv(final_file_path, process_list)
        print("Processes exposed to network attacks are written in process_exposed_network_attack.csv")

        # Write only suspicious process to CSV file
        backdoor.write_process_transfer_bytes_to_csv(suspicious_process_file_path, process_list)
        print("Processes transferring bytes are written in process_transferring_bytes.csv")

        # Write the CSV file to Json
        backdoor.convert_csv_to_json(final_file_path)
        print("Processes exposed to network attacks are written in process_exposed_network_attack.json")


def write_to_csv_suspicious_process_to_unknown_ports():
    """ Find suspicious processes from your hosts connecting to unknown ports. If you want to verify \
    if the connected external IP address is malicious, then you can create an account in \
    API VOID and provide the API key to cross verify if the IP address is really malicious.\
    You can skip that check if you don't want to cross check the maliciousness of the IP by typing none """
    # Create a new API key in API VOID and enter it here. If you don't want to check, enter none

    # Get the apikey type and value and file location from configure.txt
    api_key,api_key_type = read_configure_file('api_key')
    final_file_path = read_configure_file('file_location', value='suspicious_process_to_unknown_ports.csv')
    suspicious_process_file_path = read_configure_file('file_location', value='process_transferring_bytes.csv')

    # Get the suspicious process to unknown ports
    process_list = backdoor.suspicious_process_to_unknown_ports(hw_type, api_key, api_key_type)

    if process_list:
        # Write it to CSV file
        backdoor.convert_to_csv(final_file_path, process_list)
        print("Suspicious process connecting to unknown ports are written in suspicious_process_to_unknown_ports.csv ")

        # Write only suspicious process to CSV file
        backdoor.write_process_transfer_bytes_to_csv(suspicious_process_file_path, process_list)
        print("Processes transferring bytes are written in process_transferring_bytes.csv")

        # Write the CSV file to Json
        backdoor.convert_csv_to_json(final_file_path)
        print("Suspicious process connecting to unknown ports are written in suspicious_process_to_unknown_ports.json ")


def write_to_csv_process_running_binary_deleted():
    """ Find processes running on the endpoint whose binary has been deleted from disk"""
    # Processes that are running whose binary has been deleted from the disk
    process_list = backdoor.processes_running_binary_deleted(hw_type)
    if process_list:
        # Write it to CSV file
        final_file_path = read_configure_file('file_location', value='binary_deleted_process.csv')
        backdoor.convert_to_csv(final_file_path, process_list)
        print("Processes running with its binary deleted are written in binary_deleted_process.csv")

        # Write the CSV file to Json
        backdoor.convert_csv_to_json(final_file_path)
        print("Processes running with its binary deleted are written in binary_deleted_process.json")


def write_to_csv_suspicious_chrome_extensions():
    """Find chrome extensions which are suspicious"""
    # Find Suspicious Chrome extensions
    process_list = backdoor.find_suspicious_chrome_extensions()

    if process_list:
        # Write it to CSV file
        final_file_path = read_configure_file('file_location', value='suspicious_chrome_extensions.csv')
        backdoor.convert_to_csv(final_file_path, process_list)
        print("Suspicious chrome extensions names are written in suspicious_chrome_extensions.csv")

        # Write the CSV file to Json
        backdoor.convert_csv_to_json(final_file_path)
        print("Suspicious chrome extensions names are written in suspicious_chrome_extensions.json")


def write_to_csv_process_largest_resident_memory():
    """Find top 10 process that occupy largest resident memory"""
    # Processes that are running with largest resident memory
    process_list = backdoor.check_processes_large_resident_memory(hw_type)

    ## Write it to CSV file
    final_file_path = read_configure_file('file_location', value='large_memory_resident_size_process.csv')
    backdoor.convert_to_csv(final_file_path, process_list)
    print("Large resident memory process are written in large_memory_resident_size_process.csv")

    # Write the CSV file to JSON
    backdoor.convert_csv_to_json(final_file_path)
    print("Large resident memory process are written in large_memory_resident_size_process.json")


def write_to_csv_check_application_versions():
    """Find application and its corresponding versions """
    process_list = backdoor.check_application_version()

    if process_list:
        ## Write to CSV file
        final_file_path = read_configure_file('file_location', value='application_and_versions.csv')
        backdoor.convert_to_csv(final_file_path, process_list)
        print("Application and versions are written in application_and_versions.csv")

        ## Write the CSV file to JSON
        backdoor.convert_csv_to_json(final_file_path)
        print("Application and versions are written in application_and_versions.json")


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
                final_file_path = file_location + '/' + value
        return final_file_path
    if parameter == 'api_key':
        with open("configure.txt", 'r') as f1:
            for line in f1:
                if "api_key_type" in line:
                    type = line.split("=", 1)[1]
                if "api_key" in line:
                    value = line.split("=", 1)[1]
            return value, type

def get_arguments_options(args=sys.argv[1:]):
    """Parse arguments from command line and run specific functions"""
    parser = argparse.ArgumentParser(description="Select from the options below. All functions will be run if no\
                                                 options are given")
    parser.add_argument('-ena', action='store_true', help='Identify processes exposed to network attack')
    parser.add_argument('-spu', action='store_true', help='Identify suspicious process to unknown_ports')
    parser.add_argument('-bd', action='store_true', help='Identify malicious process running with binary deleted')
    parser.add_argument('-ce', action='store_true', help='Identify suspicious Chrome extensions')
    parser.add_argument('-lmem', action='store_true', help='Identify processes that has large resident memory')
    parser.add_argument('-appcheck', action='store_true', help='Identify applications running and its versions')
    parser.add_argument('-freq', action='store', type=int, help='Enter how frequent you want to run in minutes')
    parser.add_argument('-duration', action='store', type=int, help='Enter the duration of the run in minutes')
    option = parser.parse_args(args)
    return option


if __name__ == "__main__":
    counter = 1
    duration = 1
    delay = 0
    frequency = 0
    # Read and store the hardware vendor name
    hw_type = backdoor.check_hardware_vendor()

    options = get_arguments_options(sys.argv[1:])
    if options.duration:
        seconds = options.duration * 60
        if options.freq:
            delay = options.freq * 60
        else:
            delay = 60
        frequency = seconds / delay

    while counter and duration:
        if not (options.ena or options.spu or options.bd or options.ce or options.appcheck or options.lmem):
            write_to_csv_processes_exposed_network_attack()
            write_to_csv_suspicious_process_to_unknown_ports()
            write_to_csv_process_running_binary_deleted()
            write_to_csv_suspicious_chrome_extensions()
            write_to_csv_process_largest_resident_memory()
            write_to_csv_check_application_versions()

        if options.ena:
            # Find processes that is exposed for potential network attacks
            write_to_csv_processes_exposed_network_attack()
        if options.spu:
            # Find suspicious process connecting to unknown ports
            write_to_csv_suspicious_process_to_unknown_ports()
        if options.bd:
            # Find processes whose binary files are deleted
            write_to_csv_process_running_binary_deleted()
        if options.ce:
            # Find Suspicious Chrome extensions
            write_to_csv_suspicious_chrome_extensions()
        if options.lmem:
            # Find process having large resident memory
            write_to_csv_process_largest_resident_memory()
        if options.appcheck:
            # Find applications and its versions
            write_to_csv_check_application_versions()

        # Check to run the program to run for set number of times and duration
        if frequency > 0:
            time.sleep(delay)
            if options.duration:
                frequency = frequency - 1
        else:
            counter = counter - 1
            duration = duration - 1
