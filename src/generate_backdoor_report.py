import backdoor


def write_to_csv_processes_exposed_network_attack():
    """ Find processes that is listening on 0.0.0.0 and exposing ur network for attack and write it in csv file """
    process_list = backdoor.processes_exposed_network_attack()
    print(process_list)
    # Write it to CSV file
    backdoor.convert_to_csv('process_exposed_network_attack.csv', process_list)
    print("Processes exposed to network attacks are written in process_exposed_network_attack.csv")


if __name__ == "__main__":
    # Find processes that is exposed for potential network attacks
    write_to_csv_processes_exposed_network_attack()
