import os
import osquery


def get_api_key():
    """This function prompts the user to enter api key"""
    result = input("Do you have Apivoid api_key?(yes/no): ")
    if result == 'yes':
        api_key = input("Enter your api_key: ")
        with open("configure.txt", 'w') as f1:
            f1.write("api_key_type = apivoid" + "\n")
            f1.write("api_key = " + api_key + "\n")
    else:
        result = input("Do you have VirusTotal api_key?(yes/no): ")
        if result == 'yes':
            api_key = input("Enter your api_key: ")
            with open("configure.txt", 'w') as f1:
                f1.write("api_key_type = vt" + "\n")
                f1.write("api_key = " + api_key + "\n")
        else:
             with open("configure.txt", 'w') as f1:
                f1.write("api_key_type = none" + "\n")
                f1.write("api_key = none" + "\n")


def get_file_path():
    """This function prompts the user to enter file path"""
    result = input("Do you need a specific filepath to write all output files ?(yes/no): ")
    if result == 'yes':
        file_path = input("Enter your file path :")
        with open("configure.txt", 'a+') as f1:
            f1.write("file path = " + file_path)
    else:
        with open("configure.txt", 'a+') as f1:
            f1.write("file path = default")


if __name__ == "__main__":
    # Get api_key from user and store it in a configure file
    get_api_key()
    # Get file path
    get_file_path()