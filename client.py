#!/usr/bin/python3

# The program has been run with Python 3.8 as interpreter, on the operating system Ubuntu 20.04.2.0 LTS.
#
# Intended function   **************************************************************************************************
# Collect data from the user regarding which configuration file that is to be used in a remote automatic
# router configuration, what server to connect to and what port, username and password to use in the process.
# The program then awaits confirmation from the server and writes the response into the terminal UI.
# **********************************************************************************************************************

from os import listdir  # Enables the listing of files in specified folder(s).
from os import system  # Used to clear the terminal of unwanted characters.
from ipaddress import ip_address  # Confirm if given IP is valid.
import getpass  # Enables a user to write an input message without the key strokes echoing out into the terminal.
import socket  # Enables socket communication and functionality.
import json  # Used to serialize and deserialize data.
from cryptography.fernet import Fernet  # Enables encryption and decryption of data.


# Main execution of the program: Collect data from the user regarding which configuration file that is to be used in a
# remote automatic router configuration, what server to connect to and what port, username and password to use in the
# process. The program then awaits confirmation from the server and writes the response into the terminal UI.
def main():
    system('mode con: cols=' + str(WINDOWX) + ' lines=' + str(WINDOWY))

    loaded_files = menu_load_configuration_files(CONFPATH)
    while len(loaded_files) == 0:
        print('\nNo files loaded, please try again.')
        input('Press any key to continue...')
        loaded_files = menu_load_configuration_files(CONFPATH)

    server_info = menu_collect_server_info()
    menu_server_com(loaded_files, server_info)

    input('Press any key to exit...')
    system('clear')  # Clear the terminal of unwanted characters.


# Print a dynamic banner message.
def print_banner(banner, sub_banner):
    # Print the top row.
    print('*' * WINDOWX)

    # Print the body.
    dynamic_line(banner)
    dynamic_line(sub_banner)

    # Print the bottom row.
    print('*' * WINDOWX)


# Print a dynamically adjusted size of a banner-line.
def dynamic_line(text):
    filler = int((WINDOWX - (len(text) + 2)) / 2)
    print('*' + ' ' * filler + text + ' ' * filler, end='')

    # Adjust the banner according to even/uneven message size and window width.
    if len(text) % 2 > 0 and WINDOWX % 2 == 0 or len(text) % 2 == 0 and WINDOWX % 2 > 0:
        print(' ', end='')
    print('*')


# Read the content of a file and return it as a tuple, elements are seperated by lines.
def file_to_tuple(file_path):
    file_list = []
    with open(file_path, 'r') as file:
        for line in file:
            file_list.append(line.replace('\n', ''))

    return tuple(file_list)


# Return a tuple containing information about manually selected configuration files.
def menu_load_configuration_files(conf_path):
    # Collect and store file names from a specified folder, then remove file names that are a part of the system
    # structure, but irrelevant for the configurations.
    config_files = listdir(conf_path)
    config_files.remove('_devices')
    config_files.remove('_cryptography')
    config_files.remove('_users')
    config_files = tuple(config_files)
    loaded_files = []
    loaded_tracker = []
    exit_loop = False

    # Loop of the terminal UI.
    while not exit_loop:
        system('clear')  # Clear the terminal window of unwanted characters.
        print_banner('Automate the boring-a-tron', 'LOAD FILES')

        # List all available files.
        for i in range(0, len(config_files)):
            print(str(i + 1) + '. ' + config_files[i])

        # List all loaded files.
        print('\nPreviously loaded file(s):')
        for i in range(0, len(loaded_tracker)):
            if i != 0:
                print(', ', end='')
            print(f'{loaded_tracker[i]}', end='')

        if len(loaded_tracker) != 0:
            print('\n')

        # Collect information regarding which file to load in.
        print('-' * WINDOWX)
        try:
            option = int(input('Load file number: '))

            if option - 1 >= 0 and option <= len(config_files):
                if not config_files[option - 1] in loaded_tracker:
                    loaded_files.append(file_to_tuple(conf_path + config_files[option - 1]))
                    loaded_tracker.append(config_files[option - 1])
                    print('\nAdded file: ' + config_files[option - 1])
                else:
                    print('The file is already loaded.')
            else:
                print('File not found, please try again.')

        except ValueError:
            print('Could not read file.')

        # Option to keep loading in more files.
        print('-' * WINDOWX)
        option = input("Load more files (Y/N)? ")
        if option == 'n' or option == 'N':
            exit_loop = True

    return tuple(loaded_files)


# Return a dictionary with an IP-address, port number and username/password.
def menu_collect_server_info():
    server_info = {}
    exit_loop = False

    # Loop of the terminal UI.
    while not exit_loop:
        server_info = {'ip': '', 'port': '', 'username': '', 'password': ''}

        system('clear')  # Clear the terminal window of unwanted characters.
        print_banner('Automate the boring-a-tron', 'SERVER INFO')

        try:
            # Make sure the given IP-address is a valid IP-address.
            ip = ip_address(input('IP-address:\t'))
            server_info['ip'] = ip

            # Make sure the given port is a valid port.
            port = int(input('Port:\t\t'))
            if port <= 0 or port >= 65535:
                raise ValueError('Invalid port number.')
            server_info['port'] = port

            # Collect username and password, where the password is hidden from the output line.
            server_info['username'] = input('Username:\t')
            server_info['password'] = getpass.getpass('Password:\t')

            # Option to redo the information gathering.
            print('-' * WINDOWX)
            option = input("Change any information (Y/N)? ")
            if option == 'n' or option == 'N':
                exit_loop = True

        except ValueError as e:
            print(f'Invalid information given:\n{e}')
            input('\nPress any key to continue...')

    return server_info


# Used to encrypt a character-string of data, returning a byte-string. The encryption-key is fetched from within the
# configuration folders.
def encrypt_data(data, key_file):
    with open(key_file, 'rb') as file:
        key = file.read()
    crypto_obj = Fernet(key)
    token = crypto_obj.encrypt(data.encode())

    return token


# Used to decrypt a byte-string of data, returning a character-string. The decryption-key is fetched from within the
# configuration folders.
def decrypt_data(data, key_file):
    with open(key_file, 'rb') as file:
        key = file.read()
    crypto_obj = Fernet(key)
    token = crypto_obj.decrypt(data).decode()

    return token


# Establishes a socket communication to a server, sends configuration information and recieves the server response.
# The server information and configuration files are given through the arguments of the function call.
def menu_server_com(loaded_files, server_info):
    # Convert the content of the file(s) to a tuple, where every element of the tuple is a line from the file(s).
    config = []
    for elem_tuple in loaded_files:
        for elem_value in elem_tuple:
            config.append(elem_value)
    config = tuple(config)

    system('clear')  # Clear the terminal of other characters.
    print_banner('Automate the boring-a-tron', 'AUTOMATION IN PROGRESS')

    # Creates a tuple where the first two elements are the username and password that is used on the server side,
    # then appends the elements from the tuple "config".
    config_plus = [server_info['username'], server_info['password']]
    for elem in config:
        config_plus.append(elem)
    config_plus = tuple(config_plus)

    # Serialize the data to be sent, encrypts it and adds a header in the beginning of the packet that tells the server
    # how long the packet is expected to be (allows for packets bigger than the size the server normally accepts).
    config_serialized = json.dumps(config_plus)
    sock_data = encrypt_data(config_serialized, KEYPATH)
    sock_data_plus = f'{str(len(sock_data)):<{HSIZE}}'.encode(FORMAT) + sock_data

    # Open socket communication, awaits a response and then closes the connection.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((str(server_info['ip']), int(server_info['port'])))
        sock.sendall(sock_data_plus)

        server_data_encrypted = sock.recv(PKTSIZE)
        sock.close()

    # Decrypt and deserialize the respons from the server.
    token = decrypt_data(server_data_encrypted, KEYPATH)
    server_data = json.loads(token)

    # Print recieved message in the terminal.
    if server_data[0] != '-1':
        print(f'Configured devices: {server_data[0]}/{server_data[1]}')
    else:
        print(f'Connection failed:\n{server_data[1]}\n')


# Global variables   ***************************************************************************************************
CONFPATH = '_config-files/'
KEYPATH = '_config-files/_cryptography/crypto_key.txt'
WINDOWX = 79
WINDOWY = 45
HSIZE = 7
PKTSIZE = 1024
FORMAT = 'utf-8'
# **********************************************************************************************************************

# Start the program.
main()
