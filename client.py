from os import listdir
from os import system
from ipaddress import ip_address
import getpass
import socket
import json
from cryptography.fernet import Fernet


# Main controller of the program's function calls.
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
    system('cls')  # 'clear' in Linux


# Print a banner message.
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
    # Comment
    config_files = listdir(conf_path)
    config_files.remove('_devices')
    config_files.remove('_cryptography')
    config_files.remove('_users')
    config_files = tuple(config_files)
    loaded_files = []
    loaded_tracker = []
    exit_loop = False

    while not exit_loop:
        system('cls')  # 'clear' in Linux
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
    while not exit_loop:
        server_info = {'ip': '', 'port': '', 'username': '', 'password': ''}

        system('cls')  # 'clear' in Linux
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


# Comment
def encrypt_data(data, key_file):
    with open(key_file, 'rb') as file:
        key = file.read()
    crypto_obj = Fernet(key)
    token = crypto_obj.encrypt(data.encode())

    return token


# Comment
def decrypt_data(data, key_file):
    with open(key_file, 'rb') as file:
        key = file.read()
    crypto_obj = Fernet(key)
    token = crypto_obj.decrypt(data).decode()

    return token


# Comment
def menu_server_com(loaded_files, server_info):
    # Comment
    config = []
    for elem_tuple in loaded_files:
        for elem_value in elem_tuple:
            config.append(elem_value)
    config = tuple(config)

    system('cls')  # 'clear' in Linux
    print_banner('Automate the boring-a-tron', 'AUTOMATION IN PROGRESS')

    # Comment
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((str(server_info['ip']), int(server_info['port'])))

        # Comment
        config_plus = [server_info['username'], server_info['password']]
        for elem in config:
            config_plus.append(elem)
        config_plus = tuple(config_plus)

        # Comment
        config_serialized = json.dumps(config_plus)
        sock_data = encrypt_data(config_serialized, KEYPATH)
        sock_data_plus = f'{str(len(sock_data)):<{HSIZE}}'.encode(FORMAT) + sock_data
        sock.sendall(sock_data_plus)

        # Comment
        server_data_encrypted = sock.recv(PKTSIZE)
        token = decrypt_data(server_data_encrypted, KEYPATH)
        server_data = json.loads(token)

    if server_data[0] != '-1':
        print(f'Configured devices: {server_data[0]}/{server_data[1]}')
    else:
        print(f'Connection failed:\n{server_data[1]}\n')

    sock.close()


# Global variables.
CONFPATH = '_config-files/'
KEYPATH = '_config-files/_cryptography/crypto_key.txt'
WINDOWX = 79
WINDOWY = 45
HSIZE = 7
PKTSIZE = 1024
FORMAT = 'utf-8'

# Start the main program.
main()
