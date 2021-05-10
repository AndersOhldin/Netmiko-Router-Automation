from netmiko import ConnectHandler  # Establish SSH-connections.
from netmiko import ssh_exception  # Control of SSH-exceptions.
from paramiko.ssh_exception import SSHException  # Control of SSH-exceptions.
from joblib import Parallel, delayed  # Connect to multiple routers simultaneously.
from json import loads  # Deserialize a string into a dictionary object.
from datetime import datetime  # Fetch current time and date.
import json
import socket
from cryptography.fernet import Fernet


# Main execution of the program.
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Comment
        sock.bind((HOST, PORT))
        sock.listen(0)
        conn, addr = sock.accept()
        client_data_raw = conn.recv(PKTSIZE)

        # Comment
        msg_len = int(client_data_raw[:HSIZE].decode(FORMAT))
        client_data_encrypted = client_data_raw[HSIZE:]
        while len(client_data_encrypted) < msg_len:
            client_data_encrypted += conn.recv(PKTSIZE)

        token = decrypt_data(client_data_encrypted, KEYPATH)
        client_data = json.loads(token)

        # Collect a list of dictionaries containing permitted users (source IP, username and passwords).
        permitted_users = []
        with open(USERPATH) as file_devices:
            for line in file_devices:
                permitted_users.append(loads(line))

        # Comment
        verified_user_found = False
        send_data = ()
        for user in permitted_users:
            if addr[0] == user['source_ip'] and client_data[0] == user['user'] and client_data[1] == user['password']:
                verified_user_found = True

                # Collect a list of dictionaries containing router information (such as router IP, passwords and so on).
                all_routers = []
                with open(DEVICEPATH) as file_devices:
                    for line in file_devices:
                        all_routers.append(loads(line))

                # Run parallel functions that configure all router devices in the list "all_routers".
                conf_result = Parallel(n_jobs=-1)(delayed(configure_router)
                                                  (device_info=router_n,
                                                   config_commands=client_data[2:],
                                                   client_ip=addr[0])
                                                  for router_n in all_routers)

                # Count the number of successful executions of the above functions.
                devices_confed = 0
                for x in conf_result:
                    if x:
                        devices_confed += 1

                # Add info regarding automation process.
                send_data = (devices_confed, len(all_routers))

        if not verified_user_found:
            print(f'{addr[0]} tried to connect with faulty authorization information.')
            send_data = ('-1', 'Faulty authorization information given.')

        # Comment
        send_data_serialized = json.dumps(send_data)
        token = encrypt_data(send_data_serialized, KEYPATH)
        conn.sendall(token)
        conn.close()


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


# Log event to specified file.
def log_event(event_string, file_path):
    with open(file_path, 'a') as log_file:
        log_file.write(event_string)


# Connect to and configure the device that is stored in the dictionary "device_info".
def configure_router(device_info, config_commands, client_ip):
    # Create a log file for future use.
    formatted_time = '_date_' + str(datetime.now())[0:19].replace(':', '-').replace(' ', '_time_')
    log_path = '_logs/RouterIP_' + str(device_info['ip']).replace('.', '-') + formatted_time + '.txt'
    with open(log_path, 'x') as file_log:
        file_log.write('Connected host: ' + str(client_ip) + '\n')

    try:
        # Connect to the device.
        net_con = ConnectHandler(**device_info)

        config_event = net_con.send_config_set(config_commands)
        log_event(config_event, log_path)

        # Disconnect from the device.
        net_con.disconnect()
        disconnect_message = "\nDisconnected.\n\n"
        log_event(disconnect_message, log_path)

        return True

    except SSHEXC as e:
        log_event('Could not access the device, troubleshooting message:\n' + str(e) + '\n\n', log_path)
        return False

    except ValueError as e:
        log_event('A value error occured:\n' + str(e) + '\n\n', log_path)
        return False


# Global variables.
HOST = '127.0.0.1'  # Interface to listen for connections on.
PORT = 65432  # Port to listen for connections on.
DEVICEPATH = '_config-files/_devices/configurable_network_devices.txt'
KEYPATH = '_config-files/_cryptography/crypto_key.txt'
USERPATH = '_config-files/_users/permitted_users.txt'
HSIZE = 7
PKTSIZE = 1024
FORMAT = 'utf-8'

# Exceptions defined to avoid the script from stopping mid-execution.
SSHEXC = (ssh_exception.NetMikoTimeoutException,
          ssh_exception.NetMikoAuthenticationException,
          SSHException)

# Start the automation process.
main()
