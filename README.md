# Netmiko-Router-Automation
Still a work in progress...

Client loads in a specified configuration file, collects destination information and connects to the server, then sends the encrypted data. 
The server use the information to configure all routers that are specified from a local file (internal topology information set before script execution), 
then reports back to the client. 

Key-modules: Fernet, Netmiko and Joblib.
