# Router-Automation
Summary: 
Client/server communication with encrypted messages, ment to load a configuration file on the client-side and automate the configuration process on the server-side.

More detailed:
Client loads in a specified configuration file, collects destination information, encrypts the message and connects to the server, then sends the data. 
The server use the information to configure all routers that are specified from a local file (internal topology information set before script execution), 
then reports back to the client. 

Key-modules: Fernet, Netmiko and Joblib.
