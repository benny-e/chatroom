A simple client-server Python TCP chatroom that uses hyrbrid encryption (RSA for key exchange and AES-EAX for message encryption) with Trust on First Use (TOFU) to save and verify server identity. 

Requirements:  
- Python 3.10+
- pycryptodome

Installation:    
Clone the repository and install dependencies:  

```bash
git clone https://github.com/benny-e/chatroom   
cd chatroom  
python -m venv .venv  
source .venv/bin/activate  
pip install -e .  
```

Usage:  
The application is run using the chatroom command, which is installed when  
the project is installed in editable mode.  


Defaults:  
Server bind address: 0.0.0.0  
Client default host: 127.0.0.1  
Default port: 5555  


Starting the server:  
Start the server using default settings (binds to all interfaces on port 5555):   

```bash
chatroom --server
```
To run the server on a custom port: 
```bash
chatroom --server --port <port> 
```
Stop the server with Ctrl + C.  


Start the client:  
```bash
chatroom --host <server-ip>  
```
Connect using a custom port:  
```bash
chatroom --host <server-ip> --port <port>  
```
Type '<exit>' when connected to disconnect

