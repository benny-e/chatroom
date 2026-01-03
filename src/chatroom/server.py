import socket
import threading
import sys
import os
from functools import partial
from pathlib import Path
from chatroom.protocol import send_frame, recv_frame
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes


clients = {}
clients_lock = threading.Lock()


#This functions are in progress for generating 
#persistant RSA keys and implementing TOFU architecture

#generates key dir in ~/.config/chatroom
def server_key_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    d = Path(base) / "chatroom"
    d.mkdir(parents=True, exist_ok=True)
    return d

def load_or_create_server_keys() -> tuple[bytes, bytes]:
    d = server_key_dir()
    priv_path = d / "server_private.pem"
    pub_path = d / "server_public.pem"

    if priv_path.exists and pub_path.exists():
        return priv_path.read_bytes(), pub_path.read_bytes()
    
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    priv_path.write_bytes(private_key)
    pub_path.write_bytes(public_key)

    return private_key, public_key


def broadcast(message: bytes, sender):
    #snapshot recipients + their keys under lock
    with clients_lock:
        recipients = [(cs, info["symmetric_key"], info["send_lock"]) for cs, info in clients.items() if sender is None or cs is not sender]

    dead = []

    for cs, key, lock in recipients:
        try:
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(message)
            payload = cipher.nonce + tag + ciphertext


            with lock:
                send_frame(cs, payload)

        except OSError as e:
            print("client disconnected in broadcast:", e)
            dead.append(cs)

    #remove dead sockets in one place under lock
    if dead:
        with clients_lock:
            for cs in dead:
                clients.pop(cs, None)
                try:
                    cs.close()
                except:
                    pass
     

#function to encrypt give message with clients symmetric key
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce + ciphertext


#function for handling an individual client
def handle_client(client, symmetric_key):
    try:
        while True:
            try:
                encrypted_message = recv_frame(client)
                if not encrypted_message:
                    print("client disconnected, empty")
                    break
                if len(encrypted_message) < 32:
                    print("bad message, too small")
                    continue

                #decrypting message
                nonce = encrypted_message[:16]
                tag = encrypted_message[16:32]
                ciphertext = encrypted_message[32:]

                cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
                decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

                #send message
                #print("sending message to client: ", decrypted_message)
                broadcast(decrypted_message, client)
            except ValueError as e:
                #tag check
                print("bad tag from client, dropping: ", e)
                continue
            except OSError as e:
                print("error in handle_client:", e)
                break
            except Exception as e:
                print("error in handle_client", e)
                break

    finally:
        username = None
        with clients_lock:
            info = clients.pop(client, None)
            if info:
                username = info.get("username")

        if username:
            notice = f"<{username} disconnected>".encode("utf-8")
            broadcast(notice, sender=None)  

        try:
            client.close()
        except OSError:
            pass
   

def server_main(IP_addr, port): 
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP_addr, port))
    server.listen()

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)

    
    private_key, public_key = load_or_create_server_keys()

    print("Server started. Waiting for clients...")
    try:
        while True:
            try:
                c, addr = server.accept()
            except socket.timeout:
                continue

            print(f"connected with {str(addr)}")
            #send puclic key
            send_frame(c, public_key)
            
            encrypted_symmetric = recv_frame(c)
            
            if not encrypted_symmetric:
                print("client discconected during key exchange")
                c.close()
                continue
            #decrypting key
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
            symmetric_key = cipher_rsa.decrypt(encrypted_symmetric)
            


    #recieving a username from the client
            
            
            username_bytes = recv_frame(c)
            if not username_bytes:
                print("client disconnected during username exchange")
                c.close()
                continue
                
            username = username_bytes.decode("utf-8", errors="replace")
            print("Username: ", username)

            #adds client socket, username, and symmetric key to a nested dictionary
            with clients_lock:
                clients[c] = {
                    "username": username,
                    "symmetric_key": symmetric_key,
                    "send_lock": threading.Lock(),
                }

            join_notice = f"<{username} joined>".encode("utf-8")
            broadcast(join_notice, sender=c)  # exclude the joining client


            thread = threading.Thread(target = handle_client, args=(c,symmetric_key), daemon=True)

            print("client thread started.")
            thread.start()

    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        #notify clients
        try:
            broadcast(b"<server shutting down>", sender=None)
        except Exception:
            pass

        # close listening socket
        try:
            server.close()
        except OSError:
            pass

        #close all clients
        with clients_lock:
            sockets = list(clients.keys())
            clients.clear()

        for cs in sockets:
            try:
                cs.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                cs.close()
            except OSError:
                pass
 
if __name__ == "__main__":
 
    #checks userinput 
    if len(sys.argv) != 2:
        print("Usage: <port>")
        exit()

    bind_host = '0.0.0.0'
    hostname = socket.gethostname()

    port = int(sys.argv[1])

    print("Starting server on port: ", port)

    server_main(bind_host, port)
