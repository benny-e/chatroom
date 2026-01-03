import socket
import threading
import sys
from pathlib import Path
from chatroom.tofu import verify_or_pin_server
from chatroom.protocol import send_frame, recv_frame, CONTROL_EXIT
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes



def receive(client, username, symmetric_key):
    while True:
        try:
            data = recv_frame(client)
            if data is None:
                print("\n<server disconnected>")
                return

            if len(data) < 32:
                print("bad frame (too small)")
                continue

            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]

            cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            text = plaintext_bytes.decode("utf-8", errors="replace")

            print("\r", end="")
            print(" " * 80, end="\r")
            print(text)
            print("You: ", end="", flush=True)


        except ValueError:
            print("Message failed authentication (bad tag). Dropping it.")
            print("You: ", end="", flush=True)
        except Exception as e:
            print("\nError receiving message. Closing connection:", e)
            client.close()
            break

def write(client, username, symmetric_key):
    while True:

        try:
            user_input = input("You: ").strip()
        except(EOFError, KeyboardInterrupt):
            user_input = "<exit>"

        if user_input.lower() == "<exit>":
            try:
                send_frame(client, CONTROL_EXIT)
            except OSError:
                pass

            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            try:
                client.close()
            except OSError:
                pass

            return

        message = f"{username}: {user_input}"

        cipher = AES.new(symmetric_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))

        payload = cipher.nonce + tag + ciphertext
        send_frame(client, payload)


#function to connect client to server and start listening and send threads
def start_client(IP_addr, port):
    username = input("Enter username: ")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP_addr, port))


    server_public_key = recv_frame(client)
    if not server_public_key:
        print("server closed during handshake (public key)")
        client.close()
        return


    verify_or_pin_server(IP_addr, port, server_public_key)


    pub = RSA.import_key(server_public_key)
    symmetric_key = get_random_bytes(32)
    encrypted_key = PKCS1_OAEP.new(pub).encrypt(symmetric_key)

    send_frame(client, encrypted_key)

    send_frame(client, username.encode("utf-8"))

    receive_thread = threading.Thread(target=receive, args=(client, username, symmetric_key))
    receive_thread.start()

    write_thread = threading.Thread(target=write, args=(client, username, symmetric_key))
    write_thread.start()

    print("Client started. Type <exit> to close connection.")


    
if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: <IP addr> <port>")
        exit()

    IP_addr = sys.argv[1]
    port = int(sys.argv[2])

    start_client(IP_addr, port)
