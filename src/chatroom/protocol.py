import struct

MAX_FRAME = 256 * 1024

CONTROL_EXIT = b"__EXIT__"

def send_frame(sock, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if chunk == b"":
            return None  #disconnected
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock) -> bytes:
    header = recv_exact(sock, 4)
    if header is None:
        return None
    

    (length,) = struct.unpack("!I", header)
    if length > MAX_FRAME:
        raise ValueError("Frame too big")
    
    payload = recv_exact(sock, length)
    if payload is None:
        return None

    return payload
    

