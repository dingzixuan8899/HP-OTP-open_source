# server_hp_otp.py
import gmpy2
import hashlib
import secrets
from websocket_server import WebsocketServer
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Global group parameters ---
q = gmpy2.next_prime(2**256)
g = 2  # generator of G

# Stored registration records
server_db = {}

def H(data: str) -> int:
    """Hash to Zq."""
    digest = hashlib.sha256(data.encode()).hexdigest()
    return int(digest, 16) % q

def FOTP(shared_secret: int, ec: int) -> str:
    """Hash-based OTP generation with truncation (6 digits)."""
    data = str(shared_secret) + str(ec)
    digest = hashlib.sha256(data.encode()).hexdigest()
    otp_int = int(digest, 16) % (10**6)
    return str(otp_int).zfill(6)

def handle_message(client, server, message):
    msg_parts = message.split('|')
    cmd = msg_parts[0]

    # Registration phase
    if cmd == "REGISTER":
        DID, Ac_str = msg_parts[1], msg_parts[2]
        Ac = int(Ac_str)
        server_db[DID] = {'Ac': Ac}
        server.send_message(client, "REGISTER_OK")

    # Verification phase
    elif cmd == "CHALLENGE":
        DID = msg_parts[1]
        record = server_db.get(DID)
        if not record:
            server.send_message(client, "ERROR: UNKNOWN DID")
            return
        ms = secrets.randbelow(q)
        Bs = pow(record['Ac'], ms, q)
        record['ms'] = ms
        record['Bs'] = Bs
        server.send_message(client, f"CHALLENGE|{Bs}")

    # Receive OTP from device
    elif cmd == "OTP":
        DID, otp_recv, ec = msg_parts[1], msg_parts[2], int(msg_parts[3])
        record = server_db.get(DID)
        if not record:
            server.send_message(client, "ERROR: UNKNOWN DID")
            return
        shared_secret = pow(g, record['ms'], q)
        otp_check = FOTP(shared_secret, ec)
        if otp_recv == otp_check:
            server.send_message(client, "AUTH_SUCCESS")
        else:
            server.send_message(client, "AUTH_FAIL")

server = WebsocketServer(host='0.0.0.0', port=9000)
server.set_fn_message_received(handle_message)
print("HP-OTP Server started on ws://localhost:9000")
server.run_forever()
