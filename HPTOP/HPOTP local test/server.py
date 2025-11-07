import gmpy2
import hashlib
import secrets
import socket

# --- Global parameters ---
q = gmpy2.next_prime(2**256)
g = 2
server_db = {}

def H(data: str) -> int:
    digest = hashlib.sha256(data.encode()).hexdigest()
    return int(digest, 16) % q

def FOTP(shared_secret: int, ec: int) -> str:
    data = str(shared_secret) + str(ec)
    digest = hashlib.sha256(data.encode()).hexdigest()
    otp_int = int(digest, 16) % (10**6)
    return str(otp_int).zfill(6)

def run_server(host='127.0.0.1', port=9000):
    s = socket.socket()
    s.bind((host, port))
    s.listen(1)
    print(f"HP-OTP Server listening on {host}:{port}")

    conn, addr = s.accept()
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(4096)
        if not data:
            break
        message = data.decode().strip()
        parts = message.split('|')
        cmd = parts[0]

        if cmd == "REGISTER":
            DID, Ac = parts[1], int(parts[2])
            server_db[DID] = {'Ac': Ac}
            conn.send(b"REGISTER_OK\n")

        elif cmd == "CHALLENGE":
            DID = parts[1]
            record = server_db.get(DID)
            if not record:
                conn.send(b"ERROR_UNKNOWN_DID\n")
                continue
            ms = secrets.randbelow(q)
            Bs = pow(record['Ac'], ms, q)
            record['ms'] = ms
            record['Bs'] = Bs
            conn.send(f"CHALLENGE|{Bs}\n".encode())

        elif cmd == "OTP":
            DID, otp_recv, ec = parts[1], parts[2], int(parts[3])
            record = server_db.get(DID)
            if not record:
                conn.send(b"ERROR_UNKNOWN_DID\n")
                continue
            shared_secret = pow(g, record['ms'], q)
            otp_check = FOTP(shared_secret, ec)
            if otp_recv == otp_check:
                conn.send(b"AUTH_SUCCESS\n")
            else:
                conn.send(b"AUTH_fail\n")
    conn.close()

if __name__ == "__main__":
    run_server()
