# device_hp_otp.py
import gmpy2
import hashlib
import secrets
import websocket

q = gmpy2.next_prime(2**256)
g = 2

def H(data: str) -> int:
    digest = hashlib.sha256(data.encode()).hexdigest()
    return int(digest, 16) % q

def FOTP(shared_secret: int, ec: int) -> str:
    data = str(shared_secret) + str(ec)
    digest = hashlib.sha256(data.encode()).hexdigest()
    otp_int = int(digest, 16) % (10**6)
    return str(otp_int).zfill(6)

# Device initialization
DID = "device001"
pw = "testpassword"
kc = secrets.randbelow(q)
rc = secrets.randbelow(q)

# Registration phase
qc = H(pw + str(rc))
Ac = pow(g, qc * kc, q)
ws = websocket.create_connection("ws://localhost:9000")
ws.send(f"REGISTER|{DID}|{Ac}")
print(ws.recv())

# Verification phase
ws.send(f"CHALLENGE|{DID}")
response = ws.recv()
cmd, Bs_str = response.split('|')
Bs = int(Bs_str)

# User enters password pw'
pw_prime = input("Enter password: ")
qc_prime = H(pw_prime + str(rc))
inv = gmpy2.invert(qc_prime * kc, q)
Cs = pow(Bs, inv, q)

# OTP generation
ec = secrets.randbelow(q)
shared_secret = Cs  # equivalent to g^ms
otp = FOTP(shared_secret, ec)
print(f"Generated OTP: {otp}")

# Send OTP to server
ws.send(f"OTP|{DID}|{otp}|{ec}")
print(ws.recv())
ws.close()
