# SERVER-SIDE

# Install gmpy2 for large integer operations (depends on libgmp-dev)
sudo apt-get install libgmp-dev
pip install gmpy2

# Install pycrypto for cryptographic operations (hashing/random number generation)
pip install pycrypto

# Install WebSocket library (as specified in the document for protocol communication)
pip install websockets

# Server on
python hpotp_server.py


# DEVICE-SIDE
sudo apt-get install libgmp-dev
pip install gmpy2 pycrypto websockets
