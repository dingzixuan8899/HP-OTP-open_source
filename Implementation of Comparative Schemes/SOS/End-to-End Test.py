def test_sos_protocol():
    # Initialize components
    sms_gateway = MockSMSGateway()
    server = SOSServer(server_domain="sms2fa.dev", sms_gateway=sms_gateway)
    device = SOSDevice(phone_number="+9876543210", sms_gateway=sms_gateway)
    username = "alice_user"
    password = "test_pass123"

    # ------------------------------ Test Registration ------------------------------
    print("\n=== REGISTRATION PHASE ===")
    # 1. Server starts registration
    reg_session_key = server.register_start(username, device.phone, password)

    # 2. Device receives KE1 and sends KE2
    device.receive_ke1()
    device.send_ke2(server.server_phone)

    # 3. Server processes KE2 and generates AUTH1 (for QR)
    auth1_str = server.register_process_ke2(reg_session_key)

    # 4. Client generates QR code (simulate user scanning it)
    generate_qr_code(auth1_str)

    # 5. Device scans QR → generates T2 (OTP)
    t2 = device.scan_qr_and_generate_t2(auth1_str)

    # 6. Server verifies T2 (simulate user inputting T2)
    server.register_verify_t2(reg_session_key, t2)

    # ------------------------------ Test Authentication ------------------------------
    print("\n=== AUTHENTICATION PHASE ===")
    # 1. Server starts authentication (after password check)
    auth_session_key = server.auth_start(username, password)

    # 2. Device receives W → generates OTP
    otp = device.receive_auth_w_and_generate_otp()

    # 3. Server verifies OTP (simulate user inputting OTP)
    auth_success = server.auth_verify_otp(auth_session_key, otp)

    print(f"\n=== Final Result: Authentication {'SUCCEEDED' if auth_success else 'FAILED'} ===")


if __name__ == "__main__":
    test_sos_protocol()