def test_gtotp_mt():
    # --------------------------
    # 1. RA Setup
    # --------------------------
    # Time parameters: Valid for 1 day (Ts = 1710000000, Te = Ts + 86400)
    Ts = 1710000000
    Te = Ts + 86400
    delta_e = 300  # 5 minutes per verify epoch
    delta_s = 5    # 5 seconds per password
    phi = 8        # 8 Merkle Trees
    ra = GTOTP_RA()
    pms = ra.setup(Ts=Ts, Te=Te, delta_e=delta_e, delta_s=delta_s, phi=phi)
    print("RA Setup Complete")

    # --------------------------
    # 2. Device Registration
    # --------------------------
    # Create 2 test devices
    device1 = GTOTP_Device(device_id="user_001")
    device2 = GTOTP_Device(device_id="user_002")

    # Devices run PInit and send VP lists to RA
    device1_vp_list = device1.p_init(ra_params=pms)
    device2_vp_list = device2.p_init(ra_params=pms)
    device_vp_dict = {
        "user_001": device1_vp_list,
        "user_002": device2_vp_list
    }
    print("Devices PInit Complete (VP Lists Sent to RA)")

    # --------------------------
    # 3. RA Generates GVST and Device Data
    # --------------------------
    vstG, device_data = ra.gvst_gen(device_vp_dict=device_vp_dict)
    
    # RA sends Ci lists and Merkle proofs to devices
    device1_ci_list, device1_proofs = device_data["user_001"]
    device2_ci_list, device2_proofs = device_data["user_002"]
    device1.receive_ra_data(ci_list=device1_ci_list, merkle_proofs=device1_proofs)
    device2.receive_ra_data(ci_list=device2_ci_list, merkle_proofs=device2_proofs)
    print("RA GVSTGen Complete (Ci/Proofs Sent to Devices)")

    # --------------------------
    # 4. Device Generates Password
    # --------------------------
    # Test time T: 100 seconds after Ts (inside epoch 0: Ts ≤ T < Ts+Δe)
    T = Ts + 100
    device1_password = device1.pw_gen(T=T, ra_params=pms)
    print(f"Device 1 Generated Password (pw: {device1_password[0].hex()[:10]}..., ci: {device1_password[1].hex()[:10]}...)")

    # --------------------------
    # 5. Verifier Checks Password
    # --------------------------
    verifier = GTOTP_Verifier(vstG=vstG, pms=pms)
    is_valid = verifier.verify(gt otp_pw=device1_password, T=T, pms=pms)
    print(f"Password Validation Result: {'Valid' if is_valid else 'Invalid'}")

    # --------------------------
    # 6. RA Traces Device Identity
    # --------------------------
    traced_id = ra.open(gt otp_pw=device1_password, T=T, vstG=vstG, verifier=verifier)
    print(f"Traced Device Identity: {traced_id} (Expected: user_001)")


if __name__ == "__main__":
    test_gtotp_mt()