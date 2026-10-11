# This script implements a TCP server that listens for connections from IoT devices, processes incoming data, and forwards it to an upstream server.
# It also handles responses from the upstream server and sends them back to the respective devices.
# The script uses asyncio for asynchronous I/O operations, allowing it to manage multiple device connections concurrently.
# IOT device -> (TCP packet) -> TCP Server -> (TCP packet) -> Upstream Server
# Upstream Server -> (TCP packet) -> TCP Server -> (TCP packet) -> IOT device
# when a device is connected it should act as a device to server. some requests are responded by the bridge itself

import asyncio
from shared import calculate_crc16
from aes_handler import decrypt_packet_payload, encrypt_packet_payload, decrypt_session_key, calc_encrypted_size, build_encrypted_packet
from from_device import (
    auth_notification,
    status_notification,
    ota_result_notification,
    device_info_notification,
    ecu_ota_result_notification,
    audio_ota_result_notification,
    version_response,
    query_parameter_response,
)
from to_server import build_h0_heartbeat, build_s6_scooter_info, build_d0_positioning, build_g0_firmware_version, build_e0_fault_code, build_i0_iccid, build_m0_ble_mac

from to_device import handle_s5, handle_s7, handle_s4, handle_v0, handle_g0, handle_s1, handle_r0, handle_l0, handle_l1, handle_l5
from helpers import maybe_send_q0_or_h0
from datetime import datetime

# ==========================================================
# CONFIGURATION
# ==========================================================

# Source-IP allowlist for incoming device connections.
# NOTE: these are example addresses -- put your own device/test IPs here.
# This set is only consulted if the check in handle_client() is enabled;
# see the SECURITY note there.
ALLOWED_DEVICES = {
    "192.168.1.2",
    "192.168.1.6",
    "127.0.0.1"
}

# Upstream (Omni) server the bridge relays to.
# NOTE: set to a placeholder for publication -- replace with your own
# upstream host/port before running. Do not commit a real deployment
# endpoint to a public repo.
UPSTREAM_HOST = "upstream.example.com"
UPSTREAM_PORT = 7072

DEVICE_SERVER_HOST = "0.0.0.0"
DEVICE_SERVER_PORT = 9000


# ==========================================================
# DEVICE → SERVER PROCESSING
# ==========================================================


def maybe_encrypt_packet(packet: bytes, device_state: dict) -> bytes:
    """
    If AES is enabled, re-encrypt a plaintext DiLu packet.
    The packet from to_device.py is built plaintext (5155+len+content+CRC).
    We need to re-wrap it with encrypted content+CRC.
    """
    if not device_state.get("aes_enabled") or not device_state.get("session_key"):
        return packet  # plaintext mode, send as-is

    # Parse the plaintext packet
    if len(packet) < 6 or packet[0:2] != b'\x51\x55':
        return packet
    content_len = int.from_bytes(packet[2:4], 'little')
    content = packet[4:4 + content_len]

    # Re-build with encryption
    return build_encrypted_packet(content, device_state["session_key"])


from datetime import datetime

def process_device_data(content: bytes, device_info: dict, auth_values: dict, device_state: dict):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n[{timestamp}] Full Content: {content.hex()}")

        # Heartbeat packet (section 5.3): fixed data is a single 0x03 content byte.
        # Only forward as Omni H0 if sign-in fully complete and Q0 already sent.
        if content == b'\x03':
            if device_state.get("q0_sent"):
                print(f"[{timestamp}] [HEARTBEAT] DiLu heartbeat received; sending H0 upstream")
                return "FORWARD_TRANSLATED", build_h0_heartbeat(device_info)

            print(f"[{timestamp}] [HEARTBEAT] Ignored (Q0 not yet sent, waiting for auth+info+status)")
            return "NONE", None

        if len(content) < 2:
            print(f"[{timestamp}] Content too short to parse: {content.hex()}")
            return "NONE", None

        head = content[0]

        if head == 0x00:
            # Notification messages (device -> server, no response needed)
            # Structure: head(0x00) + cmd(1) + message
            cmd = content[1]

            print(f"[{timestamp}] Head: {head:02X}, CMD: {cmd:02X}, Length: {len(content)}")

            if cmd == 0x00:
                old_fault = device_state.get("last_fault_code", 0)

                status_notification(content, device_info)

                device_state["status_received"] = True

                new_fault = device_info.get("Fault code", 0)

                # Detect fault code change: send E0 upstream if fault appeared
                if new_fault != 0 and new_fault != old_fault:
                    device_state["last_fault_code"] = new_fault

                    # Send E0 first, then Q0/H0
                    e0_msg = build_e0_fault_code(device_info)

                    q0_h0_action, q0_h0_msg = maybe_send_q0_or_h0(device_info, device_state)

                    if q0_h0_msg:
                        return "FORWARD_TRANSLATED", e0_msg + q0_h0_msg

                    return "FORWARD_TRANSLATED", e0_msg

                elif new_fault == 0 and old_fault != 0:
                    device_state["last_fault_code"] = 0

                return maybe_send_q0_or_h0(device_info, device_state)

            elif cmd == 0x02:
                ota_result_notification(content)

            elif cmd == 0x03:
                device_info_notification(content, device_info)

                device_state["info_received"] = True

                # If auth + status already arrived, this info completes the set
                # and we can now send Q0 with the real IMEI.
                if device_state.get("status_received"):
                    return maybe_send_q0_or_h0(device_info, device_state)

            elif cmd == 0x04:
                auth_notification(content, device_info, auth_values)

                device_state["auth_received"] = True

                # If AES enabled, the root_key field in auth is the
                # encrypted session key. Decrypt it with known root key.
                if device_state.get("aes_enabled"):

                    encrypted_sk = auth_values.get("Root key", b"")

                    if len(encrypted_sk) == 16:

                        root_key = device_state.get("root_key", b"\x00" * 16)

                        device_state["session_key"] = decrypt_session_key(
                            encrypted_sk,
                            root_key
                        )

                        print(
                            f"[{timestamp}] [AES] Session key decrypted: "
                            f"{device_state['session_key'].hex()}"
                        )

                    else:
                        print(
                            f"[{timestamp}] [AES] WARNING: root key field is "
                            f"{len(encrypted_sk)} bytes, expected 16"
                        )

                print(f"[{timestamp}] [AUTH] Auth received; waiting for Device Info + Status to send Q0")

                # If info + status already arrived, this auth completes the set.
                if device_state.get("status_received"):
                    return maybe_send_q0_or_h0(device_info, device_state)

            elif cmd == 0x05:
                ecu_ota_result_notification(content)

            elif cmd == 0x06:
                audio_ota_result_notification(content)

            else:
                print(f"[{timestamp}] Unknown notification CMD 0x{cmd:02X}: {content.hex()}")

        elif head == 0x02:
            # Query response messages (device -> server)
            # Table 4: head(0x02) + serial(2) + result(1) + response(data length - 4)

            serial = int.from_bytes(content[1:3], 'little')

            result = content[3]

            response_data = content[4:]

            result_map = {
                0x00: "Success",
                0x01: "General fault",
                0x02: "Length fault",
                0x03: "Command fault",
                0x04: "CRC fault"
            }

            print(
                f"[{timestamp}] Query Response: "
                f"serial={serial}, "
                f"result={result_map.get(result, f'0x{result:02X}')}"
            )

            # Look up which command this serial belongs to (by name)
            cmd_name = device_state["pending_queries"].pop(serial, None)

            if cmd_name is not None and result == 0x00:

                if cmd_name == "get_status":

                    # Same layout as notification status; reuse the parser
                    fake_content = b'\x00\x00' + response_data

                    status_notification(fake_content, device_info)

                elif cmd_name in ("get_version", "get_version_for_g0"):

                    version_response(response_data, device_info)

                    # If there's a pending G0 request from upstream, send G0 now
                    if device_state.get("g0_lock_id"):

                        g0_msg = build_g0_firmware_version(device_info)

                        device_state.pop("g0_lock_id", None)

                        print(f"[{timestamp}] [G0] Device version received, forwarding G0 to server")

                        return "FORWARD_TRANSLATED", g0_msg

                elif cmd_name == "query_parameter":

                    query_parameter_response(response_data, device_info)

                elif cmd_name == "set_parameter":

                    print(f"[{timestamp}] [0x11] Setting parameters applied on device")

                elif cmd_name == "headlight_control":

                    print(f"[{timestamp}] [0x03] Headlight control applied on device")

                elif cmd_name == "set_speed_limit":

                    print(f"[{timestamp}] [0x07] Speed limit applied on device")

                elif cmd_name == "audio_control":

                    print(f"[{timestamp}] [0x0C] Audio control applied on device")

                elif cmd_name == "restart":

                    print(f"[{timestamp}] [0x00] Device restart confirmed")

                elif cmd_name == "unlock_motor":

                    # DiLu 0x02 unlock response — send L0 result to server
                    user_id = device_state.get("l0_user_id", "0")
                    timestamp = device_state.get("l0_timestamp", "0")
                    #lid = device_state.get("l0_lock_id", lock_id if 'lock_id' in dir() else "000000000000000")
                    status = "0" if result == 0x00 else "1"

                    l0_resp = (
                        f"*SCOR,OM,"
                        f"{device_info.get('IMEI','000000000000000')},"
                        f"L0,{status},{user_id},{timestamp2}#\n"
                    )

                    print(f"[{timestamp}] [L0] Unlock result: {status} (0=success, 1=fail)")

                    return "FORWARD_TRANSLATED", l0_resp.encode("ascii")

                elif cmd_name == "lock_motor":

                    # DiLu 0x02 lock response — send L1 result to server
                    user_id = device_state.get("r0_user_id", "0")

                    timestamp2 = device_state.get("r0_timestamp", "0")

                    status = "0" if result == 0x00 else "1"
                    l1_resp = f"*SCOR,OM,{device_info.get('IMEI','000000000000000')},L1,{status},{user_id},{timestamp},0#\n"
                    print(f"[L1] Lock result: {status} (0=success, 1=fail)")
                    return "FORWARD_TRANSLATED", l1_resp.encode("ascii")

                elif cmd_name in (
                    "unlock_battery",
                    "lock_battery",
                    "unlock_chain",
                    "lock_chain"
                ):

                    # L5 external lock response — send L5 result to server
                    op = device_state.get("l5_operation", 0)
                    lid = device_state.get("l5_lock_id", device_info.get("IMEI", "000000000000000"))
                    res = 0 if result == 0x00 else 1

                    l5_resp = f"*SCOR,OM,{lid},L5,{op},{res}#\n"

                    print(f"[{timestamp}] [L5] {cmd_name} result: {res} (0=success, 1=fail)")

                    return "FORWARD_TRANSLATED", l5_resp.encode("ascii")

                else:
                    print(f"[{timestamp}] Unhandled query response '{cmd_name}': {response_data.hex()}")

            elif cmd_name is None:
                print(f"[{timestamp}] No pending query for serial {serial}")

        else:
            print(f"[{timestamp}] Unknown HEAD 0x{head:02X}: {content.hex()}")

    except Exception as e:
        print(f"[{timestamp}] Error Parsing Binary Content: {e}")
        print(f"[{timestamp}] Raw Hex: {content.hex()}")

    # Default: do nothing. Only translated Q0/H0 (via FORWARD_TRANSLATED)
    # are forwarded upstream. Raw DiLu binary is never sent to the Omni server.
    return "NONE", None
# ===========================================================
# SERVER → DEVICE PROCESSING
# ==========================================================

def process_server_data(data: bytes, device_info: dict, device_state: dict, scooter_settings: dict):
    """
    Parses data from the Upstream Server (Omni protocol).
    Format: 0xFFFF + *SCOS,OM,<IMEI>,<TYPE>,<args>#<LF>

    Translates supported Omni commands into DiLu binary packets and sends
    them to the device. Unsupported commands are logged and dropped.
    """
    print(f"🔍 Raw Server Data (Hex): {data.hex()}")

    # 1. Check for 0xFFFF prefix — real server may or may not send it
    if len(data) < 3:
        print("⚠ Server data too short — dropping")
        return "NONE", None

    # 2. Strip the 0xFFFF prefix if present, otherwise use as-is
    if data[0:2] == b'\xff\xff':
        text = data[2:].decode("ascii", errors="ignore").split("#")[0]
    else:
        text = data.decode("ascii", errors="ignore").split("#")[0]
    parts = text.split(",")
    if len(parts) < 4:
        print(f"⚠ Not enough fields in server message: {parts}")
        return "NONE", None

    cmd_header  = parts[0]    # *SCOS
    vendor_code = parts[1]    # OM
    lock_id     = parts[2]    # IMEI
    inst_type   = parts[3]    # S5, R0, L0, ...
    args        = parts[4:]

    print("--- 📋 Parsed Server Instruction ---")
    print(f"🔹 Command:  {cmd_header}")
    print(f"🔹 Vendor:   {vendor_code}")
    print(f"🔹 Lock ID:  {lock_id}")
    print(f"🔹 Type:     {inst_type}")
    print(f"🔹 Args:     {args}")
    print("------------------------------------")

    # --- Translators ---

    if inst_type == "R0":
        return handle_r0(args, lock_id, device_state)

    if inst_type == "L0":
        return handle_l0(args, lock_id, device_state)

    if inst_type == "L1":
        return handle_l1(args, lock_id, device_state)

    if inst_type == "L5":
        return handle_l5(args, lock_id, device_info, device_state)

    if inst_type == "S5":
        return handle_s5(args, lock_id, device_info, device_state)

    if inst_type == "S7":
        return handle_s7(args, lock_id, scooter_settings, device_state)

    if inst_type == "S4":
        return handle_s4(args, lock_id, scooter_settings, device_state)

    if inst_type == "S6":
        # S6 doesn't query the device — we already have all data cached.
        return "RESPOND_TO_SERVER", build_s6_scooter_info(device_info, scooter_settings)

    if inst_type == "V0":
        return handle_v0(args, lock_id, device_state)

    if inst_type == "D0":
        # D0 doesn't query the device — GPS data is cached from status notifications.
        return "RESPOND_TO_SERVER", build_d0_positioning(device_info)

    if inst_type == "G0":
        # G0 must query the device — sends DiLu 0x06, waits for response,
        # then builds G0 and sends to server when response arrives.
        return handle_g0(lock_id, device_state)

    if inst_type == "S1":
        return handle_s1(args, lock_id, device_state)

    if inst_type == "I0":
        # I0 responds from cache — ICCID from Device Info (CMD 0x03)
        return "RESPOND_TO_SERVER", build_i0_iccid(device_info)

    if inst_type == "M0":
        # M0 responds from cache — BLE MAC from Device Info (CMD 0x03)
        return "RESPOND_TO_SERVER", build_m0_ble_mac(device_info)

    if inst_type == "D1":
        # D1 sets tracking interval. D0 (identifier=1) will be sent with every H0.
        # interval=0 stops tracking.
        try:
            interval = int(args[0]) if len(args) > 0 else 0
        except ValueError:
            interval = 0
        device_state["d1_interval"] = interval
        if interval > 0:
            print(f"[D1] Tracking enabled: D0 will be sent with every H0")
        else:
            print(f"[D1] Tracking disabled")
        d1_echo = f"*SCOR,OM,{lock_id},D1,{interval}#\n"
        return "RESPOND_TO_SERVER", d1_echo.encode("ascii")

    if inst_type == "E0":
        # Server acknowledges our E0 fault upload — just log it.
        print(f"[E0] Server acknowledged fault code for {lock_id}")
        return "NONE", None

    print(f"⚠ No translator for instruction type '{inst_type}' — ignored")
    return "NONE", None


# ==========================================================
# MAIN CONNECTION HANDLER (PER DEVICE SESSION)
# ==========================================================

async def handle_client(device_reader: asyncio.StreamReader,
                        device_writer: asyncio.StreamWriter):

    addr = device_writer.get_extra_info("peername")
    ip = addr[0]

    # SECURITY — UNAUTHENTICATED LISTENER (must be fixed before production)
    #
    # The source-IP check below is commented out, so this server accepts a
    # TCP connection from ANY host on DEVICE_SERVER_PORT and will relay its
    # traffic upstream. There is no other peer authentication in the bridge:
    # the DiLu auth packet carries a device-supplied ID and root key, and a
    # failed match is logged rather than enforced.
    #
    # It was disabled to make field/lab testing easier (devices connect from
    # changing carrier IPs, so a static allowlist kept rejecting them).
    #
    # Before exposing this on a public interface, either re-enable the check
    # with the real device IPs in ALLOWED_DEVICES, or front it with a
    # firewall / VPN / APN-private network so only provisioned SIMs can
    # reach the port.
    #
    # if ip not in ALLOWED_DEVICES:
    #     print(f"❌ Rejected connection from {ip}")
    #     device_writer.close()
    #     await device_writer.wait_closed()
    #     return

    print(f"✅ Device connected: {addr}")

    device_info = {
    # Device information (5.1.4)
    "IMSI": "Unknown",
    "ICCID": "Unknown",
    "IMEI": "Unknown",
    "BLE MAC": "Unknown",
    "Device type": "Unknown",

    # Status (5.1.1)
    "Mode": "Unknown",
    "Speed": 0.0,
    "Current": 0,
    "Voltage": 0.0,
    "Battery level": 0,
    "backup battery level": 0,
    "Charging status": 0,
    "Lock status": 0,
    "Total mileage": 0.0,
    "Remaining mileage": 0.0,

    # Location
    "Latitude": 0.0,
    "Longitude": 0.0,
    "Location accuracy": 0,
    "Location signal": 0,
    "CSQ": 0,
    "Number of satellites": 0,

    # Peripheral Status
    "Chain lock connection status": "Unconnected",
    "Chain lock status": 0,
    "Chain lock battery level": 0,
    "Chain lock signal": 0,
    "Battery lock connection status": "Unconnected",
    "Battery lock status": 0,
    "Battery lock battery level": 0,
    "Battery lock signal": 0,

    # Health
    "Alarm": 0,
    "Fault code": "0000",

    # Version (5.2.7 Get version - query response)
    "CCU serial number": "Unknown",
    "CCU firmware version": "Unknown",
    "CCU hardware version": "Unknown",
    "ECU serial number": "Unknown",
    "ECU firmware version": "Unknown",
    "ECU hardware version": "Unknown",
    "Battery serial number": "Unknown",
    "Battery firmware version": "Unknown",
    "Battery hardware version": "Unknown",
    "Battery information": b"",
    "CCU information": b"",

    # Parameters (5.2.15 Query parameter - query response)
    "APN": "",
    "APN Username": "",
    "APN Password": "",
    "BLE name": "",
    "Heartbeat interval": 3,
    "Unlock notify interval": 10,
    "Lock notify interval": 1800,
    "Static automatic lock": 600,
    "Vibration sensitivity": 0,
    "Alarm tone times": 10,
    "Chain lock BLE MAC": b"",
    "Chain lock BLE KEY": b"",
    "Battery lock BLE MAC": b"",
    "Battery lock BLE KEY": b"",
    }
    auth_values = {
    "ID": "",          # ASCII string (<= 32 chars)
    "Root key": b""    # 16-byte value (bytes) //just for testing purpose, in real case we will test using the session key
    }

    # Scooter settings cache — tracks current ride configuration.
    # Updated when S7/S4 arrive from server. Used to build DiLu 0x03/0x07.
    #
    # Mode mapping (Omni -> DiLu):
    #   Omni 1=low, 2=medium  ->  DiLu 0x00 (soft)
    #   Omni 3=high           ->  DiLu 0x01 (sport)
    #
    # Speed limit defaults per spec section 5.2.8: sport mode, 25km/h
    scooter_settings = {
        # S7 fields (temporary, not saved after power off)
        "Headlight": 1,         # 1=off, 2=on (default off)
        "Mode": 2,              # 1=low, 2=medium, 3=high (default medium)
        "Throttle response": 2, # 1=off, 2=on (default on)
        "Taillights": 1,        # 1=off, 2=on (default off)

        # S4 fields (persistent)
        "Low speed limit": 15,      # km/h (default per Omni doc)
        "Medium speed limit": 20,   # km/h
        "High speed limit": 25,     # km/h

        # DiLu 0x07 computed values (what we actually send to device)
        "DiLu mode": 0x00,          # 0x00=soft, 0x01=sport
        "DiLu speed limit": 25,     # km/h to send in 0x07
    }
    # Per-connection state: sign-in flags and pending query lookup by name.
    # Q0 is sent upstream after all three events have occurred (any order):
    #   auth_received  - device sent authentication (CMD 0x04)
    #   info_received  - device sent device info (CMD 0x03)
    #   status_received - device sent status notification (CMD 0x00)
    # Once Q0 is sent (q0_sent=True), all subsequent status/heartbeat
    # packets from the device are translated to H0 upstream.
    #
    # pending_queries is pre-populated for testing (remove in production).
    device_state = {
        "auth_received": False,
        "info_received": False,
        "status_received": False,
        "q0_sent": False,
        "d1_interval": 0,     # D1 tracking interval (0=off, >0=send D0 with H0)
        "next_serial": 100,   # next serial for bridge-initiated queries
        "pending_queries": {
            1: "get_status",
            2: "get_version",
            3: "query_parameter",
        },
        # AES encryption (section 4.3)
        # Set aes_enabled to True to enable AES-128-ECB encryption/decryption.
        # root_key: pre-configured known root key for the device.
        #
        # SECURITY: the value below is the SAME dummy key used by the test
        # fixture in "doc and test/test.py" -- it is a placeholder, not a
        # secret. Leaving it in place means AES gives no real protection,
        # since the key is public in this repo. For production, load the
        # per-device root key from provisioning data (env var / config file /
        # key store) and keep it out of version control.
        # session_key: populated from auth if AES mode.
        "aes_enabled": False,       # hardcoded for now, toggle to True for AES devices
        "root_key": b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",  # PLACEHOLDER dummy key -- replace per device, see SECURITY note above
        "session_key": b"",
    }
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            UPSTREAM_HOST,
            UPSTREAM_PORT
        )
        print(f"🔗 Connected to upstream {UPSTREAM_HOST}:{UPSTREAM_PORT} for device {addr}")

    except Exception as e:
        print(f"❌ Upstream connection failed: {e}")
        device_writer.close()
        await device_writer.wait_closed()
        return


    # ------------------------------------------------------
    # DEVICE → SERVER
    # ------------------------------------------------------
    async def device_to_server():
        try:
            while True:
                # 1. Read raw data from the device
                data = await device_reader.read(2048)
                if not data:
                    break

                print(f"📥 Raw Device Packet: {data.hex()}")

                # 2. Protocol Check: Start Code 0x51 0x55
                if len(data) >= 6 and data[0:2] == b'\x51\x55':
                    # 3. Extract Length (Bytes 2 & 3, Little-Endian)
                    #    Length = original content size BEFORE encryption
                    content_len = int.from_bytes(data[2:4], byteorder='little')

                    # 4. Extract Content and CRC
                    if device_state.get("aes_enabled") and device_state.get("session_key"):
                        # AES mode: read encrypted block, decrypt, extract content+CRC
                        enc_size = calc_encrypted_size(content_len)
                        encrypted_block = data[4 : 4 + enc_size]
                        if len(encrypted_block) < enc_size:
                            print(f"⚠ Encrypted block too short: {len(encrypted_block)} < {enc_size}")
                            continue
                        content, received_crc = decrypt_packet_payload(
                            encrypted_block, content_len, device_state["session_key"]
                        )
                        print(f"[AES] Decrypted content ({content_len}B): {content.hex()}")
                    else:
                        # Plaintext mode: content + CRC directly in packet
                        content = data[4 : 4 + content_len]
                        received_crc = data[4 + content_len : 6 + content_len]

                    # 5. Verify CRC (per spec section 2.4.2: CRC on content only)
                    calculated_crc = calculate_crc16(content)
                    if len(received_crc) < 2 or received_crc == calculated_crc:

                        # 6. Pass ONLY the clean content to processing
                        action, out = process_device_data(content, device_info, auth_values, device_state)

                        # Logic for forwarding/responding.
                        # Only translated Omni messages (Q0/H0) are forwarded upstream.
                        # Raw DiLu binary is never sent to the Omni server.
                        if action == "FORWARD_TRANSLATED" and out:
                            upstream_writer.write(out)
                            await upstream_writer.drain()
                        elif action == "RESPOND_TO_DEVICE" and out:
                            device_writer.write(out)
                            await device_writer.drain()
                    else:
                        print(f"❌ CRC Error: Calculated {calculated_crc.hex()} != Received {received_crc.hex()}")

                else:
                    # Doesn't match the 5155 DiLu protocol — drop it.
                    # Only Omni-translated messages are forwarded upstream.
                    print(f"⚠ Non-protocol data dropped: {data.hex()}")

        except Exception as e:
            print(f"⚠ Device Task Error: {e}")
    # ------------------------------------------------------
    # SERVER → DEVICE
    # ------------------------------------------------------
    async def server_to_device():
        try:
            while True:
                data = await upstream_reader.read(2048)
                if not data:
                    break

                print(f"📥 Server → Bridge: {data.hex()}")

                # Pass to parsing logic (needs device_info for current params
                # and device_state to track serial numbers)
                action, out = process_server_data(data, device_info, device_state, scooter_settings)

                if action == "FORWARD_TO_DEVICE" and out:
                    device_writer.write(maybe_encrypt_packet(out, device_state))
                    await device_writer.drain()
                elif action == "RESPOND_TO_SERVER" and out:
                    upstream_writer.write(out)
                    await upstream_writer.drain()
                elif action == "FORWARD_BOTH" and out:
                    # Send translated packet to device AND echo to server
                    if out.get("to_device"):
                        device_writer.write(maybe_encrypt_packet(out["to_device"], device_state))
                        print(f"📤 Forwarding to device: {out['to_device'].hex()}")
                        await device_writer.drain()
                    if out.get("to_server"):
                        upstream_writer.write(out["to_server"])
                        print(f"📤 Forwarding to server: {out['to_server'].hex()}")
                        await upstream_writer.drain()

        except Exception as e:
            print(f"⚠ Server read error: {e}")


    # ------------------------------------------------------
    # PERIODIC TASKS — H0 HEARTBEAT + D1 GPS TRACKING
    # ------------------------------------------------------
    H0_INTERVAL = 180  # 30 seconds for testing (change to 240 for production)

    async def periodic_upstream_loop():
        """
        Sends periodic messages to upstream server:
        - H0 heartbeat every H0_INTERVAL seconds (once signed in)
        - D0 tracking every d1_interval seconds (when D1 is active)
        """
        last_h0_time = 0
        last_d0_time = 0
        try:
            while True:
                now = asyncio.get_event_loop().time()

                if device_state.get("q0_sent"):
                    # H0 heartbeat
                    if now - last_h0_time >= H0_INTERVAL:
                        h0 = build_h0_heartbeat(device_info)
                        upstream_writer.write(h0)
                        await upstream_writer.drain()
                        print(f"[PERIODIC] H0 heartbeat sent (every {H0_INTERVAL}s)")
                        last_h0_time = now

                    # D1 tracking
                    d1_interval = device_state.get("d1_interval", 0)
                    if d1_interval > 0 and now - last_d0_time >= d1_interval:
                        d0 = build_d0_positioning(device_info, identifier=1)
                        upstream_writer.write(d0)
                        await upstream_writer.drain()
                        print(f"[PERIODIC] D1 tracking D0 sent (every {d1_interval}s)")
                        last_d0_time = now

                # Check every 5 seconds
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"⚠ Periodic Task Error: {e}")


    # ------------------------------------------------------
    # PARALLEL EXECUTION
    # ------------------------------------------------------
    task1 = asyncio.create_task(device_to_server())
    task2 = asyncio.create_task(server_to_device())
    task3 = asyncio.create_task(periodic_upstream_loop())

    done, pending = await asyncio.wait(
        [task1, task2, task3],
        return_when=asyncio.FIRST_COMPLETED
    )

    for task in pending:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    print(f"🔌 Device disconnected: {addr}")
    device_writer.close()
    upstream_writer.close()
    await device_writer.wait_closed()
    await upstream_writer.wait_closed()


# ==========================================================
# MAIN SERVER
# ==========================================================

async def main():
    server = await asyncio.start_server(
        handle_client,
        DEVICE_SERVER_HOST,
        DEVICE_SERVER_PORT
    )
    print(f"🚀 Bridge server running on port {DEVICE_SERVER_PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())