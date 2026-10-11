import socket
import threading

# Packet structure: 0x5155 + length(2 LE) + content + CRC16(2)
# Content: head(1) + cmd(1) + message data
# CRC16 is calculated on content only (per spec section 2.4.2, Appendix 3)
# All multi-byte numeric values are little-endian (per spec section 2.3)
#
# SIGN-IN FLOW TEST ORDER:
#   Step 1: Send "1" (Auth Notification)    -> bridge sets signin=1
#   Step 2: Send "h" (Heartbeat)            -> bridge ignores (signin != 2)
#   Step 3: Send "0" (Status Notification)  -> bridge sends Q0 upstream, signin=2
#   Step 4: Send "h" (Heartbeat)            -> bridge sends H0 upstream
#   Step 5: Send "0" (Status Notification)  -> bridge sends H0 upstream

PACKETS = {
    "0": {
        "name": "Status Notification (CMD 0x00)",
        "hex": "5155"
              + "2D00"          # length: 45 LE
              + "0000"          # head=0x00, cmd=0x00
              + "00"            # Mode: 0x00 = Normal
              + "7B00"          # Speed: 123 LE (12.3 km/h)
              + "F401"          # Current: 500 LE (1000 mA)
              + "C012"          # Voltage: 4800 LE (12.0V)
              + "55"            # Battery level: 85%
              + "5A"            # Backup battery level: 90%
              + "01"            # Charging status: charging
              + "00"            # Lock status: locked
              + "40E20100"      # Total mileage: 123456 LE (12345.6 km)
              + "F8FF0000"      # Remaining mileage: 65528 LE (6552.8 km)
              + "15CD5B07"      # Latitude: 123456789 LE (12.3456789 deg)
              + "B168DE3A"      # Longitude: 987654321 LE (98.7654321 deg)
              + "0500"          # Location accuracy: 5m LE
              + "01"            # Location signal: GPS
              + "14"            # CSQ: 20
              + "0A"            # Number of satellites: 10
              + "01"            # Chain lock connection status: Connected
              + "00"            # Chain lock status: Locked
              + "64"            # Chain lock battery level: 100%
              + "50"            # Chain lock signal: 80
              + "00"            # Battery lock connection status: Unconnected
              + "FF"            # Battery lock status: Unknown
              + "FF"            # Battery lock battery level: Error
              + "FF"            # Battery lock signal: Error
              + "00"            # Alarm: None
              + "0000"          # Fault code: No fault LE
              + "F905",         # CRC16
    },
    "1": {
        "name": "Auth Notification (CMD 0x04)",
        "hex": "5155"
              + "2000"                              # length: 32 LE
              + "0004"                              # head=0x00, cmd=0x04
              + "4D59444556494345494431323300"      # ID: "MYDEVICEID123\0"
              + "00112233445566778899AABBCCDDEEFF"  # Root key: 16 bytes
              + "DEEB",                             # CRC16
    },
    "2": {
        "name": "OTA Result Notification (CMD 0x02)",
        "hex": "5155"
              + "0300"      # length: 3 LE
              + "000201"    # head=0x00, cmd=0x02, result=0x01 (success)
              + "B160",     # CRC16
    },
    "3": {
        "name": "Device Info Notification (CMD 0x03)",
        "hex": "5155"
              + "3900"                                  # length: 57 LE
              + "0003"                                  # head=0x00, cmd=0x03
              + "34363031313132333435363738393000"      # IMSI: "460111234567890\0"
              + "49434349443132333435363738393000"      # ICCID: "ICCID1234567890\0"
              + "38363637383930313233343536373800"      # IMEI: "866789012345678\0"
              + "112233445566"                          # BLE MAC: 6 bytes
              + "00"                                    # Device type: 0x00 = Scooter
              + "B97E",                                 # CRC16
    },
    "4": {
        "name": "ECU OTA Result (CMD 0x05)",
        "hex": "5155"
              + "0300"      # length: 3 LE
              + "000501"    # head=0x00, cmd=0x05, result=0x01 (success)
              + "B350",     # CRC16
    },
    "5": {
        "name": "Audio OTA Result (CMD 0x06)",
        "hex": "5155"
              + "0300"      # length: 3 LE
              + "000600"    # head=0x00, cmd=0x06, result=0x00 (failure)
              + "7260",     # CRC16
    },

    # === Query Responses (head=0x02) ===
    # These require matching serial numbers in pending_queries on the server.
    # Server pre-populates: {1: 0x05, 2: 0x06, 3: 0x10} for testing.

    "6": {
        "name": "Get Status Response (CMD 0x05, serial=1)",
        "hex": "5155"
              + "2F00"          # length: 47 LE
              + "02"            # head=0x02 (query response)
              + "0100"          # serial: 1 LE
              + "00"            # result: 0x00 = Success
              # Status data (same fields as 5.1.1)
              + "00"            # Mode: Normal
              + "7B00"          # Speed: 123 LE (12.3 km/h)
              + "F401"          # Current: 500 LE (1000 mA)
              + "C012"          # Voltage: 4800 LE (12.0V)
              + "55"            # Battery: 85%
              + "5A"            # Backup battery: 90%
              + "01"            # Charging: yes
              + "00"            # Lock: locked
              + "40E20100"      # Total mileage: 123456 LE
              + "F8FF0000"      # Remaining mileage: 65528 LE
              + "15CD5B07"      # Latitude: 123456789 LE
              + "B168DE3A"      # Longitude: 987654321 LE
              + "0500"          # Accuracy: 5m LE
              + "01"            # Signal: GPS
              + "14"            # CSQ: 20
              + "0A"            # Satellites: 10
              + "01"            # Chain lock conn: connected
              + "00"            # Chain lock status: locked
              + "64"            # Chain lock battery: 100%
              + "50"            # Chain lock signal: 80
              + "00"            # Battery lock conn: unconnected
              + "FF"            # Battery lock status: unknown
              + "FF"            # Battery lock battery: error
              + "FF"            # Battery lock signal: error
              + "00"            # Alarm: none
              + "0000"          # Fault code: none
              + "D52A",         # CRC16
    },
    "7": {
        "name": "Get Version Response (CMD 0x06, serial=2)",
        # 395 bytes content: head(02)+serial(0200)+result(00)
        # + CCU serial/fw/hw + ECU serial/fw/hw + BAT serial/fw/hw
        # + Battery info(23) + CCU info(16)
        "hex": "51558b01020200004343552d534e2d30303100000000000000000000000000000000000000000000312e302e3400000000000000000000000000000000000000000000000000000048572d322e3000000000000000000000000000000000000000000000000000004543552d534e2d3030310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004543552d46572d312e32000000000000000000000000000000000000000000004543552d48572d312e30000000000000000000000000000000000000000000004241542d534e2d3030310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004241542d46572d332e31000000000000000000000000000000000000000000004241542d48572d312e3000000000000000000000000000000000000000000000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBffd3",
    },
    "h": {
        "name": "Heartbeat (section 5.3, fixed packet)",
        "hex": "51550100" + "03" + "FF41",   # fixed heartbeat per spec
    },
    "8": {
        "name": "Query Parameter Response (CMD 0x10, serial=3)",
        "hex": "5155"
              + "6200"          # length: 98 LE
              + "02"            # head=0x02 (query response)
              + "0300"          # serial: 3 LE
              + "00"            # result: 0x00 = Success
              + "696E7465726E657400"      # APN: "internet\0"
              + "757365723100"            # APN Username: "user1\0"
              + "706173733100"            # APN Password: "pass1\0"
              + "4D7953636F6F746572424C4500"  # BLE name: "MyScooterBLE\0"
              + "03"                      # Heartbeat interval: 3 min
              + "0A000000"                # Unlock notify interval: 10 sec LE
              + "08070000"                # Lock notify interval: 1800 sec LE
              + "58020000"                # Static automatic lock: 600 sec LE
              + "05"                      # Vibration sensitivity: 5
              + "0A"                      # Alarm tone times: 10
              + "AABBCCDDEEFF"            # Chain lock BLE MAC
              + "00112233445566778899AABBCCDDEEFF00"  # Chain lock BLE KEY (16)
              + "112233445566"            # Battery lock BLE MAC
              + "FFEEDDCCBBAA99887766554433221100"    # Battery lock BLE KEY (16)
              + "D4BB",                   # CRC16
    },
    # === Device responses to bridge-initiated queries ===
    # Serial numbers start at 100 and increment per command.
    # After restart: S5 uses 100, S7 uses 100+101, S4 uses 102, etc.
    # Use the matching serial for whatever command was last sent.

    "9": {
        "name": "Success Response (serial=100)",
        "hex": "5155" + "0400" + "02" + "6400" + "00" + "4043",  # CRC verified
    },
    "a": {
        "name": "Success Response (serial=101)",
        "hex": "5155" + "0400" + "02" + "6500" + "00" + "1183",  # CRC verified
    },
    "b": {
        "name": "Success Response (serial=102)",
        "hex": "5155" + "0400" + "02" + "6600" + "00" + "E183",  # CRC verified
    },
    "f": {
        "name": "Status with FAULT (Alarm=1, Fault=0x0003 Overcurrent+LowVoltage)",
        "hex": "5155"
              + "2D00"
              + "0000"
              + "00" + "7B00" + "F401" + "C012"
              + "55" + "5A" + "01" + "00"
              + "40E20100" + "F8FF0000"
              + "15CD5B07" + "B168DE3A"
              + "0500" + "01" + "14" + "0A"
              + "01" + "00" + "64" + "50"
              + "00" + "FF" + "FF" + "FF"
              + "01"            # Alarm: 1 (vehicle moved)
              + "0300"          # Fault code: 0x0003 LE
              + "A835",         # CRC16 verified
    },

    # === AES ENCRYPTED TEST PACKETS ===
    # To test: set device_state["aes_enabled"] = True in pythonserver.py
    # Root key:    00112233445566778899AABBCCDDEEFF
    # Session key: AABBCCDDEEFF00112233445566778899

    "x": {
        "name": "[AES] Auth (contains encrypted session key)",
        "hex": "5155200000044d59444556494345494431323300cbbd4a2b34f2571758ff6a797e09859d27a2",
    },
    "y": {
        "name": "[AES] Encrypted Status Notification",
        "hex": "51552d00e2ea7901450ec416deaabf703337c4532897d502891a694c1c86e67cc89be5eea81c27170e5227089cc104ed36e18465",
    },
}

HOST = "192.168.1.2"
PORT = 9000

def receive_loop(sock):
    """Background thread: prints any data received from the bridge."""
    while True:
        try:
            data = sock.recv(2048)
            if not data:
                print("\n[RECV] Connection closed by bridge")
                break
            print(f"\n[RECV] {len(data)} bytes: {data.hex()}")
            # Try to parse DiLu packet structure
            if len(data) >= 4 and data[0:2] == b'\x51\x55':
                length = int.from_bytes(data[2:4], 'little')
                content = data[4:4+length]
                if len(content) >= 4 and content[0] == 0x01:
                    serial = int.from_bytes(content[1:3], 'little')
                    cmd = content[3]
                    print(f"[RECV] DiLu Query: head=0x01, serial={serial}, cmd=0x{cmd:02X}")
                    print(f"[RECV] Payload ({len(content)-4} bytes): {content[4:].hex()}")
            print("> ", end="", flush=True)  # reprint prompt
        except OSError:
            break


def main():
    s = socket.socket()
    s.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # Start background receiver thread
    rx = threading.Thread(target=receive_loop, args=(s,), daemon=True)
    rx.start()

    try:
        while True:
            print("\n--- Test Menu ---")
            for key, pkt in PACKETS.items():
                print(f"  {key}: {pkt['name']}")
            print("  q: Quit")

            choice = input("> ").strip()

            if choice == 'q':
                print("Bye")
                break
            elif choice in PACKETS:
                pkt = PACKETS[choice]
                print(f"Sending: {pkt['name']}")
                try:
                    data = bytes.fromhex(pkt["hex"])
                    s.sendall(data)
                    print(f"Sent {len(data)} bytes: {data.hex()}")
                except Exception as e:
                    print(f"Error: {e}")
                    break
            else:
                print(f"Unknown option: {choice}")
    finally:
        s.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()
