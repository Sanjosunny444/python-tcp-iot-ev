def status_notification(content: bytes, device_info: dict):
    i = 2  # Start after head + cmd

    def dbg(field, size):
        nonlocal i
        raw = content[i:i+size]
        print(f"{field:<25} @[{i}:{i+size}] -> {raw.hex()}")
        return raw

    # Mode (1)
    raw = dbg("Mode", 1)
    device_info["Mode"] = "Normal" if raw[0] == 0x00 else "Maintain"
    i += 1

    # Speed (2)
    raw = dbg("Speed", 2)
    device_info["Speed"] = int.from_bytes(raw, 'little') * 0.1
    i += 2

    # Current (2) - unit 2mA
    raw = dbg("Current", 2)
    device_info["Current"] = int.from_bytes(raw, 'little') * 2
    i += 2

    # Voltage (2)
    raw = dbg("Voltage", 2)
    device_info["Voltage"] = (int.from_bytes(raw, 'little') * 2.5) / 1000
    i += 2

    # Battery level (1)
    raw = dbg("Battery level", 1)
    device_info["Battery level"] = raw[0]
    i += 1

    # backup battery level (1)
    raw = dbg("backup battery level", 1)
    device_info["backup battery level"] = raw[0]
    i += 1

    # Charging status (1)
    raw = dbg("Charging status", 1)
    device_info["Charging status"] = raw[0]
    i += 1

    # # Lock status (1)
    # raw = dbg("Lock status", 1)
    # lock_map = {0x00: "Locked", 0x01: "Unlocked", 0x02: "Pushed"}
    # device_info["Lock status"] = lock_map.get(raw[0], "Unknown")
    # i += 1

    # Total mileage (4)
    raw = dbg("Total mileage", 4)
    device_info["Total mileage"] = int.from_bytes(raw, 'little') * 0.1
    i += 4

    # Remaining mileage (4)
    raw = dbg("Remaining mileage", 4)
    device_info["Remaining mileage"] = int.from_bytes(raw, 'little') * 0.1
    i += 4

    # Latitude (4)
    raw = dbg("Latitude", 4)
    device_info["Latitude"] = int.from_bytes(raw, 'little', signed=True) * 0.0000001
    i += 4


    # Longitude (4)
    raw = dbg("Longitude", 4)
    device_info["Longitude"] = int.from_bytes(raw, 'little', signed=True) * 0.0000001
    i += 4



    # Location accuracy (2) - unit 1 meter
    raw = dbg("Location accuracy", 2)
    device_info["Location accuracy"] = int.from_bytes(raw, 'little')
    i += 2

    # Location signal (1)
    raw = dbg("Location signal", 1)
    device_info["Location signal"] = raw[0]
    i += 1

    # CSQ (1)
    raw = dbg("CSQ", 1)
    device_info["CSQ"] = raw[0]
    i += 1

    # Number of satellites (1)
    raw = dbg("Number of satellites", 1)
    device_info["Number of satellites"] = raw[0]
    i += 1

    # Chain lock connection status (1)
    raw = dbg("Chain lock connection", 1)
    device_info["Chain lock connection status"] = "Connected" if raw[0] == 0x01 else "Unconnected"
    i += 1

    # Chain lock status (1)
    raw = dbg("Chain lock status", 1)
    chain_lock_map = {0x00: "Locked", 0x01: "Unlocked", 0xFF: "Unknown"}
    device_info["Chain lock status"] = chain_lock_map.get(raw[0], f"Unknown (0x{raw[0]:02X})")
    i += 1

    # Chain lock battery level (1)
    raw = dbg("Chain lock battery", 1)
    device_info["Chain lock battery level"] = raw[0]
    i += 1

    # Chain lock signal (1)
    raw = dbg("Chain lock signal", 1)
    device_info["Chain lock signal"] = raw[0]
    i += 1

    # Battery lock connection status (1)
    raw = dbg("Battery lock connection", 1)
    device_info["Battery lock connection status"] = "Connected" if raw[0] == 0x01 else "Unconnected"
    i += 1

    # Battery lock status (1)
    raw = dbg("Battery lock status", 1)
    bat_lock_map = {0x00: "Locked", 0x01: "Unlocked", 0xFF: "Unknown"}
    device_info["Battery lock status"] = bat_lock_map.get(raw[0], f"Unknown (0x{raw[0]:02X})")
    i += 1

    # Battery lock battery level (1)
    raw = dbg("Battery lock battery", 1)
    device_info["Battery lock battery level"] = raw[0]
    i += 1

    # Battery lock signal (1)
    raw = dbg("Battery lock signal", 1)
    device_info["Battery lock signal"] = raw[0]
    i += 1

    # Alarm (1)
    raw = dbg("Alarm", 1)
    device_info["Alarm"] = raw[0]
    i += 1

    # Fault code (2)
    raw = dbg("Fault code", 2)
    device_info["Fault code"] = int.from_bytes(raw, 'little')
    i += 2

    print("\n✅ FINAL PARSED DATA:")
    for k, v in device_info.items():
        print(f"{k}: {v}")

    print(
        f"\n📊 Status: {device_info['Battery level']}% | "
        f"{device_info['Voltage']}V | CSQ: {device_info['CSQ']}"
    )

def auth_notification(content: bytes, device_info: dict, auth_values: dict):
    """CMD 0x04 - Authentication. First message sent after connection to verify client."""
    print("Received Authentication Packet")

    i = 2

    # ID (ASCII, up to 32 bytes, null-terminated)
    raw_block = content[i:i+32]

    end = raw_block.find(b'\x00')
    if end == -1:
        end = 32

    auth_id = raw_block[:end].decode(errors="ignore")

    print(f"ID RAW HEX: {raw_block.hex()}")
    print(f"ID LENGTH: {end}")

    i += end + 1  # move past the null terminator

    # Root key (16 bytes)
    root_key = content[i:i+16]

    print(f"ROOT START INDEX: {i}")

    print(f"ID: {auth_id}")

    # SECURITY: the root key is the AES master secret for this device.
    # It is deliberately NOT printed. The previous debug lines here dumped
    # `root_key.hex()` to stdout, which writes the master key into any log
    # file or console scrollback. Only the length is logged now; if you need
    # the real bytes while debugging, print them temporarily and never commit
    # that change.
    print(f"Root Key: <redacted, {len(root_key)} bytes>")

    auth_values["ID"] = auth_id
    auth_values["Root key"] = root_key

    return auth_id, root_key


def ota_result_notification(content: bytes):
    """CMD 0x02 - OTA result. Device uploads OTA upgrade result after restart."""
    print("Received OTA Result Notification")

    result = content[2]
    result_str = "Success" if result == 0x01 else "Failure"
    print(f"OTA Result: {result_str} (0x{result:02X})")

    return result


def device_info_notification(content: bytes, device_info: dict):
    """CMD 0x03 - Device information. Uploaded after each connection to identify device."""
    print("Received Device Information Notification")

    i = 2

    # IMSI (String, null-terminated)
    end = content.find(b'\x00', i)
    if end == -1:
        end = len(content)
    imsi = content[i:end].decode(errors="ignore")
    i = end + 1

    # ICCID (String, null-terminated)
    end = content.find(b'\x00', i)
    if end == -1:
        end = len(content)
    iccid = content[i:end].decode(errors="ignore")
    i = end + 1

    # IMEI (String, null-terminated)
    end = content.find(b'\x00', i)
    if end == -1:
        end = len(content)
    imei = content[i:end].decode(errors="ignore")
    i = end + 1

    # BLE MAC (6 bytes)
    ble_mac = content[i:i+6]
    ble_mac_str = ":".join(f"{b:02X}" for b in ble_mac)
    i += 6

    # Device type (1 byte)
    device_type_byte = content[i]
    device_type_map = {0x00: "Scooter", 0x01: "E-bike", 0x02: "Electric motorcycle"}
    device_type = device_type_map.get(device_type_byte, f"Unknown (0x{device_type_byte:02X})")
    i += 1

    device_info["IMSI"] = imsi
    device_info["ICCID"] = iccid
    device_info["IMEI"] = imei
    device_info["BLE MAC"] = ble_mac_str
    device_info["Device type"] = device_type

    print(f"IMSI: {imsi}")
    print(f"ICCID: {iccid}")
    print(f"IMEI: {imei}")
    print(f"BLE MAC: {ble_mac_str}")
    print(f"Device Type: {device_type}")

    return {"IMSI": imsi, "ICCID": iccid, "IMEI": imei, "BLE_MAC": ble_mac_str, "Device_type": device_type}


def ecu_ota_result_notification(content: bytes):
    """CMD 0x05 - ECU (motor driver) OTA result."""
    print("Received ECU OTA Result Notification")

    result = content[2]
    result_str = "Success" if result == 0x01 else "Failure"
    print(f"ECU OTA Result: {result_str} (0x{result:02X})")

    return result


def audio_ota_result_notification(content: bytes):
    """CMD 0x06 - Audio OTA result."""
    print("Received Audio OTA Result Notification")

    result = content[2]
    result_str = "Success" if result == 0x01 else "Failure"
    print(f"Audio OTA Result: {result_str} (0x{result:02X})")

    return result


def version_response(data: bytes, device_info: dict):
    """CMD 0x06 query response - Get version.
    Response data (after head+serial+result):
    CCU serial number     String 32
    CCU firmware version  String 32
    CCU hardware version  String 32
    ECU serial number     String 64
    ECU firmware version  String 32
    ECU hardware version  String 32
    Battery serial number String 64
    Battery firmware version String 32
    Battery hardware version String 32
    Battery information   Byte   23
    CCU information       Byte   16
    """
    print("Received Version Response")

    i = 0

    def read_string(length):
        nonlocal i
        raw = data[i:i+length]
        end = raw.find(b'\x00')
        if end == -1:
            end = length
        s = raw[:end].decode(errors="ignore")
        i += length
        return s

    def read_bytes(length):
        nonlocal i
        raw = data[i:i+length]
        i += length
        return raw

    device_info["CCU serial number"] = read_string(32)
    device_info["CCU firmware version"] = read_string(32)
    device_info["CCU hardware version"] = read_string(32)
    device_info["ECU serial number"] = read_string(64)
    device_info["ECU firmware version"] = read_string(32)
    device_info["ECU hardware version"] = read_string(32)
    device_info["Battery serial number"] = read_string(64)
    device_info["Battery firmware version"] = read_string(32)
    device_info["Battery hardware version"] = read_string(32)
    device_info["Battery information"] = read_bytes(23)
    device_info["CCU information"] = read_bytes(16)

    print(f"CCU Serial: {device_info['CCU serial number']}")
    print(f"CCU FW: {device_info['CCU firmware version']}")
    print(f"CCU HW: {device_info['CCU hardware version']}")
    print(f"ECU Serial: {device_info['ECU serial number']}")
    print(f"ECU FW: {device_info['ECU firmware version']}")
    print(f"ECU HW: {device_info['ECU hardware version']}")
    print(f"Battery Serial: {device_info['Battery serial number']}")
    print(f"Battery FW: {device_info['Battery firmware version']}")
    print(f"Battery HW: {device_info['Battery hardware version']}")
    print(f"Battery Info: {device_info['Battery information'].hex()}")
    print(f"CCU Info: {device_info['CCU information'].hex()}")


def query_parameter_response(data: bytes, device_info: dict):
    """CMD 0x10 query response - Query parameter.
    Response data (after head+serial+result):
    APN                    String  <36
    APN Username           String  <36
    APN Password           String  <36
    BLE name               String  <=20
    Heartbeat interval     BYTE    1   (unit: minutes, default 3)
    Unlock notify interval BYTE    4   (unit: seconds, default 10)
    Lock notify interval   BYTE    4   (unit: seconds, default 1800)
    Static automatic lock  BYTE    4   (unit: seconds, default 600)
    Vibration sensitivity  BYTE    1   (1-10, 0=off)
    Alarm tone times       BYTE    1   (1-120, 0=off, default 10)
    Chain lock BLE MAC     BYTE    6
    Chain lock BLE KEY     BYTE    16
    Battery lock BLE MAC   BYTE    6
    Battery lock BLE KEY   BYTE    16
    """
    print("Received Query Parameter Response")

    i = 0

    def read_string():
        """Read null-terminated string."""
        nonlocal i
        end = data.find(b'\x00', i)
        if end == -1:
            end = len(data)
        s = data[i:end].decode(errors="ignore")
        i = end + 1
        return s

    device_info["APN"] = read_string()
    device_info["APN Username"] = read_string()
    device_info["APN Password"] = read_string()
    device_info["BLE name"] = read_string()

    device_info["Heartbeat interval"] = data[i]
    i += 1

    device_info["Unlock notify interval"] = int.from_bytes(data[i:i+4], 'little')
    i += 4

    device_info["Lock notify interval"] = int.from_bytes(data[i:i+4], 'little')
    i += 4

    device_info["Static automatic lock"] = int.from_bytes(data[i:i+4], 'little')
    i += 4

    device_info["Vibration sensitivity"] = data[i]
    i += 1

    device_info["Alarm tone times"] = data[i]
    i += 1

    device_info["Chain lock BLE MAC"] = data[i:i+6]
    chain_mac_str = ":".join(f"{b:02X}" for b in data[i:i+6])
    i += 6

    device_info["Chain lock BLE KEY"] = data[i:i+16]
    i += 16

    device_info["Battery lock BLE MAC"] = data[i:i+6]
    bat_mac_str = ":".join(f"{b:02X}" for b in data[i:i+6])
    i += 6

    device_info["Battery lock BLE KEY"] = data[i:i+16]
    i += 16

    print(f"APN: {device_info['APN']}")
    print(f"APN Username: {device_info['APN Username']}")
    print(f"APN Password: {device_info['APN Password']}")
    print(f"BLE name: {device_info['BLE name']}")
    print(f"Heartbeat interval: {device_info['Heartbeat interval']} min")
    print(f"Unlock notify interval: {device_info['Unlock notify interval']} sec")
    print(f"Lock notify interval: {device_info['Lock notify interval']} sec")
    print(f"Static automatic lock: {device_info['Static automatic lock']} sec")
    print(f"Vibration sensitivity: {device_info['Vibration sensitivity']}")
    print(f"Alarm tone times: {device_info['Alarm tone times']}")
    print(f"Chain lock BLE MAC: {chain_mac_str}")
    print(f"Chain lock BLE KEY: {device_info['Chain lock BLE KEY'].hex()}")
    print(f"Battery lock BLE MAC: {bat_mac_str}")
    print(f"Battery lock BLE KEY: {device_info['Battery lock BLE KEY'].hex()}")