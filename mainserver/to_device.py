"""
Translators that build DiLu binary commands from Omni server instructions.

When the upstream Omni server sends *SCOS,OM,<imei>,<type>,<args>#
the bridge translates it into the corresponding DiLu binary packet
and sends it to the device.

Per DiLu spec section 2.4 — packet structure:
    0x51 0x55 + length(2 LE) + content + CRC16(2)

Query request structure (section 5.2, Table 3):
    head(0x01) + serial(2 LE) + cmd(1) + request data
"""

from shared import calculate_crc16


def _wrap_packet(content: bytes) -> bytes:
    """Wrap content in DiLu protocol packet: 0x5155 + length(LE) + content + CRC."""
    length = len(content).to_bytes(2, "little")
    crc = calculate_crc16(content)
    return b"\x51\x55" + length + content + crc


def _pad_bytes(value, size: int) -> bytes:
    """Ensure value is exactly `size` bytes (pad with 0x00 or truncate)."""
    if value is None:
        return b"\x00" * size
    b = bytes(value)
    if len(b) >= size:
        return b[:size]
    return b + b"\x00" * (size - len(b))


# ---------------------------------------------------------------------------
# S5 -> 0x11 (Setting parameters)
# ---------------------------------------------------------------------------

# Map Omni S5 accelerometer sensitivity (0-3) to DiLu vibration sensitivity (0-10).
# DiLu: 1=most sensitive, 10=least sensitive, 0=off.
SENSITIVITY_MAP = {
    0: None,    # invalid / don't set
    1: 10,      # low  sensitivity -> DiLu 10 (least sensitive)
    2: 6,       # mid              -> DiLu 6
    3: 3,       # high sensitivity -> DiLu 3 (most sensitive)
}


def build_setting_parameters_from_s5(
    s5_args: list,
    serial: int,
    current_params: dict,
) -> bytes:
    """
    Translate Omni S5 (IOT device settings) into a DiLu 0x11
    Setting parameters query.

    Omni S5 args (4 ints, 0 means "don't set"):
        [accelerometer_sensitivity, s6_upload_in_unlock,
         heartbeat_upload_interval_sec, s6_interval_in_unlock_sec]

    current_params: dict holding the last-known 0x11 parameter values from
    the device (populated via query_parameter_response). Fields here are
    kept unchanged when S5 says "don't set".

    Returns a fully-framed DiLu binary packet ready to send to the device.
    """
    # Parse S5 args (strings from comma split) with safe defaults
    try:
        accel = int(s5_args[0]) if len(s5_args) > 0 else 0
        s6_unlock_on = int(s5_args[1]) if len(s5_args) > 1 else 0
        hb_sec = int(s5_args[2]) if len(s5_args) > 2 else 0
        unlock_sec = int(s5_args[3]) if len(s5_args) > 3 else 0
    except ValueError:
        print(f"[S5->0x11] Invalid S5 args: {s5_args}")
        accel = s6_unlock_on = hb_sec = unlock_sec = 0

    # Start from last-known device params (so untouched fields stay as-is)
    apn        = current_params.get("APN", "")
    apn_user   = current_params.get("APN Username", "")
    apn_pass   = current_params.get("APN Password", "")
    ble_name   = current_params.get("BLE name", "")
    heartbeat  = current_params.get("Heartbeat interval", 3)
    unlock_iv  = current_params.get("Unlock notify interval", 10)
    lock_iv    = current_params.get("Lock notify interval", 1800)
    static_lk  = current_params.get("Static automatic lock", 600)
    vibration  = current_params.get("Vibration sensitivity", 0)
    alarm_tone = current_params.get("Alarm tone times", 10)
    chain_mac  = current_params.get("Chain lock BLE MAC", b"\x00" * 6)
    chain_key  = current_params.get("Chain lock BLE KEY", b"\x00" * 16)
    bat_mac    = current_params.get("Battery lock BLE MAC", b"\x00" * 6)
    bat_key    = current_params.get("Battery lock BLE KEY", b"\x00" * 16)

    # --- Apply S5 overrides ---

    # Accelerometer sensitivity -> Vibration sensitivity
    mapped = SENSITIVITY_MAP.get(accel)
    if mapped is not None:
        vibration = mapped
        print(f"[S5->0x11] Vibration sensitivity: {accel} -> {vibration}")

    # S6 upload in unlock (0=invalid, 1=off, 2=on)
    if s6_unlock_on == 1:           # shutdown
        unlock_iv = 0
        print("[S5->0x11] Unlock S6 upload disabled (unlock_iv=0)")
    elif s6_unlock_on == 2:         # open
        if unlock_iv == 0:
            unlock_iv = 10          # restore default
        print(f"[S5->0x11] Unlock S6 upload enabled (unlock_iv={unlock_iv})")

    # Heartbeat upload interval (Omni: seconds, DiLu: minutes)
    if hb_sec > 0:
        heartbeat = max(1, round(hb_sec / 60))   # at least 1 minute
        print(f"[S5->0x11] Heartbeat interval: {hb_sec}s -> {heartbeat}min")

    # S6 interval in unlock (seconds, direct map)
    if unlock_sec > 0:
        unlock_iv = unlock_sec
        print(f"[S5->0x11] Unlock notify interval: {unlock_iv}s")

    # --- Encode content per spec section 5.2.15 / 5.2.16 ---
    content = bytearray()
    content.append(0x01)                                # head: query request
    content.extend(serial.to_bytes(2, "little"))         # serial
    content.append(0x11)                                # cmd: Setting parameters

    # Strings (null-terminated ASCII)
    for s in (apn, apn_user, apn_pass, ble_name):
        content.extend(s.encode("ascii", errors="ignore") + b"\x00")

    content.append(heartbeat & 0xFF)                    # Heartbeat interval (1B)
    content.extend(int(unlock_iv).to_bytes(4, "little"))# Unlock notify interval (4B)
    content.extend(int(lock_iv).to_bytes(4, "little"))  # Lock notify interval (4B)
    content.extend(int(static_lk).to_bytes(4, "little"))# Static automatic lock (4B)
    content.append(vibration & 0xFF)                    # Vibration sensitivity (1B)
    content.append(alarm_tone & 0xFF)                   # Alarm tone times (1B)

    # Fixed-size byte fields
    content.extend(_pad_bytes(chain_mac, 6))
    content.extend(_pad_bytes(chain_key, 16))
    content.extend(_pad_bytes(bat_mac, 6))
    content.extend(_pad_bytes(bat_key, 16))

    return _wrap_packet(bytes(content))


def handle_s5(args: list, lock_id: str, device_info: dict, device_state: dict):
    """
    Handle incoming Omni S5 (IOT device settings).
    1. Cache new values in device_info
    2. Allocate serial and register pending query
    3. Build DiLu 0x11 binary packet
    4. Build S5 echo back to upstream server

    Returns: (action, out) tuple for the caller.
    """
    from helpers import apply_s5_to_device_info

    print("🔔 S5 IOT Device Settings -> translating to DiLu 0x11")

    # 1. Cache new values in device_info
    apply_s5_to_device_info(args, device_info)

    # 2. Allocate serial and register pending query
    serial = device_state.get("next_serial", 100)
    device_state["next_serial"] = serial + 1
    device_state["pending_queries"][serial] = "set_parameter"

    # 3. Build DiLu 0x11 binary packet
    packet = build_setting_parameters_from_s5(args, serial, device_info)
    print(f"[S5->0x11] Sending to device (hex): {packet.hex()}")

    # 4. Echo S5 back to upstream server (Omni: device confirms receipt)
    args_str = ",".join(args) if args else ""
    s5_echo = f"*SCOR,OM,{lock_id},S5,{args_str}#\n"
    print(f"[S5] Echoing to server: {s5_echo.strip()}")

    return "FORWARD_BOTH", {
        "to_device": packet,
        "to_server": s5_echo.encode("ascii"),
    }


# ---------------------------------------------------------------------------
# S7 -> 0x03 (Headlight) + 0x07 (Speed limit)
# ---------------------------------------------------------------------------

def _compute_dilu_mode_and_speed(scooter_settings: dict):
    """
    From current scooter_settings, compute DiLu 0x07 mode + speed limit.

    Omni mode 1=low, 2=medium -> DiLu soft (0x00), use low/medium speed limit
    Omni mode 3=high          -> DiLu sport (0x01), use high speed limit
    """
    mode = scooter_settings.get("Mode", 2)
    if mode == 1:
        dilu_mode = 0x00  # soft
        speed = scooter_settings.get("Low speed limit", 15)
    elif mode == 2:
        dilu_mode = 0x00  # soft
        speed = scooter_settings.get("Medium speed limit", 20)
    else:  # 3 = high
        dilu_mode = 0x01  # sport
        speed = scooter_settings.get("High speed limit", 25)

    scooter_settings["DiLu mode"] = dilu_mode
    scooter_settings["DiLu speed limit"] = speed
    return dilu_mode, speed


def handle_s7(args: list, lock_id: str, scooter_settings: dict, device_state: dict):
    """
    Handle Omni S7 (Scooter setting 1 — temporary).

    S7 args: [headlight, mode, throttle_response, taillights]
      0 = invalid (don't set)

    Translates to:
      - DiLu 0x03 (Headlight control) if headlight changed
      - DiLu 0x07 (Set speed limit)   if mode changed

    Returns: (action, out) tuple.
    """
    print("🔔 S7 Scooter Setting 1 -> translating to DiLu 0x03/0x07")

    try:
        headlight = int(args[0]) if len(args) > 0 else 0
        mode      = int(args[1]) if len(args) > 1 else 0
        throttle  = int(args[2]) if len(args) > 2 else 0
        taillights = int(args[3]) if len(args) > 3 else 0
    except ValueError:
        print(f"[S7] Invalid args: {args}")
        headlight = mode = throttle = taillights = 0

    # Cache in scooter_settings (0 = don't change)
    if headlight != 0:
        scooter_settings["Headlight"] = headlight
    if mode != 0:
        scooter_settings["Mode"] = mode
    if throttle != 0:
        scooter_settings["Throttle response"] = throttle
    if taillights != 0:
        scooter_settings["Taillights"] = taillights

    packets = []

    # --- 0x03 Headlight control ---
    # Spec 5.2.4: request = 1 byte (0x00=off, 0x01=on)
    if headlight != 0:
        serial = device_state.get("next_serial", 100)
        device_state["next_serial"] = serial + 1
        device_state["pending_queries"][serial] = "headlight_control"
        hl_value = 0x01 if headlight == 2 else 0x00
        content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x03, hl_value])
        packets.append(_wrap_packet(content))
        print(f"[S7->0x03] Headlight {'ON' if hl_value else 'OFF'} (serial={serial})")

    # --- 0x07 Set speed limit ---
    # Spec 5.2.8: request = mode(1) + speed(1)
    if mode != 0:
        serial = device_state.get("next_serial", 100)
        device_state["next_serial"] = serial + 1
        device_state["pending_queries"][serial] = "set_speed_limit"
        dilu_mode, speed = _compute_dilu_mode_and_speed(scooter_settings)
        content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x07, dilu_mode, speed])
        packets.append(_wrap_packet(content))
        print(f"[S7->0x07] Mode={'soft' if dilu_mode==0 else 'sport'}, Speed={speed}km/h (serial={serial})")

    if not packets:
        print("[S7] Nothing to send (all args were 0/invalid)")
        # Still echo S7 back
        args_str = ",".join(args) if args else ""
        s7_echo = f"*SCOR,OM,{lock_id},S7,{args_str}#\n"
        return "RESPOND_TO_SERVER", s7_echo.encode("ascii")

    combined = b"".join(packets)

    # Echo S7 back to server
    args_str = ",".join(args) if args else ""
    s7_echo = f"*SCOR,OM,{lock_id},S7,{args_str}#\n"
    print(f"[S7] Echoing to server: {s7_echo.strip()}")

    return "FORWARD_BOTH", {
        "to_device": combined,
        "to_server": s7_echo.encode("ascii"),
    }


# ---------------------------------------------------------------------------
# S4 -> updates speed limits, triggers 0x07 if mode already set
# ---------------------------------------------------------------------------

def handle_s4(args: list, lock_id: str, scooter_settings: dict, device_state: dict):
    """
    Handle Omni S4 (Scooter setting 2 — persistent).

    S4 args: [inch_speed, cruise, startup_mode, button_switch, key_headlight,
              low_speed, medium_speed, high_speed]
      0 = invalid (don't set)

    Saves speed limits. If a speed limit changes for the current active mode,
    sends DiLu 0x07 with the updated value.

    Returns: (action, out) tuple.
    """
    print("🔔 S4 Scooter Setting 2 -> saving speed limits")

    try:
        inch_speed   = int(args[0]) if len(args) > 0 else 0
        cruise       = int(args[1]) if len(args) > 1 else 0
        startup_mode = int(args[2]) if len(args) > 2 else 0
        btn_switch   = int(args[3]) if len(args) > 3 else 0
        key_headlight = int(args[4]) if len(args) > 4 else 0
        low_speed    = int(args[5]) if len(args) > 5 else 0
        med_speed    = int(args[6]) if len(args) > 6 else 0
        high_speed   = int(args[7]) if len(args) > 7 else 0
    except ValueError:
        print(f"[S4] Invalid args: {args}")
        low_speed = med_speed = high_speed = 0

    # Cache speed limits (0 = don't change)
    if low_speed != 0:
        scooter_settings["Low speed limit"] = low_speed
        print(f"[S4] Low speed limit: {low_speed} km/h")
    if med_speed != 0:
        scooter_settings["Medium speed limit"] = med_speed
        print(f"[S4] Medium speed limit: {med_speed} km/h")
    if high_speed != 0:
        scooter_settings["High speed limit"] = high_speed
        print(f"[S4] High speed limit: {high_speed} km/h")

    packets = []

    # If any speed limit changed, re-send 0x07 with updated value for current mode
    if low_speed != 0 or med_speed != 0 or high_speed != 0:
        serial = device_state.get("next_serial", 100)
        device_state["next_serial"] = serial + 1
        device_state["pending_queries"][serial] = "set_speed_limit"
        dilu_mode, speed = _compute_dilu_mode_and_speed(scooter_settings)
        content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x07, dilu_mode, speed])
        packets.append(_wrap_packet(content))
        print(f"[S4->0x07] Mode={'soft' if dilu_mode==0 else 'sport'}, Speed={speed}km/h (serial={serial})")

    # Echo S4 back to server
    args_str = ",".join(args) if args else ""
    s4_echo = f"*SCOR,OM,{lock_id},S4,{args_str}#\n"
    print(f"[S4] Echoing to server: {s4_echo.strip()}")

    if packets:
        return "FORWARD_BOTH", {
            "to_device": b"".join(packets),
            "to_server": s4_echo.encode("ascii"),
        }

    return "RESPOND_TO_SERVER", s4_echo.encode("ascii")


# ---------------------------------------------------------------------------
# V0 -> 0x0C (Audio control)
# ---------------------------------------------------------------------------

def handle_v0(args: list, lock_id: str, device_state: dict):
    """
    Handle Omni V0 (Beep playback).

    V0 args: [play_content]
        1  = out of range prompt
        2  = vehicle search prompt
        3  = low battery prompt
        80 = turn off voice
        81 = turn on voice

    Translates to DiLu 0x0C (Audio control):
        audio_switch(1) + audio_file(1) + repeat(1)

    Returns: (action, out) tuple.
    """
    print("🔔 V0 Beep Playback -> translating to DiLu 0x0C")

    try:
        play = int(args[0]) if len(args) > 0 else 0
    except ValueError:
        print(f"[V0] Invalid args: {args}")
        play = 0

    serial = device_state.get("next_serial", 100)
    device_state["next_serial"] = serial + 1
    device_state["pending_queries"][serial] = "audio_control"

    if play == 80:
        # Turn off audio function
        audio_switch = 0x10
        audio_file = 0x00
        repeat = 0x00
        print(f"[V0->0x0C] Turn OFF audio (serial={serial})")
    elif play == 81:
        # Turn on audio function
        audio_switch = 0x11
        audio_file = 0x00
        repeat = 0x00
        print(f"[V0->0x0C] Turn ON audio (serial={serial})")
    elif play in (1, 2, 3):
        # Play audio file = V0 value, repeat 3 times
        audio_switch = 0x01
        audio_file = play
        repeat = 0x03
        print(f"[V0->0x0C] Play file {audio_file}, repeat {repeat}x (serial={serial})")
    else:
        print(f"[V0] Unknown play value: {play}")
        args_str = ",".join(args) if args else ""
        v0_echo = f"*SCOR,OM,{lock_id},V0,{args_str}#\n"
        return "RESPOND_TO_SERVER", v0_echo.encode("ascii")

    # Build DiLu 0x0C packet: head(0x01) + serial(2) + cmd(0x0C) + switch + file + repeat
    content = (bytes([0x01])
               + serial.to_bytes(2, "little")
               + bytes([0x0C, audio_switch, audio_file, repeat]))
    packet = _wrap_packet(content)

    # Echo V0 back to server
    args_str = ",".join(args) if args else ""
    v0_echo = f"*SCOR,OM,{lock_id},V0,{args_str}#\n"
    print(f"[V0] Echoing to server: {v0_echo.strip()}")

    return "FORWARD_BOTH", {
        "to_device": packet,
        "to_server": v0_echo.encode("ascii"),
    }


# ---------------------------------------------------------------------------
# G0 -> 0x06 (Get version)
# ---------------------------------------------------------------------------

def handle_g0(lock_id: str, device_state: dict):
    """
    Handle Omni G0 (Get firmware version).

    Sends DiLu CMD 0x06 (Get version) to the device.
    The response is handled in process_device_data (head=0x02, "get_version").
    When the response arrives, the bridge builds and sends Omni G0 to the server.

    Spec 5.2.7: Request has no data, just head(0x01) + serial(2) + cmd(0x06).

    Returns: (action, out) — only sends to device, NOT to server yet.
    """
    print("🔔 G0 Get Firmware Version -> sending DiLu 0x06 to device")

    serial = device_state.get("next_serial", 100)
    device_state["next_serial"] = serial + 1
    device_state["pending_queries"][serial] = "get_version_for_g0"

    # DiLu 0x06 Get version: no request data
    content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x06])
    packet = _wrap_packet(content)
    print(f"[G0->0x06] Querying device (serial={serial}, hex={packet.hex()})")

    # Store lock_id so we can build the G0 response when 0x06 reply comes
    device_state["g0_lock_id"] = lock_id

    return "FORWARD_TO_DEVICE", packet


# ---------------------------------------------------------------------------
# S1 -> 0x00 (Restart) — only code 2 is handled
# ---------------------------------------------------------------------------

def handle_s1(args: list, lock_id: str, device_state: dict):
    """
    Handle Omni S1 (Event notification).
    Only code 2 (IOT restart) is translated -> DiLu 0x00 Restart.
    All other codes are echoed back to server with no device action.
    """
    try:
        event_code = int(args[0]) if len(args) > 0 else 0
    except ValueError:
        print(f"[S1] Invalid event code: {args}")
        return "NONE", None

    s1_echo = f"*SCOR,OM,{lock_id},S1,{event_code}#\n"

    if event_code == 2:
        print("🔔 S1 IOT Restart -> sending DiLu 0x00 to device")
        serial = device_state.get("next_serial", 100)
        device_state["next_serial"] = serial + 1
        device_state["pending_queries"][serial] = "restart"

        content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x00])
        packet = _wrap_packet(content)
        print(f"[S1->0x00] Restart (serial={serial})")

        return "FORWARD_BOTH", {
            "to_device": packet,
            "to_server": s1_echo.encode("ascii"),
        }

    print(f"[S1] Event code {event_code} — echo only, no device action")
    return "RESPOND_TO_SERVER", s1_echo.encode("ascii")


# ---------------------------------------------------------------------------
# R0 -> Echo KEY back (handshake for L0/L1)
# L0 -> 0x02 Lock control (unlock motor)
# L1 -> 0x02 Lock control (lock motor)
# ---------------------------------------------------------------------------

import random


def handle_r0(args: list, lock_id: str, device_state: dict):
    """
    Handle Omni R0 (Unlock/Lock operation request).

    R0 is a handshake — server sends it before L0/L1 to get an operation KEY.
    DiLu doesn't need a handshake, so the bridge generates a random KEY,
    stores it, and echoes R0 back with the KEY.

    Omni R0 server->lock args:
        [operation, key_time, user_id, timestamp]
        operation: 0=unlock, 1=lock, 2=RFID unlock, 3=RFID lock

    Omni R0 lock->server response:
        [operation, KEY, user_id, timestamp]
        KEY: random 0-255, needed by server when sending L0/L1
    """
    print("🔔 R0 Unlock/Lock Request (handshake)")

    try:
        operation = args[0] if len(args) > 0 else "0"
        user_id = args[2] if len(args) > 2 else "0"
        timestamp = args[3] if len(args) > 3 else "0"
    except (IndexError, ValueError):
        print(f"[R0] Invalid args: {args}")
        return "NONE", None

    # Generate random KEY (0-255)
    key = random.randint(0, 255)
    device_state["r0_key"] = key
    device_state["r0_user_id"] = user_id
    device_state["r0_timestamp"] = timestamp
    device_state["r0_operation"] = operation

    r0_echo = f"*SCOR,OM,{lock_id},R0,{operation},{key},{user_id},{timestamp}#\n"
    print(f"[R0] Generated KEY={key}, echoing to server: {r0_echo.strip()}")

    return "RESPOND_TO_SERVER", r0_echo.encode("ascii")


def handle_l0(args: list, lock_id: str, device_state: dict):
    """
    Handle Omni L0 (Unlock command).

    Omni L0 server->lock args: [KEY, user_id, timestamp]
    Translates to DiLu 0x02: lock_control=0x01 (unlock), lock_type=0x00 (motor)

    After sending to device, echoes L0 result back to server.
    """
    print("🔔 L0 Unlock -> sending DiLu 0x02 (unlock motor)")

    try:
        key = int(args[0]) if len(args) > 0 else 0
        user_id = args[1] if len(args) > 1 else "0"
        timestamp = args[2] if len(args) > 2 else "0"
    except (IndexError, ValueError):
        print(f"[L0] Invalid args: {args}")
        return "NONE", None

    # Verify KEY matches what we generated in R0
    expected_key = device_state.get("r0_key")
    if expected_key is not None and key != expected_key:
        print(f"[L0] KEY mismatch: got {key}, expected {expected_key}")
        l0_fail = f"*SCOR,OM,{lock_id},L0,2,{user_id},{timestamp}#\n"
        return "RESPOND_TO_SERVER", l0_fail.encode("ascii")

    serial = device_state.get("next_serial", 100)
    device_state["next_serial"] = serial + 1
    device_state["pending_queries"][serial] = "unlock_motor"

    # Store user_id and timestamp for the response
    device_state["l0_user_id"] = user_id
    device_state["l0_timestamp"] = timestamp
    device_state["l0_lock_id"] = lock_id

    # DiLu 0x02: lock_control(1) + lock_type(1)
    # unlock=0x01, motor=0x00
    #lock or unlock saved inside device_state["r0_operation"] = operation
    expected_operation = device_state.get("r0_operation")
    if expected_operation in ["0"]:
        lock_control = 0x01   # unlock
    elif expected_operation in ["1"]:
        lock_control = 0x00   # lock
    else:
        print(f"[L0] Unknown operation: {expected_operation}")
        return "NONE", None
    content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x02, lock_control, 0x00])
    packet = _wrap_packet(content)
    action = "unlock" if lock_control == 0x01 else "lock"
    print(f"[L0->0x02] {action} motor (serial={serial})")
    return "FORWARD_TO_DEVICE", packet


def handle_l1(args: list, lock_id: str, device_state: dict):
    """
    Handle Omni L1 (Lock command).

    Omni L1 server->lock args: [KEY]
    Translates to DiLu 0x02: lock_control=0x00 (lock), lock_type=0x00 (motor)

    After sending to device, echoes L1 result back to server.
    """
    print("🔔 L1 Lock -> sending DiLu 0x02 (lock motor)")

    try:
        key = int(args[0]) if len(args) > 0 else 0
    except (IndexError, ValueError):
        print(f"[L1] Invalid args: {args}")
        return "NONE", None

    # Verify KEY matches
    expected_key = device_state.get("r0_key")
    if expected_key is not None and key != expected_key:
        print(f"[L1] KEY mismatch: got {key}, expected {expected_key}")
        user_id = device_state.get("r0_user_id", "0")
        timestamp = device_state.get("r0_timestamp", "0")
        l1_fail = f"*SCOR,OM,{lock_id},L1,2,{user_id},{timestamp},0#\n"
        return "RESPOND_TO_SERVER", l1_fail.encode("ascii")

    serial = device_state.get("next_serial", 100)
    device_state["next_serial"] = serial + 1
    device_state["pending_queries"][serial] = "lock_motor"

    # Store lock_id for response
    device_state["l1_lock_id"] = lock_id

    # DiLu 0x02: lock_control(1) + lock_type(1)
    # lock=0x00, motor=0x00
    content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x02, 0x00, 0x00])
    packet = _wrap_packet(content)
    print(f"[L1->0x02] Lock motor (serial={serial})")

    return "FORWARD_TO_DEVICE", packet


# ---------------------------------------------------------------------------
# L5 -> 0x02 Lock control (chain lock / battery lock)
# ---------------------------------------------------------------------------

# Omni L5 operation -> (DiLu lock_control, DiLu lock_type)
L5_LOCK_MAP = {
    1:  (0x01, 0x03),   # unlock battery lock
    3:  (0x01, 0x02),   # unlock cable lock -> chain lock
    17: (0x00, 0x03),   # lock battery lock
    19: (0x00, 0x02),   # lock cable lock -> chain lock
}

# Omni L5 get-status operations -> device_info keys
L5_STATUS_MAP = {
    33: ("Battery lock connection status", "Battery lock status"),
    35: ("Chain lock connection status", "Chain lock status"),
}


def handle_l5(args: list, lock_id: str, device_info: dict, device_state: dict):
    """
    Handle Omni L5 (Unlock external devices).

    Supported:
      1/17  - unlock/lock battery lock -> DiLu 0x02 type=0x03
      3/19  - unlock/lock cable lock   -> DiLu 0x02 type=0x02 (chain lock)
      33/35 - get battery/cable status -> respond from cached device_info

    Not supported:
      2/18/34 - helmet lock (not in device doc)
      4/20/36 - hub lock (excluded per decision)
    """
    print("🔔 L5 External Lock Control")

    try:
        operation = int(args[0]) if len(args) > 0 else 0
        print(f"[L5] Operation code: {operation}")
    except ValueError:
        print(f"[L5] Invalid args: {args}")
        return "NONE", None

    # --- Lock/Unlock (send to device) ---
    if operation in L5_LOCK_MAP:
        lock_control, lock_type = L5_LOCK_MAP[operation]
        action_str = "Unlock" if lock_control == 0x01 else "Lock"
        type_str = "battery" if lock_type == 0x03 else "chain"

        serial = device_state.get("next_serial", 100)
        device_state["next_serial"] = serial + 1
        query_name = f"{'unlock' if lock_control == 0x01 else 'lock'}_{type_str}"
        device_state["pending_queries"][serial] = query_name
        device_state["l5_operation"] = operation
        device_state["l5_lock_id"] = lock_id

        content = bytes([0x01]) + serial.to_bytes(2, "little") + bytes([0x02, lock_control, lock_type])
        packet = _wrap_packet(content)
        print(f"[L5->0x02] {action_str} {type_str} lock (serial={serial})")
        
        return "FORWARD_BOTH", {
            "to_device": packet,
            "to_server": f"*SCOR,OM,{lock_id},L5,{operation},0#\n".encode("ascii"),
        }
    #to devvice :0x01 serial(2) + cmd(0x02) + lock_control(1) + lock_type(1)
    #to server:*SCOR,OM,123456789123456,L5,1,0#<LF>
    # --- Get Status (respond from cache) ---
    if operation in L5_STATUS_MAP:
        conn_key, status_key = L5_STATUS_MAP[operation]
        conn = device_info.get(conn_key, "Unconnected")
        status = device_info.get(status_key, 0)

        # Map to Omni L5 result: 16=locked, 17=unlocked
        if status == "Locked":
            result = 16
        elif status == "Unlocked":
            result = 17
        else:
            result = 1  # failure/unknown

        l5_resp = f"*SCOR,OM,{lock_id},L5,{operation},{result}#\n"
        type_str = "battery" if operation == 33 else "chain"
        print(f"[L5] Get {type_str} lock status: {status} (result={result})")
        return "RESPOND_TO_SERVER", l5_resp.encode("ascii")

    # --- Unsupported operations ---
    print(f"[L5] Operation {operation} not supported (helmet/hub not in device)")
    l5_fail = f"*SCOR,OM,{lock_id},L5,{operation},1#\n"
    return "RESPOND_TO_SERVER", l5_fail.encode("ascii")
