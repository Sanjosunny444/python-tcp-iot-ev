"""
Translators that build Omni TCP protocol messages from DiLu device state.

These functions take the parsed DiLu device_info dict and return the
Omni-formatted ASCII bytes to forward to the upstream server.

Omni message format (section 1.1):
    *SCOR,OM,<IMEI>,<CMD>,<args...>#<LF>

Voltage conversion note:
    DiLu reports voltage in volts (float, e.g. 12.0 V).
    Omni Q0/H0 use centi-volts (int, e.g. 412 means 4.12 V).
    We multiply by 100 to match Omni's format.
"""


def build_q0_signin(device_info: dict) -> bytes:
    """Build Omni Q0 (sign-in) message from DiLu status fields.

    Omni Q0 format:
        *SCOR,OM,<IMEI>,Q0,<voltage>,<battery>,<csq>#\n
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"
    voltage = int(round(device_info.get("Voltage", 0) * 100))
    battery = device_info.get("Battery level", 0)
    csq = device_info.get("CSQ", 0)
    msg = f"*SCOR,OM,{imei},Q0,{voltage},{battery},{csq}#\n"
    print(f"[SIGNIN] Sending Q0 upstream: {msg.strip()}")
    return msg.encode("ascii")


def build_h0_heartbeat(device_info: dict) -> bytes:
    """Build Omni H0 (heartbeat) message from DiLu status fields.

    Omni H0 format:
        *SCOR,OM,<IMEI>,H0,<lock>,<voltage>,<csq>,<battery>,<charging>#\n

    Lock mapping: Omni uses 0=unlocked, 1=locked.
    DiLu Lock status has been decoded to a string by status_notification(),
    so we map the string back to an int.
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"
    lock_raw = device_info.get("Lock status", 0)
    lock = 0 if lock_raw == "Unlocked" else 1
    voltage = int(round(device_info.get("Voltage", 0) * 100))
    csq = device_info.get("CSQ", 0)
    battery = device_info.get("Battery level", 0)
    charging = device_info.get("Charging status", 0)
    msg = f"*SCOR,OM,{imei},H0,{lock},{voltage},{csq},{battery},{charging}#\n"
    print(f"[HEARTBEAT] Sending H0 upstream: {msg.strip()}")
    return msg.encode("ascii")


def build_s6_scooter_info(device_info: dict, scooter_settings: dict) -> bytes:
    """Build Omni S6 (scooter info) response from cached DiLu data.

    Omni S6 format:
        *SCOR,OM,<IMEI>,S6,<power>,<mode>,<speed>,<charging>,
         <bat1_v>,<bat2_v>,<lock>,<signal>,<mileage>,<mcc-mnc>,<lac>,<cellid>#\n

    Field mapping:
        1  power       -> Battery level (0-100%)
        2  mode        -> scooter_settings["Mode"] (1=low, 2=med, 3=high)
        3  speed       -> Speed (DiLu 0.1km/h * 10 = Omni 1km/h units; e.g. 221=22.1)
        4  charging    -> Charging status (0/1)
        5  bat1 voltage -> Voltage (DiLu volts * 10; e.g. 37.2V -> 372)
        6  bat2 voltage -> 0 (DiLu has no second battery)
        7  lock status -> 0=unlocked, 1=locked
        8  signal      -> CSQ (2-32)
        9  mileage     -> 0 (single ride mileage not tracked, unit 10m)
        10 mcc-mnc     -> empty (not in DiLu protocol)
        11 lac         -> empty
        12 cellid      -> empty
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"

    power = device_info.get("Battery level", 0)
    mode = scooter_settings.get("Mode", 2)

    # DiLu Speed is in 0.1 km/h (float after parsing, e.g. 12.3).
    # Omni S6 speed is integer in 1 km/h (e.g. 221 = 22.1 km/h).
    # So we multiply the parsed float by 10 to get the Omni format.
    speed_raw = device_info.get("Speed", 0.0)
    speed = int(round(speed_raw * 10))

    charging = device_info.get("Charging status", 0)

    # DiLu Voltage is in volts (float, e.g. 12.0V).
    # Omni S6 bat1 voltage unit is 0.1V (e.g. 372 = 37.2V).
    bat1_v = int(round(device_info.get("Voltage", 0) * 10))
    bat2_v = 0  # no second battery in DiLu

    lock_raw = device_info.get("Lock status", 0)
    lock = 0 if lock_raw == "Unlocked" else 1

    signal = device_info.get("CSQ", 0)
    mileage = 0  # single ride mileage not tracked

    msg = (
        f"*SCOR,OM,{imei},S6,"
        f"{power},{mode},{speed},{charging},"
        f"{bat1_v},{bat2_v},{lock},{signal},"
        f"{mileage},,,#\n"
    )
    print(f"[S6] Sending scooter info upstream: {msg.strip()}")
    return msg.encode("ascii")


def _decimal_to_nmea_lat(decimal_deg: float):
    """
    Convert decimal degrees latitude to NMEA ddmm.mmmm format + hemisphere.

    Example: 12.3456789 -> ("1220.7407", "N")
             -33.8688   -> ("3352.1280", "S")

    Conversion: degrees = int(abs(decimal))
                minutes = (abs(decimal) - degrees) * 60
                result  = dd * 100 + mm.mmmm  formatted as ddmm.mmmm
    """
    if decimal_deg >= 0:
        hemisphere = "N"
    else:
        hemisphere = "S"
    abs_deg = abs(decimal_deg)
    degrees = int(abs_deg)
    minutes = (abs_deg - degrees) * 60
    nmea = f"{degrees:02d}{minutes:07.4f}"
    return nmea, hemisphere


def _decimal_to_nmea_lon(decimal_deg: float):
    """
    Convert decimal degrees longitude to NMEA dddmm.mmmm format + hemisphere.

    Example: 98.7654321  -> ("09845.9259", "E")
             -114.14369  -> ("11408.6214", "W")

    Conversion: same as lat but with 3-digit degree field (ddd).
    """
    if decimal_deg >= 0:
        hemisphere = "E"
    else:
        hemisphere = "W"
    abs_deg = abs(decimal_deg)
    degrees = int(abs_deg)
    minutes = (abs_deg - degrees) * 60
    nmea = f"{degrees:03d}{minutes:07.4f}"
    return nmea, hemisphere


def build_d0_positioning(device_info: dict, identifier: int = 0) -> bytes:
    """Build Omni D0 (positioning) response from cached DiLu data.

    Omni D0 format (section 1.3.12):
        *SCOR,OM,<IMEI>,D0,<id>,<utc_time>,<status>,<lat>,<ns>,<lon>,<ew>,
         <sats>,<hdop>,<utc_date>,<alt>,<unit>,<mode>#\n

    identifier: 0 = single position (D0 query), 1 = tracking (D1 active)

    DiLu provides: Latitude, Longitude (decimal degrees, signed),
    Location signal (0=none, 1=GPS, 2=LBS), Number of satellites,
    Location accuracy (meters).

    Fields we don't have from DiLu: UTC time, UTC date, altitude.
    These are sent as empty or placeholder values.
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"

    lat_decimal = device_info.get("Latitude", 0.0)
    lon_decimal = device_info.get("Longitude", 0.0)
    loc_signal = device_info.get("Location signal", 0)
    satellites = device_info.get("Number of satellites", 0)
    accuracy = device_info.get("Location accuracy", 0)

    # Determine positioning status
    # DiLu Location signal: 0=No signal, 1=GPS, 2=LBS
    # Omni D0 status: A=valid positioning, V=invalid
    if loc_signal == 0 or (lat_decimal == 0.0 and lon_decimal == 0.0):
        status = "V"
        mode = "N"      # N = invalid data
    elif loc_signal == 1:
        status = "A"
        mode = "A"      # A = autonomous (GPS)
    else:
        status = "A"
        mode = "E"      # E = estimate (LBS)

    # Convert decimal degrees to NMEA format
    lat_nmea, lat_hemi = _decimal_to_nmea_lat(lat_decimal)
    lon_nmea, lon_hemi = _decimal_to_nmea_lon(lon_decimal)

    # HDOP: approximate from Location accuracy (meters).
    # Rough: HDOP ~ accuracy / 5. Typical GPS HDOP is 0.5-2.0.
    # If no accuracy data, default to 99.
    if accuracy > 0:
        hdop = f"{accuracy / 5:.2f}"
    else:
        hdop = ""

    # UTC time/date and altitude not available from DiLu — send empty
    utc_time = ""
    utc_date = ""
    altitude = ""

    msg = (
        f"*SCOR,OM,{imei},D0,"
        f"{identifier},"            # 0 = single position, 1 = tracking
        f"{utc_time},"              # UTC time (empty)
        f"{status},"                # A=valid, V=invalid
        f"{lat_nmea},{lat_hemi},"   # latitude ddmm.mmmm, N/S
        f"{lon_nmea},{lon_hemi},"   # longitude dddmm.mmmm, E/W
        f"{satellites},"            # number of satellites
        f"{hdop},"                  # HDOP
        f"{utc_date},"              # UTC date (empty)
        f"{altitude},"              # altitude (empty)
        f"M,"                       # height unit
        f"{mode}#\n"                # mode indicator
    )
    print(f"[D0] Sending positioning upstream: {msg.strip()}")
    return msg.encode("ascii")


def build_g0_firmware_version(device_info: dict) -> bytes:
    """Build Omni G0 (firmware version) response from cached DiLu data.

    Omni G0 format (section 1.3.14):
        *SCOR,OM,<IMEI>,G0,<iot_ver>,<iot_date>,<ctrl_ver>,<bms_ver>,
         <voice_ver>,<rsv>,<rsv>,<rsv>,<rsv>#\n

    Mapping from DiLu device_info:
        1  IoT software version   <- CCU firmware version
        2  IoT compilation date   <- (not in DiLu, empty)
        3  Controller version     <- ECU firmware version
        4  BMS version            <- Battery firmware version
        5  Voice file version     <- (not in DiLu, empty)
        6-9 Reserved              <- empty
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"

    iot_ver = device_info.get("CCU firmware version", "")
    if iot_ver == "Unknown":
        iot_ver = ""

    iot_date = ""  # not available from DiLu

    ctrl_ver = device_info.get("ECU firmware version", "")
    if ctrl_ver == "Unknown":
        ctrl_ver = ""

    bms_ver = device_info.get("Battery firmware version", "")
    if bms_ver == "Unknown":
        bms_ver = ""

    voice_ver = ""  # not available from DiLu

    msg = f"*SCOR,OM,{imei},G0,{iot_ver},{iot_date},{ctrl_ver},{bms_ver},{voice_ver},,,,#\n"
    print(f"[G0] Sending firmware version upstream: {msg.strip()}")
    return msg.encode("ascii")


def build_e0_fault_code(device_info: dict) -> bytes:
    """Build Omni E0 (upload fault code) message.

    Omni E0 format (section 1.3.15):
        *SCOR,OM,<IMEI>,E0,<error_code>#\n

    Sent when DiLu status notification has a non-zero fault code.
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"

    fault = device_info.get("Fault code", 0)
    msg = f"*SCOR,OM,{imei},E0,{fault}#\n"
    print(f"[E0] Sending fault code upstream: {msg.strip()}")
    return msg.encode("ascii")


def build_i0_iccid(device_info: dict) -> bytes:
    """Build Omni I0 (SIM card ICCID) response from cached DiLu data.

    Omni I0 format (section 1.4.1):
        *SCOR,OM,<IMEI>,I0,<ICCID>#\n

    ICCID comes from DiLu Device Info notification (CMD 0x03).
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"

    iccid = device_info.get("ICCID", "")
    if iccid == "Unknown":
        iccid = ""

    msg = f"*SCOR,OM,{imei},I0,{iccid}#\n"
    print(f"[I0] Sending ICCID upstream: {msg.strip()}")
    return msg.encode("ascii")


def build_m0_ble_mac(device_info: dict) -> bytes:
    """Build Omni M0 (BLE MAC address) response from cached DiLu data.

    Omni M0 format (section 1.4.2):
        *SCOR,OM,<IMEI>,M0,<MAC>#\n

    BLE MAC comes from DiLu Device Info notification (CMD 0x03).
    """
    imei = device_info.get("IMEI") or "000000000000000"
    if imei == "Unknown":
        imei = "000000000000000"

    ble_mac = device_info.get("BLE MAC", "")
    if ble_mac == "Unknown":
        ble_mac = ""

    msg = f"*SCOR,OM,{imei},M0,{ble_mac}#\n"
    print(f"[M0] Sending BLE MAC upstream: {msg.strip()}")
    return msg.encode("ascii")
