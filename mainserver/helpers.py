"""
Helper functions used by the bridge for sign-in flow and Omni S5 translation.
"""

from to_server import build_q0_signin, build_h0_heartbeat


def maybe_send_q0_or_h0(device_info, device_state):
    """
    Decide whether a status notification should trigger a Q0 (sign-in) or H0
    (heartbeat) upstream message.

    Q0 is sent exactly once — after auth, device info, and status have all
    arrived (in any order). After Q0 is sent, all future status notifications
    become H0 heartbeats.

    D1 tracking (periodic D0) is handled by a separate task in pythonserver.py.
    """
    ready = (
        device_state.get("auth_received")
        and device_state.get("info_received")
        and device_state.get("status_received")
    )
    if ready and not device_state.get("q0_sent"):
        device_state["q0_sent"] = True
        return "FORWARD_TRANSLATED", build_q0_signin(device_info)
    if device_state.get("q0_sent"):
        return "FORWARD_TRANSLATED", build_h0_heartbeat(device_info)
    print("[STATUS] Held (waiting for auth/info); nothing sent upstream")
    return "NONE", None


def apply_s5_to_device_info(s5_args: list, device_info: dict):
    """
    Update device_info (the bridge's cached picture of 0x10/0x11 device
    parameters) with the values pushed from server S5.

    This keeps our local copy of Vibration sensitivity / Heartbeat interval /
    Unlock notify interval in sync with what we are about to send to the
    device in the 0x11 packet.
    """
    try:
        accel      = int(s5_args[0]) if len(s5_args) > 0 else 0
        s6_unlock  = int(s5_args[1]) if len(s5_args) > 1 else 0
        hb_sec     = int(s5_args[2]) if len(s5_args) > 2 else 0
        unlock_sec = int(s5_args[3]) if len(s5_args) > 3 else 0
    except ValueError:
        print(f"[S5-cache] Invalid S5 args: {s5_args}")
        return

    # Accelerometer sensitivity -> Vibration sensitivity
    sens_map = {0: None, 1: 10, 2: 6, 3: 3}
    if sens_map.get(accel) is not None:
        device_info["Vibration sensitivity"] = sens_map[accel]

    # S6 upload in unlock: 1=off, 2=on
    if s6_unlock == 1:
        device_info["Unlock notify interval"] = 0
    elif s6_unlock == 2 and device_info.get("Unlock notify interval", 0) == 0:
        device_info["Unlock notify interval"] = 10

    # Heartbeat interval (Omni seconds -> DiLu minutes)
    if hb_sec > 0:
        device_info["Heartbeat interval"] = max(1, round(hb_sec / 60))

    # Unlock notify interval (seconds, direct)
    if unlock_sec > 0:
        device_info["Unlock notify interval"] = unlock_sec
