"""
Dummy upstream (main) server for testing the bridge.

Mimics the Omni server the bridge forwards to. Listens for TCP connections
from the bridge, prints incoming Omni messages, and provides an interactive
menu to send server-to-device instructions back to the bridge.

Protocol (Omni, per section 1.1 of the Omni TCP spec):
    Server -> Device: 0xFFFF*SCOS,OM,<IMEI>,<TYPE>,<CONTENT>#\n
    Device -> Server: *SCOR,OM,<IMEI>,<CMD>,<ARGS>#\n   (no 0xFFFF prefix)

Run this on the bridge's UPSTREAM_HOST:UPSTREAM_PORT (default 192.168.1.5:8000).
For local testing, change pythonserver.py UPSTREAM_HOST to "127.0.0.1".
"""

import asyncio

HOST = "0.0.0.0"
PORT = 8000

# Default IMEI used when sending instructions (overridden when first message arrives)
LAST_IMEI = {"value": "123456789123456"}

# Active client writer so the input loop can send to the bridge
CLIENT_WRITER = {"writer": None}
LAST_R0_KEY = {"value": "0"}    # Captured from R0 response, used by L0/L1


# ---------- Instruction templates the server can send to the device ----------
# These are Omni *SCOS,OM,<IMEI>,<TYPE>,... commands.
INSTRUCTIONS = {
    # --- Lock / Unlock (send R0 first, then L0 or L1) ---
    "1":  ("R0", "Unlock request (send before L0)",    "0,20,1234,1497689816"),
    "2":  ("L0", "Unlock command (uses R0 KEY)",       "{KEY},1234,1497689816"),
    "3":  ("R0", "Lock request (send before L1)",      "1,20,1234,1497689816"),
    "4":  ("L1", "Lock command (uses R0 KEY)",         "{KEY}"),
    # --- Settings ---
    "5":  ("S5", "IOT device settings (accel=3, S6=on, HB=240s, unlock=10s)", "3,2,240,10"),
    "6":  ("S7", "Scooter setting 1 (headlight=on, mode=high)",               "2,3,2,0"),
    "7":  ("S4", "Scooter setting 2 (low=15, med=20, high=25 km/h)",          "0,0,0,0,0,15,20,25"),
    # --- Queries ---
    "8":  ("S6", "Get scooter info",     ""),
    "9":  ("V0", "Beep: vehicle search", "2"),
    "a":  ("D0", "Get GPS",              ""),
    "b":  ("G0", "Get firmware version", ""),
    "c":  ("S1", "IOT Restart",          "2"),
    "d":  ("I0", "Get SIM ICCID",        ""),
    "e":  ("M0", "Get BLE MAC",          ""),
    # --- External Locks (L5) ---
    "f":  ("L5", "Unlock battery lock",    "1"),
    "g":  ("L5", "Lock battery lock",      "17"),
    "h":  ("L5", "Unlock cable/chain lock","3"),
    "i":  ("L5", "Lock cable/chain lock",  "19"),
    "j":  ("L5", "Get battery lock status","33"),
    "k":  ("L5", "Get chain lock status",  "35"),
}


def build_instruction(inst_type: str, content: str, imei: str) -> bytes:
    """Build an Omni server instruction: 0xFFFF + *SCOS,OM,<imei>,<type>,<content>#\n"""
    if content:
        msg = f"*SCOS,OM,{imei},{inst_type},{content}#\n"
    else:
        msg = f"*SCOS,OM,{imei},{inst_type}#\n"
    return b"\xff\xff" + msg.encode("ascii")


def parse_device_message(data: bytes):
    """Parse a device->server message: *SCOR,OM,<imei>,<cmd>,<args>#\n"""
    try:
        text = data.decode("ascii", errors="ignore").strip().strip("#")
        parts = text.split(",")
        if len(parts) >= 4 and parts[0] == "*SCOR":
            return {
                "vendor": parts[1],
                "imei":   parts[2],
                "cmd":    parts[3],
                "args":   parts[4:] if len(parts) > 4 else [],
            }
    except Exception as e:
        print(f"Parse error: {e}")
    return None


async def handle_bridge_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    print(f"\nBridge connected: {addr}")
    CLIENT_WRITER["writer"] = writer

    try:
        while True:
            data = await reader.read(2048)
            if not data:
                break

            print(f"\n[RECV] raw hex: {data.hex()}")

            # TCP may deliver multiple messages in one read.
            # Split on '#' which ends each Omni message.
            text = data.decode("ascii", errors="ignore")
            messages = [m.strip() for m in text.split("#") if m.strip()]

            for msg_text in messages:
                print(f"[RECV] {msg_text}#")
                parsed = parse_device_message((msg_text + "#").encode("ascii"))
                if parsed:
                    LAST_IMEI["value"] = parsed["imei"]
                    print(f"  vendor: {parsed['vendor']}")
                    print(f"  IMEI:   {parsed['imei']}")
                    print(f"  cmd:    {parsed['cmd']}")
                    print(f"  args:   {parsed['args']}")

                    if parsed["cmd"] == "R0":
                        # Capture the KEY for L0/L1
                        if len(parsed["args"]) >= 2:
                            LAST_R0_KEY["value"] = parsed["args"][1]
                            print(f"  >> R0 KEY captured: {LAST_R0_KEY['value']}")
                    elif parsed["cmd"] == "Q0":
                        print(f"  >> SIGN-IN received (voltage/battery/csq): {parsed['args']}")
                    elif parsed["cmd"] == "H0":
                        print(f"  >> HEARTBEAT received (lock/voltage/csq/batt/charging): {parsed['args']}")
                    elif parsed["cmd"] == "E0":
                        print(f"  >> FAULT CODE received: {parsed['args']}")
                        # Auto-acknowledge E0 back to bridge
                        ack = build_instruction("E0", "", parsed["imei"])
                        writer.write(ack)
                        await writer.drain()
                        print(f"  >> E0 acknowledged")
                else:
                    print(f"  (could not parse: {msg_text})")

    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"Bridge read error: {e}")
    finally:
        print(f"\nBridge disconnected: {addr}")
        if CLIENT_WRITER["writer"] is writer:
            CLIENT_WRITER["writer"] = None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def input_loop():
    """Interactive menu: send server instructions back to the bridge."""
    loop = asyncio.get_event_loop()

    while True:
        # Show menu
        print("\n--- Send Instruction to Device (via bridge) ---")
        for key, (inst_type, name, _) in INSTRUCTIONS.items():
            print(f"  {key}: {inst_type:4s} - {name}")
        print("  q: Quit")
        print(f"  (IMEI: {LAST_IMEI['value']}, R0 KEY: {LAST_R0_KEY['value']})")

        choice = await loop.run_in_executor(None, input, "> ")
        choice = choice.strip()

        if choice == "q":
            print("Quitting server.")
            for task in asyncio.all_tasks():
                if task is not asyncio.current_task():
                    task.cancel()
            break

        if choice not in INSTRUCTIONS:
            print(f"Unknown option: {choice}")
            continue

        inst_type, name, content = INSTRUCTIONS[choice]
        writer = CLIENT_WRITER["writer"]
        if writer is None:
            print("No bridge connected — cannot send.")
            continue

        # Substitute {KEY} with the last R0 KEY
        content = content.replace("{KEY}", LAST_R0_KEY["value"])

        packet = build_instruction(inst_type, content, LAST_IMEI["value"])
        print(f"[SEND] {inst_type} ({name})")
        print(f"[SEND] hex: {packet.hex()}")
        print(f"[SEND] str: {packet!r}")
        try:
            writer.write(packet)
            await writer.drain()
        except Exception as e:
            print(f"Send failed: {e}")


async def main():
    server = await asyncio.start_server(handle_bridge_client, HOST, PORT)
    print(f"Dummy main server listening on {HOST}:{PORT}")
    print("Waiting for bridge connection...")

    # Run server and input loop concurrently
    server_task = asyncio.create_task(server.serve_forever())
    input_task = asyncio.create_task(input_loop())

    try:
        await asyncio.gather(server_task, input_task)
    except asyncio.CancelledError:
        pass
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
