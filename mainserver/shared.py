"""
DiLu CCU GPRS Protocol - Shared utilities

CRC16 algorithm from Appendix 3 of the protocol spec.
Polynomial: 0xA001 (CRC-16/MODBUS), init: 0xFFFF, result byte-swapped (sw16).
Per section 2.4.2: CRC16 is calculated on data content only.

Verified against spec section 5.3: heartbeat content 0x03 -> CRC 0xFF 0x41.
"""


def calculate_crc16(content: bytes) -> bytes:
    """
    CRC16 per DiLu Appendix 3.
    Input: data content bytes only (not start code or length).
    Returns: 2 bytes as they appear on the wire (per spec example).
    """
    crc = 0xFFFF

    for byte in content:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1

    # sw16: swap high and low bytes. Store swapped value in memory order.
    # For content=0x03: raw crc=0x41FF -> sw16=0xFF41 -> bytes FF 41.
    swapped = ((crc & 0xFF) << 8) | ((crc >> 8) & 0xFF)
    return bytes([(swapped >> 8) & 0xFF, swapped & 0xFF])
