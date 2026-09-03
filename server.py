#!/usr/bin/env python3
"""
Modbus/TCP rich test server for parser/analyzer comparison.

Creates two slave/unit IDs with coils, discrete inputs, holding registers,
and input registers populated with recognizable patterns. Intended for a
local lab capture only.

Tested target: pymodbus 3.x. Install with:
    python -m pip install pymodbus

Run:
    python server.py --host 127.0.0.1 --port 1502
"""

import argparse
import logging
from itertools import cycle

try:
    from pymodbus.server import StartTcpServer
except ImportError:  # older pymodbus
    from pymodbus.server.sync import StartTcpServer

try:
    from pymodbus.datastore import (
        ModbusSparseDataBlock,
        ModbusServerContext,
        ModbusDeviceContext as _ModbusUnitContext,
    )
    _CONTEXT_KW = "devices"      # pymodbus >= 3.10-ish
except ImportError:
    from pymodbus.datastore import (
        ModbusSequentialDataBlock,
        ModbusServerContext,
        ModbusSlaveContext as _ModbusUnitContext,
    )
    _CONTEXT_KW = "slaves"       # older pymodbus

try:
    from pymodbus import ModbusDeviceIdentification
except ImportError:
    from pymodbus.device import ModbusDeviceIdentification


LOG = logging.getLogger("modbus-rich-server")


def bit_pattern(length: int, offset: int = 0):
    """Alternating but non-trivial boolean pattern."""
    pat = [False, True, True, False, True, False, False, True]
    c = cycle(pat[offset % len(pat):] + pat[:offset % len(pat)])
    return [next(c) for _ in range(length)]


def register_pattern(length: int, base: int):
    """16-bit words with edge values, ASCII-ish values, counters, and patterns."""
    seed = [
        0x0000, 0x0001, 0x0002, 0x000A, 0x00FF, 0x0100, 0x1234, 0x7FFF,
        0x8000, 0xABCD, 0xBEEF, 0xCAFE, 0xFF00, 0xFFFE, 0xFFFF,
        0x4D4F, 0x4442, 0x5553,  # "MODBUS" as 16-bit ASCII chunks
    ]
    values = []
    for i in range(length):
        if i < len(seed):
            values.append(seed[i])
        else:
            values.append((base + i * 37 + (i << 4)) & 0xFFFF)
    return values


def data_block(values):
    """Create a block starting at address 0 across pymodbus versions."""
    if "ModbusSparseDataBlock" in globals():
        return ModbusSparseDataBlock({0: values})
    return ModbusSequentialDataBlock(0, values)


def make_slave(unit_id: int):
    kwargs = dict(
        di=data_block(bit_pattern(256, unit_id)),
        co=data_block(bit_pattern(256, unit_id + 3)),
        hr=data_block(register_pattern(512, 0x1000 * unit_id)),
        ir=data_block(register_pattern(512, 0x2000 * unit_id)),
    )
    try:
        # Older pymodbus supports zero_mode, which makes client address 0 map to block index 0.
        return _ModbusUnitContext(**kwargs, zero_mode=True)
    except TypeError:
        return _ModbusUnitContext(**kwargs)


def build_context() -> ModbusServerContext:
    slaves = {
        1: make_slave(1),
        2: make_slave(2),
        17: make_slave(17),
    }
    if _CONTEXT_KW == "devices":
        return ModbusServerContext(devices=slaves, single=False)
    return ModbusServerContext(slaves=slaves, single=False)


def build_identity() -> ModbusDeviceIdentification:
    identity = ModbusDeviceIdentification()
    identity.VendorName = "PCAP Parser Lab"
    identity.ProductCode = "RICH-MBTCP"
    identity.VendorUrl = "https://example.invalid/local-lab"
    identity.ProductName = "Rich Modbus TCP Traffic Generator"
    identity.ModelName = "pymodbus-server"
    identity.MajorMinorRevision = "1.0"
    return identity


def main():
    parser = argparse.ArgumentParser(description="Rich Modbus/TCP server for PCAP generation")
    parser.add_argument("--host", default="127.0.0.1", help="bind address, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=1502, help="TCP port, default: 1502")
    parser.add_argument("--debug", action="store_true", help="enable pymodbus debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    LOG.info("Starting Modbus/TCP server on %s:%s", args.host, args.port)
    LOG.info("Serving unit IDs: 1, 2, 17")
    LOG.info("Capture example: tcpdump -i lo -w modbus-rich.pcap 'tcp port %s'", args.port)

    StartTcpServer(
        context=build_context(),
        identity=build_identity(),
        address=(args.host, args.port),
    )


if __name__ == "__main__":
    main()
