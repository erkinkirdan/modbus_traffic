#!/usr/bin/env python3
"""
Modbus/TCP rich test client for parser/analyzer comparison.

Generates diverse Modbus/TCP traffic against server.py:
  - Reads coils, discrete inputs, holding registers, input registers
  - Writes single coil/register and multiple coils/registers
  - Mask write register and read/write multiple registers when supported
  - Device identification request when supported
  - Multi-unit traffic, boundary-ish reads, transaction variation
  - Intentional exception responses for invalid addresses and unsupported unit IDs
  - Optional reconnects to create multiple TCP sessions

Install:
    python -m pip install pymodbus

Run while server.py is running:
    python client.py --host 127.0.0.1 --port 1502 --loops 3 --delay 0.05 --reconnect
"""

import argparse
import logging
import random
import time
from typing import Any, Callable

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:  # older pymodbus
    from pymodbus.client.sync import ModbusTcpClient

LOG = logging.getLogger("modbus-rich-client")


def is_error(response: Any) -> bool:
    return response is None or (hasattr(response, "isError") and response.isError())


def call(client: ModbusTcpClient, method_name: str, *args, slave: int = 1, **kwargs):
    """Call pymodbus methods across keyword changes: device_id, slave, unit."""
    method: Callable = getattr(client, method_name)
    started = time.perf_counter()
    last_error = None
    for key in ("device_id", "slave", "unit"):
        try:
            response = method(*args, **{key: slave}, **kwargs)
            break
        except TypeError as exc:
            last_error = exc
    else:
        raise last_error
    elapsed_ms = (time.perf_counter() - started) * 1000

    status = "EXCEPTION/ERROR" if is_error(response) else "OK"
    LOG.info("unit=%s %-28s args=%s kwargs=%s -> %s in %.1f ms: %s",
             slave, method_name, args, kwargs, status, elapsed_ms, response)
    return response


def safe_call(client: ModbusTcpClient, method_name: str, *args, slave: int = 1, **kwargs):
    """Run a request if the installed pymodbus client exposes it."""
    if not hasattr(client, method_name):
        LOG.warning("Skipping %s: not available in this pymodbus version", method_name)
        return None
    try:
        return call(client, method_name, *args, slave=slave, **kwargs)
    except Exception as exc:
        LOG.warning("%s failed locally before/after request: %r", method_name, exc)
        return None


def connect_client(host: str, port: int, timeout: float) -> ModbusTcpClient:
    client = ModbusTcpClient(host=host, port=port, timeout=timeout)
    if not client.connect():
        raise SystemExit(f"Could not connect to Modbus/TCP server at {host}:{port}")
    return client


def normal_sequence(client: ModbusTcpClient, unit: int):
    # Common read function codes: 0x01, 0x02, 0x03, 0x04
    call(client, "read_coils", 0, count=13, slave=unit)
    call(client, "read_coils", 10, count=20, slave=unit)
    call(client, "read_discrete_inputs", 0, count=11, slave=unit)
    call(client, "read_discrete_inputs", 13, count=19, slave=unit)
    call(client, "read_holding_registers", 0, count=16, slave=unit)
    call(client, "read_holding_registers", 120, count=10, slave=unit)
    call(client, "read_input_registers", 0, count=16, slave=unit)
    call(client, "read_input_registers", 200, count=8, slave=unit)

    # Common write function codes: 0x05, 0x06, 0x0F, 0x10
    call(client, "write_coil", 5, True, slave=unit)
    call(client, "write_coil", 6, False, slave=unit)
    call(client, "write_register", 7, 0x1234, slave=unit)
    call(client, "write_register", 8, 0xFFFF, slave=unit)
    call(client, "write_coils", 20, [True, False, True, True, False, False, True, False, True, True], slave=unit)
    call(client, "write_registers", 30, [0x0000, 0x0001, 0x7FFF, 0x8000, 0xABCD, 0xFFFF], slave=unit)

    # Verify writes with follow-up reads to create request/response pairs analyzers can correlate.
    call(client, "read_coils", 0, count=32, slave=unit)
    call(client, "read_holding_registers", 0, count=40, slave=unit)

    # Less-common function codes, support depends on pymodbus version/server behavior.
    safe_call(client, "mask_write_register", 9, 0x00FF, 0x5500, slave=unit)  # FC 0x16
    safe_call(client, "readwrite_registers", 40, 8, 50, [0x1111, 0x2222, 0x3333, 0x4444], slave=unit)  # FC 0x17
    safe_call(client, "read_device_information", slave=unit)  # MEI 0x2B/0x0E when supported


def exception_sequence(client: ModbusTcpClient):
    # These intentionally provoke Modbus exception responses for parser comparison.
    # Out-of-range addresses/counts against our limited datastore.
    for unit in (1, 2, 17):
        safe_call(client, "read_holding_registers", 65000, count=10, slave=unit)
        safe_call(client, "read_coils", 65000, count=16, slave=unit)
        safe_call(client, "write_register", 65000, 0x2222, slave=unit)

    # Unsupported unit/server ID should usually timeout or error at this server.
    safe_call(client, "read_holding_registers", 0, count=4, slave=99)

    # Illegal counts. Some pymodbus versions reject these locally before sending,
    # which is still useful to know during test generation.
    safe_call(client, "read_coils", 0, count=0, slave=1)
    safe_call(client, "read_holding_registers", 0, count=126, slave=1)
    safe_call(client, "write_registers", 0, [], slave=1)


def randomized_sequence(client: ModbusTcpClient, unit: int, requests: int):
    ops = [
        lambda: call(client, "read_coils", random.randint(0, 220), count=random.randint(1, 24), slave=unit),
        lambda: call(client, "read_discrete_inputs", random.randint(0, 220), count=random.randint(1, 24), slave=unit),
        lambda: call(client, "read_holding_registers", random.randint(0, 480), count=random.randint(1, 20), slave=unit),
        lambda: call(client, "read_input_registers", random.randint(0, 480), count=random.randint(1, 20), slave=unit),
        lambda: call(client, "write_coil", random.randint(0, 220), random.choice([True, False]), slave=unit),
        lambda: call(client, "write_register", random.randint(0, 480), random.randint(0, 0xFFFF), slave=unit),
        lambda: call(client, "write_coils", random.randint(0, 220), [random.choice([True, False]) for _ in range(random.randint(2, 16))], slave=unit),
        lambda: call(client, "write_registers", random.randint(0, 470), [random.randint(0, 0xFFFF) for _ in range(random.randint(2, 12))], slave=unit),
    ]
    for _ in range(requests):
        random.choice(ops)()


def main():
    parser = argparse.ArgumentParser(description="Generate rich Modbus/TCP client traffic")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1502)
    parser.add_argument("--loops", type=int, default=2, help="number of deterministic passes")
    parser.add_argument("--random", type=int, default=20, help="random requests per loop")
    parser.add_argument("--delay", type=float, default=0.05, help="delay between major groups")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--reconnect", action="store_true", help="close/reopen TCP connection each loop")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    random.seed(0xBEEF)  # deterministic traffic mix

    client = connect_client(args.host, args.port, args.timeout)
    try:
        for loop in range(args.loops):
            LOG.info("=== loop %s/%s ===", loop + 1, args.loops)
            if args.reconnect and loop > 0:
                client.close()
                time.sleep(args.delay)
                client = connect_client(args.host, args.port, args.timeout)

            for unit in (1, 2, 17):
                normal_sequence(client, unit)
                randomized_sequence(client, unit, args.random)
                time.sleep(args.delay)

            exception_sequence(client)
            time.sleep(args.delay)
    finally:
        client.close()
        LOG.info("Done")


if __name__ == "__main__":
    main()
