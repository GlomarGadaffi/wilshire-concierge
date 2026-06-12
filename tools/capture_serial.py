#!/usr/bin/env python3
"""Reset the ESP32-S3 over COM5 and capture boot output until the glo_mtls
self-test reports completion (or a timeout). Used to verify on-device KATs."""
import sys, time
import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM5"
DEADLINE = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
BREAK_ON = sys.argv[3].encode() if len(sys.argv) > 3 else b"self-test complete"

ser = serial.Serial(PORT, 115200, timeout=0.2)
# Classic auto-reset: RTS -> EN. Pulse low to reset, IO0 high = run app.
ser.setDTR(False)
ser.setRTS(True)
time.sleep(0.15)
ser.setRTS(False)

start = time.time()
buf = b""
while time.time() - start < DEADLINE:
    data = ser.read(4096)
    if not data:
        continue
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
    buf += data
    if BREAK_ON and BREAK_ON in buf:
        time.sleep(0.5)
        tail = ser.read(8192)
        sys.stdout.buffer.write(tail)
        sys.stdout.flush()
        break
ser.close()
print("\n[capture] done")
