#!/usr/bin/env python3
"""Raw UART capture via pyserial — bypasses macOS tty canonical mode."""
import serial, sys, time, os

PORT = '/dev/cu.usbmodem212403'
BAUD = 115200
LOG  = sys.argv[1] if len(sys.argv) > 1 else f'uart_capture_{int(time.time())}.log'

print(f'[uart_capture] Opening {PORT} @ {BAUD}, writing to {LOG}', flush=True)
with serial.Serial(PORT, BAUD, timeout=1,
                   bytesize=serial.EIGHTBITS,
                   parity=serial.PARITY_NONE,
                   stopbits=serial.STOPBITS_ONE,
                   xonxoff=False, rtscts=False, dsrdtr=False) as ser:
    ser.dtr = False  # prevent ST-Link DTR from resetting STM32
    ser.rts = False
    with open(LOG, 'wb') as f:
        while True:
            chunk = ser.read(256)
            if chunk:
                f.write(chunk)
                f.flush()
