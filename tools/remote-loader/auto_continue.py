"""auto_continue.py — beacon-driven auto-dismiss of the PS5 memory-crash dialog.

v3: press X IMMEDIATELY on crash detection (dialog appears at/after the crash,
not 45s later — the ~40s is session-start-to-crash, not crash-to-dialog).
If the dialog wasn't up yet at the first press, retries every 8s until a new
session boots (its beacons cancel the retries).

Usage:  python auto_continue.py     (Ctrl+C to stop)
"""
import os
import re
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, 'host-beacons.log')
DISMISS = r'D:\ps5\PS5-14.10-Research\tools\dismiss_dialog.py'
DIARY = os.path.join(HERE, 'auto_continue.log')
TERMINAL = ('NOLEAK', 'SCAN-END', 'WALK-FAIL', 'NOSELF', 'NOCLIENT', 'NOFACES',
            'NOTIN', 'RJ-', 'BASE-0x', 'ZONE-EXHAUSTED',
            'PATHB-DONE', 'PATHB-STOP', 'V17-DONE', 'V17-RESTORED', 'FACE-IDENTITY-FAIL', 'ADDROF-FAIL',
            'ADDROF-CERTIFIED', 'VERIFY-DONE', 'NOVP', 'NOORACLE')
SILENCE_CRASH_S = 12
LINE = re.compile(r'"t": "([^"]+)".*"path": "/beacon/V(6(78V2|83|84|86|87|88)|17)-([^"?]+)')


def log(msg):
    line = f'{datetime.now().strftime("%H:%M:%S")} {msg}'
    print(line, flush=True)
    with open(DIARY, 'a') as f:
        f.write(line + '\n')


def to_sec(t):
    h, m, s = t.split(':')
    return int(h) * 3600 + int(m) * 60 + int(s)


def press():
    log('pressing X (dismiss_dialog.py)')
    try:
        r = subprocess.run([sys.executable, DISMISS], capture_output=True, text=True, timeout=30)
        log(f'dismiss rc={r.returncode} out={r.stdout.strip()!r}')
    except Exception as e:
        log(f'dismiss FAILED: {e!r}')


def main():
    last_ts = None            # beacon time-of-day (seconds)
    last_beacon_wall = 0.0    # wall-clock of last beacon
    armed = False
    pos = 0
    retries = 0
    next_retry = None
    last_press_wall = 0.0
    log(f'watching {LOG}')
    while True:
        time.sleep(2)
        if os.path.exists(LOG):
            with open(LOG, 'rb') as f:
                f.seek(pos)
                chunk = f.read().decode('utf-8', 'replace')
                pos = f.tell()
            for line in chunk.splitlines():
                m = LINE.search(line)
                if not m:
                    continue
                clock, msg = m.group(1), m.group(3)
                last_ts = to_sec(clock)
                last_beacon_wall = time.time()
                if 'BOOT' in msg and not armed:
                    log('session BOOT — armed')
                    armed = True
                if any(k in msg for k in TERMINAL):
                    armed = False
                if time.time() - last_press_wall < 60:
                    retries = 0    # beacons after a press = dialog dismissed, new session
                    next_retry = None
        if armed and last_ts is not None:
            lt = time.localtime()
            now_sod = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec
            silence = (now_sod - last_ts) % 86400
            if silence > SILENCE_CRASH_S:
                log(f'crash signature: silence {silence}s — pressing X now')
                press()
                last_press_wall = time.time()
                armed = False
                retries = 2 if silence < 25 else 0   # retry only if dialog plausibly late
                next_retry = time.time() + 8 if retries else None
        if next_retry is not None and time.time() >= next_retry:
            if last_beacon_wall > last_press_wall:   # new session booted: cancel
                log('retry cancelled — new session booted')
                next_retry = None
                retries = 0
            else:
                log('retry X (dialog may have appeared late)')
                press()
                last_press_wall = time.time()
                retries -= 1
                next_retry = time.time() + 8 if retries > 0 else None


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log('stopped')
