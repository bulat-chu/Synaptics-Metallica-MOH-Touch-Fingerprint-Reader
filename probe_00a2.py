#!/usr/bin/env python3
"""
Staged, step-by-step probe of a Synaptics 06cb:00a2 fingerprint sensor on Linux.
It replays the command sequence that the Windows driver sent in the USB capture
and decodes the answers, using the TLS code from python-validity.

  Stage 1: read-only queries      01, 19, 43 02
  Stage 2: + the init blob the Windows driver sent, 3e, and read of TLS flash
           (40 01 ...), compared with the dump taken from the capture
  Stage 3: + TLS handshake using the existing pairing (needs the name/serial of
           the PC the sensor is paired with), then queries 01, 75, 43 02 over TLS

Nothing here calls factory-reset, flash-write, erase or firmware upload.
The init blob in stage 2 is a command with an unknown effect: it is exactly
what the Windows driver sent at the start of every session in the capture.
Run stage by stage and stop if an answer looks wrong.

Setup (Arch): sudo pacman -S python-pyusb python-cryptography git
              git clone https://github.com/uunicorn/python-validity
Run:          sudo python3 probe_00a2.py --repo ./python-validity --stage 1
"""
import argparse, atexit, logging, struct, sys, hashlib
from binascii import hexlify, unhexlify

# 581-byte blob sent by the Windows driver (packet 63 of the capture)
INIT_BLOB_HEX = (
    "06020000017f157bcf4f0360ff4dae96e4721ee8834bf6ab6f2828da9ad2b3ff40ab7e5176c478dd2459747722fc914b"
    "8b98b22d5a9574f52c0e8b257b952e7ce12ed46ef77801481d698006fd09e5a9a8d7e9ca705a79549b984504778513b7"
    "2668f9a5b7f41dd5537460ced2c46ac9a70e345638ba7cb04f3829105f64bd2ddf5a0cb418ad350b022d2eace9fe2104"
    "2e402bc9524bd87208271849c199280ffed5a881a547074fcaf33a22aec694f028b9cf56818d9792066e3bbfc72d6930"
    "050d45c9a2edeba1abd07f3b40e3830ff31aa9dab715f59bb150686d5648808a9ff9e775f58f6c6e3910eb1a579bb206"
    "178545d54c5dd32a0d3e247e64d73afe84d701b42a8920ea02768734221260d083bebb39c176d129c01d1a0f13884971"
    "71402ba041afd925d71e76ce4905e44fa5fd528759a2c9f12895864b5aa394dc71a4a17161dd82197a10742fa5f3135c"
    "5e78820e36653fa3db535f57c71897242939d7da50f81070ce9ab81c61af6ac29a6c6c4a5df73ffd08542fb540e41793"
    "9ed117298051d27736c2faf1c5577a2133b6f60ea7484c692faae2a49c51c8e6f69af77774bad51a9adeea3109d3611d"
    "6a437cdc0c356e46a8f9a6d3054c5519c17c986e54f61f8329006ce184c275984799dbdf5512188fa8ff10aa2ddc25eb"
    "697ebdcb156509309ade5d7909a734bf35ec69e062cb941c2ea4af0958110da93bd2b5f17fc9b1ebdbd8020a3c36f22a"
    "68f707226cec716126d6a830219521669bd59fa0e4bd35db6ef0aa2999d1c0e7acf67e598696cd58cc4bdb1b7c037ee9"
    "a085f784c4"
)

def st(rsp):
    return struct.unpack('<H', rsp[:2])[0] if len(rsp) >= 2 else None

def show(label, rsp):
    print('%-28s status=%s len=%d  %s' % (label, ('0x%04x' % st(rsp)) if st(rsp) is not None else '?', len(rsp), hexlify(rsp[:48]).decode()))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', default='./python-validity', help='path to the python-validity checkout')
    ap.add_argument('--stage', type=int, default=1, choices=[1, 2, 3])
    ap.add_argument('--name', help='stage 3: product name of the paired PC')
    ap.add_argument('--serial', help='stage 3: serial number of the paired PC')
    ap.add_argument('--expect-flash', default='tls_flash.bin', help='stage 2: dump from the capture to compare with')
    ap.add_argument('--log', default='probe_00a2.log')
    ap.add_argument('--no-reset', action='store_true', help='do not reset the USB device at exit')
    a = ap.parse_args()

    logging.basicConfig(filename=a.log, level=logging.DEBUG, format='%(message)s')
    sys.path.insert(0, a.repo)
    from validitysensor.usb import usb
    from validitysensor.tls import tls
    usb.trace_enabled = True
    tls.trace_enabled = False  # tls traces would log private keys

    usb.open(0x06cb, 0x00a2)
    print('opened 06cb:00a2')

    def _reset():
        # python-validity also resets the device at exit (Usb.close); this is
        # the software equivalent of re-plugging it, so the next run starts clean
        try:
            usb.dev.reset()
        except Exception as e:
            logging.debug('reset at exit failed: %r', e)
    if not a.no_reset:
        atexit.register(_reset)

    # ---- stage 1 ----
    r = usb.cmd(unhexlify('01')); show('01 (rom info)', r)
    if len(r) >= 18:
        ts, build, major, minor, prod, u1 = struct.unpack('<LLBBxBxxxB', r[2:18])
        print('   timestamp=%d build=%d major=%d minor=%d product=0x%02x u1=%d' % (ts, build, major, minor, prod, u1))
    show('19', usb.cmd(unhexlify('19')))
    r = usb.cmd(unhexlify('4302')); show('43 02 (fw info)', r)
    if a.stage == 1:
        print('stage 1 done, log: ' + a.log); return

    # ---- stage 2 ----
    show('init blob (581 bytes)', usb.cmd(unhexlify(INIT_BLOB_HEX.replace('\n', '').replace(' ', ''))))
    show('3e', usb.cmd(unhexlify('3e')))
    # read_flash(partition=1, addr=0, size=0x1000), same bytes as in the capture
    r = usb.cmd(struct.pack('<BBBHLL', 0x40, 1, 1, 0, 0, 0x1000))
    show('40 (read TLS flash)', r)
    size = struct.unpack('<xxLxx', r[:8])[0]
    flash = r[8:8+size]
    open('tls_flash_live.bin', 'wb').write(flash)
    try:
        exp = open(a.expect_flash, 'rb').read()
        print('flash equals dump from capture:', exp == flash)
    except OSError:
        print('no', a.expect_flash, 'to compare with; saved tls_flash_live.bin')
    if a.stage == 2:
        print('stage 2 done, log: ' + a.log); return

    # ---- stage 3 ----
    if not (a.name and a.serial):
        sys.exit('stage 3 needs --name and --serial')
    tls.set_hwkey(a.name, a.serial)
    tls.parse_tls_flash(flash)
    print('client key decrypted (pairing matches this name/serial)')
    tls.open()
    print('TLS handshake finished')
    show('01 over TLS', tls.cmd(unhexlify('01')))
    show('75 over TLS (sensor id)', tls.cmd(unhexlify('75')))
    show('43 02 over TLS', tls.cmd(unhexlify('4302')))
    print('stage 3 done, log: ' + a.log)

if __name__ == '__main__':
    main()
