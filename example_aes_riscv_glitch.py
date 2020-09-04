import glitchoz0r3k
import phoenixAES

from aeskeyschedule import reverse_key_schedule
from binascii import unhexlify

glitchoz0r3k.GLITCHES = [glitchoz0r3k.glitch.Skip]

g = glitchoz0r3k.Glitchozor()

g.open('testcases/aes_riscv_compress.elf')
g.set_start(0x0001011a)
g.set_end(0x0001019e)
#ops = g.analyze()
#print(f"Number of ops : {ops}")
g.steps = 26675

# Glitch from cycle 21700 to 20000
g.set_glitch_start(21700)
g.set_glitch_end(22000)

# Need more time to perform simulation
g.set_timeout(8)

print(f"Number of ops : {g.steps}")

def conditions(ctx):
    """
    Tests for stack to verify that our glitch worked
    ie. a fault occured during the AES computation
    """
    buff = bytes(ctx['stack'][192:208])
    if buff.hex() == "3ad77bb40d7a3660a89ecaf32466ef97":
        return False
    else:
        print(f"{ctx['glitch_str']} - {buff.hex()}")
        return True

def dfa():
    subkey10 = phoenixAES.crack_file("testcases/tracefile.orig", verbose=1)
    base_key = reverse_key_schedule(unhexlify(subkey10), 10)
    print("Main key:")
    print(base_key.hex().upper())

if __name__ == '__main__':
    g.set_conditions(conditions)
    ref = bytearray.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    f = open("testcases/tracefile", "w")
    f.write(ref.hex() + "\n")
    for r in g.run():
        f.write(bytes(r['stack'][192:208]).hex() + "\n")
    f.close()
    dfa()