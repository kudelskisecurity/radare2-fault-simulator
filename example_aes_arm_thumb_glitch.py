import glitchoz0r3k
import phoenixAES

from aeskeyschedule import reverse_key_schedule
from binascii import unhexlify

glitchoz0r3k.GLITCHES = [glitchoz0r3k.glitch.Skip]

g = glitchoz0r3k.Glitchozor()

g.open('testcases/aes_arm_thumb.elf')
g.set_start(0x00009488)
g.set_end(0x000094d0)
#ops = g.analyze()
#print(f"Number of ops : {ops}")
g.steps = 36965

# Glitch from cycle 21700 to 20000
g.set_glitch_start(32000)
g.set_glitch_end(33000)

# Need more time to perform semulation
g.set_timeout(32)

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
        return True

def dfa():
    subkey10 = phoenixAES.crack_file("testcases/aes_arm_thumb_tracefile", verbose=0)
    base_key = reverse_key_schedule(unhexlify(subkey10), 10)
    print("Main key:")
    print(base_key.hex().upper())

if __name__ == '__main__':
    g.set_conditions(conditions)
    ref = bytearray.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    f = open("testcases/aes_arm_thumb_tracefile", "w")
    f.write(ref.hex() + "\n")
    for r in g.run():
        f.write(bytes(r['stack'][192:208]).hex() + "\n")
    f.close()
    dfa()
