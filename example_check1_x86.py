import glitchoz0r3k

glitchoz0r3k.GLITCHES = [glitchoz0r3k.glitch.Skip]

g = glitchoz0r3k.Glitchozor()

g.open('testcases/check1_x64.elf')
g.set_start(0x00001306)
g.set_end(0x00001357)

ops = g.analyze()
print(f"Number of ops : {ops}")

def conditions(ctx):
    """
    Tests for registers to verify that our glitch worked
    """
    if ctx['regs']['rax'] == 0:
        return True
    else:
        return False

g.set_conditions(conditions)

for r in g.run():
    print(r['glitch_str'])
