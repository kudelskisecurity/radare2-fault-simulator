"""
Copyright (c) 2020 Kudelski Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

class Glitch():
    """
    Base glitch class
    """

    @classmethod
    def apply(self, pipe):
        return ""

class Skip(Glitch):
    """
    Simple glitch. Skips the instruction
    """

    def apply(pipe):
        cur_instr = pipe.cmdj("pdj 1@PC")[0]
        new_addr = cur_instr['offset']+cur_instr['size']
        pipe.cmd('aer PC = '+hex(new_addr))
        return f"Skip {cur_instr['disasm']} @ {hex(cur_instr['offset'])}"

class ZeroSReg(Glitch):
    """
    Zero source register

    TODO: Add support for multiple register glitches
    """

    def apply(pipe):
        cur_instr = pipe.cmdj("pdj 1@PC")[0]
        changes = pipe.cmdj('aeaj 1@PC')
        try:
            reg = changes['I'][0]
            pipe.cmd(f"aer {reg} = 0")
            return f"Zero {reg} in {cur_instr['disasm']} @ {hex(cur_instr['offset'])}"
        except:
            return None

class ZeroDReg(Glitch):
    """
    Zero destination register

    TODO: Add support for multiple register glitches
    """

    def apply(pipe):
        cur_instr = pipe.cmdj("pdj 1@PC")[0]
        changes = pipe.cmdj('aeaj 1@PC')
        try:
            reg = changes['W'][0]
            pipe.cmd(f"aer {reg} = 0")
            return f"Zero {reg} in {cur_instr['disasm']} @ {hex(cur_instr['offset'])}"
        except:
            return None
