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
import json
from multiprocessing import Pool, TimeoutError
import os
import sys

import r2pipe
from tqdm import tqdm


MAX_INSTRS = 50000

import glitch
GLITCHES = [glitch.Skip, glitch.ZeroSReg, glitch.ZeroDReg]

class Glitchozor():

    def __init__(self):
        self.binary = ''
        self.steps = 0
        self.glitch_start = 0
        self.glitch_end = None
        self._check_func = lambda x: True
        self._init_instrs = []
        self.timeout = 2

    def open(self, binary):
        if os.path.isfile(binary):
            self.binary = binary
        else:
            raise Exception("File does not exist")

    def set_timeout(self, timeout):
        """
        Sets the timeout for the emulator
        """
        self.timeout = timeout

    def set_start(self, address):
        """
        Sets the base address for the session
        """
        if type(address) == int:
            self.start = address
        else:
            self.start = int(address, 0)

    def set_end(self, address):
        """
        Sets the end address for the session
        """
        if type(address) == int:
            self.end = address
        else:
            self.end = int(address, 0)
    
    def set_glitch_start(self, cycle):
        """
        Sets the starting point in cycles for the glitch.
        """
        if type(cycle) == int:
            self.glitch_start = cycle
        else:
            self.glitch_start = int(cycle, 0)
        
        assert(0 < self.glitch_start < self.steps)

    def set_glitch_end(self, cycle):
        """
        Sets the end cycle for the glitch.
        """
        if type(cycle) == int:
            self.glitch_end = cycle
        else:
            self.glitch_end = int(cycle, 0)

        assert(0 < self.glitch_end < self.steps)

    def set_conditions(self, function):
        """
        Set a glitch checker
        function should either return True (=valid glitch) or False
        """
        self._check_func = function

    def analyze(self):
        """
        Get the number of instructions to emulate
        """
        e = Emulator(self.binary)
        e.set_start(self.start)
        e.set_end(self.end)
        self.steps = e.analyze()
        return self.steps

    def add_init_command(self, cmd):
        """
        Add a command that will be passed to the emulator before running the
        simulation

        This is useful to set register values, stack, ...

        Example:
            >>>g = Glitchozor('/tmp/test.elf')
            >>>g.add_init_command('aer SP=(BP-0x60)')
            >>>g.add_init_command('aer rsi =SP+0x10')
            >>>g.add_init_command('aer rdi =SP+0x20')
            >>>g.add_init_command('aer rdx =SP+0x30')
        """
        self._init_instrs.append(cmd)

    def _emu_process(self, steps, glitch):
        """
        Emulation task
        """
        e = Emulator(self.binary)
        e.set_start(self.start)
        e.set_end(self.end)
        e.init_cmds = self._init_instrs
        ret =  e.run_pass(steps, glitch)
        e._process.kill()
        return ret

    def _emu_worker(self, steps, glitch):
        """
        Wrapper to get emulator timeout possible
        """
        #return self._emu_process(steps, glitch)
        from multiprocessing.dummy import Pool as ThreadPool
        p = ThreadPool(1)
        res = p.apply_async(self._emu_process, (steps, glitch))
        try:
            out = res.get(self.timeout)  # Wait timeout seconds for func to complete.
            p.terminate()
            return out
        except TimeoutError:
            raise


    def run(self, nb_process=4):
        """
        Run the simulation
        """
        pool = Pool(processes=nb_process, maxtasksperchild=5)
        result = []
        processes = []

        if self.glitch_end == None:
            self.glitch_end =self.steps
        
        for i in range(self.glitch_start,self.glitch_end):
            processes += [pool.apply_async(self._emu_worker, (i,g)) for g in GLITCHES]
        for process in tqdm(processes, file=sys.stdout):
            try:
               x = process.get(timeout=self.timeout)
               if self._check_func(x):
                   result.append(x)
            except TimeoutError as e:
                pass
            except KeyboardInterrupt:
                sys.exit(0)
            except TypeError:
                pass
            except BrokenPipeError:
                pass
        pool.terminate()
        return result


class Emulator():

    def __init__(self, binary = ''):
        if binary != '':
            self._pipe = r2pipe.open(binary, flags=['-2'])
            self._process = self._pipe.process
        self.start = 0
        self.end = 0
        self._instr_count = 0
        self._instr_cache = []
        self._reg_cache = []
        self.init_cmds = []

    def __del__(self):
        try:
            self._pipe.quit()
        except:
            pass
        finally:
            self._process.kill()

    def _reset_emu(self):
        self._pipe.cmd(f's {self.start}') 
        self._pipe.cmd('aer0')
        self._pipe.cmd('aei')
        self._pipe.cmd('aeim')
        self._pipe.cmd('aeip')

        for cmd in self.init_cmds:
            self._pipe.cmd(cmd)

    def set_start(self, address):
        """
        Sets the base address for the emulator
        """
        self.start = address

    def set_end(self, address):
        """
        Sets the end address for the emulator
        """
        self.end = address

    def get_instr(self):
        return self._pipe.cmdj('pdj 1@PC')[0]

    def print_instr(self):
        instr = self.get_instr()
        print(hex(instr['offset']), instr['opcode'])

    def get_ip(self):
        return self._pipe.cmd("aer PC").strip()

    def analyze(self):
        """
        Perform a first trace to get the number of instructions
        """
        self._reset_emu()
        self._instr_count = 0
        while(int(self._pipe.cmd('aer PC'), 0) != self.end and self._instr_count < MAX_INSTRS):
            self._instr_cache.append(self.get_instr())
            self._instr_count += 1 
            self._pipe.cmd('aes')
        self._reg_cache = self._pipe.cmdj('aerj')
        self._stack_cache = self._pipe.cmdj('pxj (BP-SP)@SP')
        return self._instr_count

    def run_pass(self, steps, glitch_class):
        """
        Run a simulation pass

        :param steps: Number of steps to simulate before inserting glitch
        :param glitch_class: Glitch class to simulate

        :return: dictionnary containing the simulation state :
            glitch_str : representation of the simulated glitch
            stack : contents of the stack
            regs : registers
        """
        retval = {}

        self._reset_emu()
        if steps==0:
            pass
        else:
            self._pipe.cmd(f"{steps} aes")

        glitch_str = glitch_class.apply(self._pipe)
        if glitch_str is None:
            return
        retval.update({'glitch_str':f"{glitch_str}(count={steps})"})

        self._pipe.cmd(f"aecu {self.end}")
        stack = self._pipe.cmdj('pxj (BP-SP)@SP')
        retval.update({'stack':stack})

        end_reg = self._pipe.cmdj('aerj')
        retval.update({'regs':end_reg})

        self._pipe.quit()

        #TODO return stack memory
        return retval

if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="filename",
                      help="File to analyze", metavar="FILE")
    parser.add_option("-s", "--start", dest="start_addr",
                      help="Start address")
    parser.add_option("-e", "--end", dest="end_addr",
                      help="End address")
    parser.add_option("--glitch_start", dest="glitch_start",
                      help="Glitch start")
    parser.add_option("--glitch_end", dest="glitch_end",
                      help="Glitch end")
    parser.add_option("-t", "--threads", dest="threads",
                      type=int, default=2, help="Number of threads")
    parser.add_option("-r", "--reg", dest="reg",
                      type=str, default="rax", help="Register to check")

    (options, args) = parser.parse_args()

    print("""
             ████████
           ███▄███████
           ███████████
           ███████████
           ██████
           █████████         ▗▄ ▝▜   ▝   ▗      ▐            ▄▄          ▄▄  ▄▄  ▄▄  ▄▄
 █       ███████            ▗▘ ▘ ▐  ▗▄  ▗▟▄  ▄▖ ▐▗▖  ▄▖ ▗▄▄ ▗▘▝▖ ▖▄     ▝ ▝▌▗▘▝▖▗▘▝▖▗▘▝▖
 ██    ████████████         ▐ ▗▖ ▐   ▐   ▐  ▐▘▝ ▐▘▐ ▐▘▜   ▞ ▐ ▖▌ ▛ ▘     ▗▄▘▐ ▖▌▐ ▖▌▐ ▖▌
 ███  ██████████  █         ▐  ▌ ▐   ▐   ▐  ▐   ▐ ▐ ▐ ▐  ▞  ▐  ▌ ▌        ▝▌▐  ▌▐  ▌▐  ▌
 ███████████████             ▚▄▘ ▝▄ ▗▟▄  ▝▄ ▝▙▞ ▐ ▐ ▝▙▛ ▐▄▄  ▙▟  ▌      ▝▄▟▘ ▙▟  ▙▟  ▙▟
           ███████████████
  █████████████
   ███████████
     ████████
      ███  ██
      ██    █
   █     █
      ██    ██
 """)

    g = Glitchozor()

    if options.filename == None or options.start_addr == None or options.end_addr == None:
        parser.print_help()
        exit()
    g.open(options.filename)
    g.set_start(options.start_addr)
    g.set_end(options.end_addr)
    ops = g.analyze()
    print(f"Number of ops : {ops}")

    def conditions(ctx):
        """
        Tests for registers to verify that our glitch worked
        """
        if ctx['regs'][options.reg] == 0:
            return True
        else:
            return False

    g.set_conditions(conditions)

    for r in g.run(options.threads):
        print(r['glitch_str'])
