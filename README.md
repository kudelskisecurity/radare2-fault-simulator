# Glitch simulation

Tool to simulate fault injection in a firmware using the ESIL of radare2.
For each instruction of a firmware between the start address and the stop address the simulation replaces the current instruction by another according to the defined fault model and execute the resulting code.
If a specific success condition is matched then the fault model and instruction is reported.

## Installation
Python3 is mandatory to run glitch simulation. Requirement package can be install with
```bash
pip3 install -r requirements.txt --user
```

## Usage
```bash
glitchoz0r3k.py [options]
```

Options:

  -h, --help: show the help message and exit

  -f FILE, --file=FILE:  File to analyze

  -s START_ADDR, --start=START_ADDR: Start address
  
  -e END_ADDR, --end=END_ADDR: End address

  -t THREADS, --threads=THREADS: Number of threads

  -r REG, --reg=REG: Register to check

The fault model are defined in the **glitch.py** module. New fault models may be added there.

The success condition is defined in the **conditions** function of **glitchoz0r3k.py** module.

After usage run the **r2kill.sh** script in order to terminate all the process launched.

## Test

The **target_glitch.py** script runs the x86-64 example:
```bash
python3 target_glitch.py
```

## Advanced usage

It is possible to create a custom script to run a simulation.

```python
import glitchoz0r3k

#Instantiate the tool
g = glitchoz0r3k.Glitchozor()

#Open the executable file
g.open('testcases/target')

#Set the address where to start the simulation
g.set_start(0x00001155)
#Set the address where to end the simulation
g.set_end(0x00001297)

#Run the analyze() function to calculate the number of operations.
#This has to be made before running the actual simulation
ops = g.analyze()
print(f"Number of ops : {ops}")
```

Once the initial setup is done, it is required to setup a condition function. This function will be called at the end of every simulation and will be passed a `ctx` dictionnary.
This function must return `True` if the glitch succeded (ie. the glitch caused a desired state)

```python
#Define a condition function
def conditions(ctx):
    """
    Tests for registers to verify that our glitch worked
    """
    if ctx['regs']['rax'] == 0:
        return True
    else:
        return False

#Set the condition checking for the sumulation instance
g.set_conditions(conditions)
```


The `ctx` dictionnary contains the following information :

 * `glitch_str` : The applied glitch in text form
 * `regs` : All the register status at the end of the simulation. This is architecture-dependant (eg. ctx['regs']['eax'])
 * `stack` : The full stack contents, starting from the stack pointer to the base pointer.


Finally, the simulation can be started using this following code :

```python
for r in g.run():
    print(r['glitch_str'])
```


## Adding new glitch models

The `glitch.py` contains all the glitch models. To add a new model, simply create a new class inheriting the `Glitch` class.

The tool currently contains the following models :

 * `Skip` : Skip the current instruction
 * `ZeroSReg` : Reset the source register for the current instruction to 0 before execution
 * `ZeroDReg` : Reset the destination register for the current instruction to 0 after execution

## Cleaning stalled workers

In the case a simulation crashes or is stucked in an infinite loop, it might be necessary to kill stalled workers. In order to do that you can use the following bash script:

```bash
#!/bin/bash
while true
do
    (ps -ef; sleep 9) | grep 'radare2' | grep -v grep | awk '{print $2}' | xargs kill
done
```