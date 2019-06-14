# RevEngE - A trace-based decompiler for reverse engineer
# Author: Marcus Botacin
# Supporter: Lucas Galante
# Creation: UFPR, 2018

# External Module Imports
import gdb          # GDB control
import re           # String manipulation
import os           # filesystem interaction
import subprocess   # external tools
import sys          # path adjusts

# Path Adjust
path = os.path.dirname(os.path.abspath(__file__))
module_path = os.path.join(path,"src/")
sys.path.append(module_path)

# Internal Module Imports
from introspection import * # Function Introspection Module

# Solution Name to be printed for user warnings
PROMPT = "(RevEngE)"

# File Manager
class FileManager():
    # instantiate
    def __init__(self):
        # decompiled sources will be stored here
        self.source_files = "sources"
        # decompiled binaries will be stored here
        self.bin_files = "bins"
        # check if exists, if not, create
        if not os.path.exists(self.source_files):
            os.makedirs(self.source_files)
        if not os.path.exists(self.bin_files):
            os.makedirs(self.bin_files)

    # create a source file
    def create_source(self,name):
        self.name = name
        self.source_path = self.source_files+"/"+name+".c"
        self.source = open(self.source_path,"w+")
        return self.source

    # close a source file, then ident
    def close_source(self):
        self.source.close()
        self.ident_source_file()

    # ident file
    def ident_source_file(self):
        # call GNU's indent
        cmd = ["indent",self.source_path]
        s = subprocess.Popen(cmd)
        s.wait()

    # print_file
    def print_source(self,name):
        src = open(self.source_files+"/"+name+".c","r")
        for line in src:
            print(line.replace("\n",""))

    # compile source to binary
    def compile(self):
        print("%s Compiling..." % PROMPT)
        # Compile using GCC
        cmd=["gcc",self.source_path,"-Wno-format","-o",self.bin_files+"/"+self.name]
        s = subprocess.Popen(cmd)
        s.wait()

    # execute decompiled code
    def exec_bin(self,name,tty):
        # only print on tty
        if tty:
            print("%s Executing..." % PROMPT)
        cmd=[self.bin_files+"/"+self.name]
        # execute
        s = subprocess.Popen(cmd)
        # retrieves exit code
        exit_code = s.wait()
	    # Notice only positive exit codes are considered
	    # 2's complement of exit code
        exit_comp = dec.parser.twos_comp(exit_code,8)
	    # check if they differ
	    # if so, also print the negative interpretation
        if exit_comp != exit_code:
            # only print on tty
            if tty:
                print("%s Return Code: %d (%d)" % (PROMPT,exit_code,exit_comp))
        else:
            # only print on tty
            if tty:
                # if not, display only the positive interpretation
                print("%s Return Code: %d" % (PROMPT,exit_code))
        return exit_code

# Instruction Superclass
# Intrusction objects store instruction data for all asm, even the unsupported ones
class Instruction(object):
    def __init__(self,addr=None,module=None,instr=None,arg1=None,arg2=None):
	    # basic data storage
        self.set_addr(addr)
        self.set_external_module(False)
        self.set_module(module)
        self.set_instruction(instr)
        self.arg1=arg1
        self.arg2=arg2
        # all instruction are handled, at this time
        self.set_handled(True)

    # print the parsed instructions
    def print(self):
        # case having at least one argument
        if self.arg1 is not None:
            # case having a second one
            if  self.arg2 is not None:
                print("%s %x %s %s %s %s" % (PROMPT,self.addr,self.module,self.instr,self.arg1.get_operand(),self.arg2.get_operand()))
            else:
                print("%s %x %s %s %s" % (PROMPT,self.addr,self.module,self.instr,self.arg1.get_operand()))
        # case no args
        else:
            print("%s %x %s %s" % (PROMPT,self.addr,self.module,self.instr))

    # store instruction address    
    def set_addr(self,addr):
        if addr is None:
            self.addr=None
            return
        # interpret as hex
        try:
            self.addr=int(addr,16)    
        except:
            self.addr=addr

    # return PC/IP
    def get_addr(self):
        return self.addr

    # set probably external
    def set_external_module(self,external):
        if external is not None:
            self.external = external
        else:
            self.external = False

    # get probably external
    def get_external_module(self):
        return self.external

    # set module name
    def set_module(self,module):
        # check error
        if module is None:
            self.module="None"
            return
        # remove chars after @
        if "@" in module:
            # probably external
            self.set_external_module(True)
            self.module=module.split("@")[0]
            # remove iso string
            if "iso" in module:
                self.module=self.module.split("__isoc99_")[1]
            return
        # no need to strip
        self.module=module

    # return module name
    def get_module(self):
        return self.module

    # set instruction itself
    def set_instruction(self,instr):
        self.instr=instr

    # return instruction
    def get_instruction(self):
        return self.instr

    # mark instruction as handled
    def set_handled(self,handled):
        self.handled=handled

    # check instruction was handled
    def get_handled(self):
        return self.handled

    # get operand
    def get_operand(self,n=1):
        # maximum two arguments
        # if specified two, returns it
        if n==2:
            return self.arg2
        # any other case, return the first
        return self.arg1

    # generic code generation
    def emit_code(self):
        # do nothing
        # unsupported instr will not generate code
        return

# Operand Class
class Operand():
    def __init__(self,operand):
        # operand string
        self.set_operand(operand)
        # is memory segment operand
        self.set_segment(self.check_is_segment(self.operand))
        self.transform_operand()
        # is ordinary memory operand
        self.set_memory(self.check_is_memory(self.operand))
        # is constant operand
        self.set_constant(self.check_is_constant(self.operand))
        # last option, is register
        self.set_register(self.check_is_register())

    # transform operand - for segment notation handling
    def transform_operand(self):
        if self.get_segment():
            op = self.get_operand()
            # %fs:0x28 %rax -> -0x8(%rbp)
            reg = op.split(":")[0]
            offset = op.split(":")[1].split(" ")[0]
            new_operand = "%s(%s)" % (offset,reg)
            self.set_operand(new_operand)

    # check if is memory segment
    def check_is_segment(self,operand):
        # check for strings which looks like 'eax'/'rax'
        return ":" in operand and "%" in operand

    # check if is memory
    def check_is_memory(self,operand):
        # check for strings which looks like 'eax'/'rax'
        return "(%r" in operand or "(%e" in operand or "(%f" in operand

    # check if is constant
    def check_is_constant(self,operand):
        # check if it has the constant symbol
        return "$" in operand

    # check if it is register
    def check_is_register(self):
        # check not none
        if self.is_memory is None or self.is_constant is None:
            return False
        # check itself
        return not self.is_memory and not self.is_constant

    # get constant value if so
    def get_value(self):
        # constant value from string to int
        if self.is_constant:
            # remove constant symbol
            value = int(self.operand.replace("$",""),16)
            # check if represented in 2's complement
            return dec.parser.twos_comp(value)
        # error case
        return -1

    # attribute operand itself
    def set_operand(self,operand):
        self.operand = operand

    # return operand as string
    def get_operand(self):
        return self.operand

    # segment memory flag
    def set_segment(self,seg):
        self.is_segment = seg
   
    # retrieve segment memory flag
    def get_segment(self):
        return self.is_segment

    # attribute memory flag
    def set_memory(self,mem):
        self.is_memory = mem
   
    # retrieve memory flag
    def get_memory(self):
        return self.is_memory

    # attribute constant flag
    def set_constant(self,const):
        self.is_constant = const
   
    # retrieve constant flag
    def get_constant(self):
        return self.is_constant

    # attribute register flag
    def set_register(self,reg):
        self.is_register = reg
   
    # retrieve register flag
    def get_register(self):
        return self.is_register

    # just a wrapper for compatibility
    def get_name(self):
        return self.get_value()

    # check if this operand is a given register
    def check_is_reg_operand(self,reg):
        # if it is register and is substring
        if self.get_register() and reg is not None and reg in self.get_operand():
            return True
        # other cases, False
        return False

# Instruction Factory
class IFactory():

    # Dictionary of existing class to handle each instruction.
    # Instructions with diferent opcodes but same execution are
    # treated as a single case
    def __init__(self):
        self.classes=dict()

	# arithmetic operations
        self.classes['add']="IAdd"	# Add
        self.classes['addl']="IAdd"	# Add
        self.classes['and']="IAnd"	# AND
        self.classes['cmp']="ICmp"	# CMP
        self.classes['cmpl']="ICmp"	# CMP
        self.classes['div']="IDiv"	# DIV
        self.classes['divl']="IDiv"	# DIV
        self.classes['idiv']="IDiv"	# DIV
        self.classes['idivl']="IDiv"	# DIV
        self.classes['imul']="IMul"	# MUL
        self.classes['mul']="IMul"	# MUL
        self.classes['sub']="ISub"	# SUB
        self.classes['subl']="ISub"	# SUB

	# data movements
        # Not sure if lea behaves as Mov or if we have to query the pointed memory value
        self.classes['lea']="IMov"	    # lea
        self.classes['mov']="IMov"	    # Mov
        self.classes['movl']="IMov"	    # Mov
        self.classes['movw']="IMov"	    # Mov
        self.classes['movzbl']="IMov"	# Mov
        self.classes['pop']="IPop"	    # Stack Pop

	# bitwise operations
        self.classes['not']="INot"	# NOT
        self.classes['or']="IOr"	# OR
        self.classes['sar']="IShr"	# Shift Right
        self.classes['shr']="IShr"	# Shift Right
        self.classes['sal']="IShl"	# Shift Left
        self.classes['shl']="IShl"	# Shift Left
        self.classes['shll']="IShl"	# Shift Left
        self.classes['test']="ICmp"	# CMP
        self.classes['xor']="IXor"	# XOR

	# control flow operation
        self.classes['call']="ICall"	# Function call
        self.classes['callq']="ICall"	# Function call
        self.classes['ret']="IRet"	    # Return
        self.classes['iret']="IRet"	    # Return
        self.classes['retq']="IRet"	    # Return

	# sets, used to generate IFs
        self.classes['sete']="ISete"	# set equal
        self.classes['setge']="ISetge"	# set greater or equal
        self.classes['setg']="ISetg"	# set greater
        self.classes['setle']="ISetle"	# set lesser or equal
        self.classes['setl']="ISetl"	# set lesser
        self.classes['setne']="ISetne"	# set not equal

	# handle jumps as sets, as they should produce an if while stepping only one for iteration
        self.classes['je']="ISete"	    # jump equal = sete
        self.classes['jne']="ISetne"	# jump not equal = setne
        self.classes['jg']="ISetg"	    # jump greater = setg
        self.classes['jge']="ISetge"	# jump greater equal = setge
        self.classes['ja']="ISetg"	    # jump above = setg
        self.classes['jae']="ISetge"	# jump above equal = setge
        self.classes['jl']="ISetl"	    # jump lesser = setl
        self.classes['jle']="ISetle"	# jump lesser equal = setle
        self.classes['jb']="ISetl"	    # jump below = setl
        self.classes['jbe']="ISetle"	# jump below equal = setle
    	# still not handled cases
	    # jo jump if overflow
    	# jno jump not overflow
	    # jnz jump not zero
	    # js jump signed
	    # jns jump not signed

    # get a class for given instruction
    def get(self,Iaddr,Imodule,Instr,arg1,arg2):
        # if we can get an specific class
        try:
            # class name from instruction
            name = self.classes[Instr]
            # instantiate specific class
            newclass = globals()[name](Iaddr,Imodule,Instr,arg1,arg2)
            return newclass
        # if we cannot, return a generic instruction
        except:
            # instantiate the generic instruction object
            instr = Instruction(Iaddr,Imodule,Instr,arg1,arg2)
            # mark as not properly handled
            instr.set_handled(False)
            # return the object
            return instr

# Instruction Parser
class IParser():

    # Parser has a instruction factory
    def __init__(self):
        self.f = IFactory()

    # parse method
    def parse(self,raw_line):
        # inputted line
        line = raw_line
        # remove additional information to handle standard size
        # remove breakpoint info
        if "Breakpoint" in raw_line:
            line = raw_line[raw_line.find(",")+1:]
        # convert stripped positions into main
        if "??" in line:
            line = line.replace("??","main")
            line = line.replace(":\t"," <main+0>:\t")
        
        # remove trailing chars
        stripped_line = line.strip()
        # remove tabs
        line_without_tabs = stripped_line.replace("\t"," ")
        # condense whitespaces
        condensed_line = ' '.join(line_without_tabs.split())
        # split on whitespaces
        splitted_line = condensed_line.split(" ")

        # validate
        if len(splitted_line)>15:
            return None

        # parse args
        # check if they are comma splitted
        try:
            args = splitted_line[11].split(',')
            arg1=Operand(args[0])
            # check for a second comma
            try:
                arg2=Operand(args[1])
            except:
                arg2=None
        except:
            # otherwise, nothing
            arg1=None
            arg2=None

        Iaddr = splitted_line[8].split(":")[0]
        Imodule = splitted_line[2]
        Instr = splitted_line[10]

        # build instruction - ask factory for best class type
        return self.f.get(Iaddr,Imodule,Instr,arg1,arg2)

    # Support function
    # 2's complement calculatior
    # default: bits = x32
    def twos_comp(self, value, bits=32):
        # check if have the last bit set (two complement is used)
        if (value & (1 << (bits - 1))) != 0:
            # inversion
            value = value - (1 << bits)
        # return the same value if 2's not used
        # return the modified value if used
        return value

# Instruction Classes

# External Function Class
class IFunc(Instruction):
    def __init__ (self,func):
        # Upper class construction
        super(IFunc,self).__init__(None,None,None,None,None)

        # argument list definition
        self.arg_to_reg=dict()
        self.arg_to_reg[0]="%rdi"
        self.arg_to_reg[1]="%esi"
        # to be completed

        # store function
        self.set_function(func)

        # handle function return
        self.handle_return()

        # handle function arguments
        self.set_args(self.handle_args())

    # handle function return
    def handle_return(self):
        # check if function has a return
        self.ret = self.func.get_return()
        # if it has, it will be placed on eax
        if self.ret is not None:
            # check existing var on eax
            var = dec.current_piece.vars.get_var(reg="%eax")
            # if already existing
            if var is not None:
                # remove
                var.set_reg(None)
            # in all cases, create a new one
            self.var = dec.current_piece.vars.new_var(reg="%eax")
            # force it as used
            self.var.set_used(True)
        # case no return, assume it is void
        else:
            self.ret = "void"            

    # handle function args
    def handle_args(self):
        arg=[]
        for arg_number, arg_type in enumerate(self.func.get_args()):
            reg_val = RevReg().invoke(self.arg_to_reg[arg_number],from_tty=False)
            # if it is a format string
            if "char" in arg_type:
                string = RevString().invoke(str("0x%x" % reg_val),from_tty=False)
                arg.append(string)
            # int 
            elif "int" in arg_type:
                reg_val = RevReg().invoke(self.arg_to_reg[arg_number],from_tty=False)
                arg.append(str("0x%x" % reg_val))
            else:
                # get variable name
                try:
                    var = dec.current_piece.vars.get_var(reg=self.arg_to_reg[arg_number])
                    if var is not None:
                        arg.append(var.get_name())
                # error cases
                except:
                    pass

        return ",".join(arg)

    # set function
    def set_function(self,func):
        self.func=func

    # set args
    def set_args(self,args):
        self.args = args

    # get args
    def get_args(self):
        return self.args

    # get lib
    def get_lib(self):
        return self.func.get_lib()

    # get cast
    def get_cast(self):
        if "void*" in self.ret:
            return "(int*)"
        return ""

    # print function info
    def print(self):
        #print("External Call %s" % self.var.get_name())
        return

    # emit code
    def emit_code(self):
        return "%s = %s %s(%s);" % (self.var.get_name(),self.get_cast(),self.func.get_name(),self.get_args())
        return

# MOV Class
class IMov(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IMov,self).__init__(addr,module,instr,arg1,arg2)
        # Flag to mark variable reattribution
        self.reattrib = False
        # Flag no variable was duplicated
        self.duplicated = False

        # ignore cases regarding the stack
        if arg1.check_is_reg_operand("%rsp") or arg2.check_is_reg_operand("%rsp"):
            return

	    # case register to register
        if arg1.is_register and arg2.is_register:
            # get variable on register 1
            var1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())

            # check if register2 has something
            var2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())
            if var2 is not None:
                var2.set_reg(None)

            # say it is on register2
            var1.set_reg(arg2.get_operand())

            # create a copy of variable
            # for the case of the same variable on two registers
            val = var1.get_value(True)
            if val is not None:
                x = dec.current_piece.vars.new_var(reg=arg1.get_operand(),value=val)

        # case constant to mem (var initialization
        if arg1.is_constant and arg2.is_memory:
            # check var exists
            var = dec.current_piece.vars.get_var(mem=arg2.get_operand())
            # if not exists, create
            if var is None:
                x = dec.current_piece.vars.new_var(value=arg1.get_value(),mem=arg2.get_operand())
            else:
                # this is a reattribution
                self.reattrib=True
                # old
                self.old = var
                # value already set, create new var
                new_var = dec.current_piece.vars.new_var(value=arg1.get_value(),mem=arg2.get_operand())
                # remove old one
                var.set_mem(None)
                # new
                self.new = new_var

        # case mem to reg
        if arg1.is_memory and arg2.is_register:
            # try to get existing variable on such register
            var =  dec.current_piece.vars.get_var(reg=arg2.get_operand())
            # if something exists in the target register, remove
            if var is not None:
                var.set_reg(None)

            # try to retrieve var from memory now
            var = dec.current_piece.vars.get_var(mem=arg1.get_operand())

            # if failed, unitialized
            if var is None:
                # create var
                var = dec.current_piece.vars.new_var(mem=arg1.get_operand(),reg=arg2.get_operand())
		        # check if it is global
                if var.get_global():
                    # global read from .data
                    # HERE WE HAVE A PROBLEMATIC CASE TO BE HANDLED IN THE FUTURE (WARNING)
                    value = RevMemVal().invoke(arg="0x%x" % var.get_mem(),from_tty=False)
                    var.set_value(value)
                    var.set_read_from_data(True)
                # set as uninitialized
                var.set_init(False)
            else:
                # check if var already has an attributed register
                if var.get_reg() is not None:
                    # old, make a copy
                    self.old = dec.current_piece.vars.new_var(reg=var.get_reg(),value=var.get_value(True))
                    # mark duplicated
                    self.duplicated = True
                    # copy
                    self.new = var
                # new, just set register
                var.set_reg(arg2.get_operand())

        # reg to memory
        if arg1.is_register and arg2.is_memory:
            # retrieve from register
            var1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())

            # check if there is a var in register
            if var1 is None:
                var1 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                var1.set_init(False)
                # we should save to identify argc/argv
                self.argc = var1

            # retrieve from memory
            var2 = dec.current_piece.vars.get_var(mem=arg2.get_operand())

            # var reg does not have mem
            if var1.get_mem() is None:
                # var2 does not exist
                if var2 is None:
                    # set var 2 mem address for variable 1
                    var1.set_mem(mem=arg2.get_operand())
                else:
                    # new variable store on the same location than other one
                    var1.set_mem(var2.get_mem())
                    # clear old one, so they do not overlap
                    var2.set_mem(None)
                    var2.set_reg(None)
            else:
                # in the future, it may be useful to compare the addresses
                #src_addr = var1.get_mem()
                #dst_addr = RevMem().invoke(arg=arg2.get_operand(),from_tty=False)

                # not handled case
                print("Var %s already has Memory Position" % var1.name)

                # forcing duplication
                # workaround by now, we need to find a better solution
                if var2 is not None:
                    var2.set_mem(None)
                var2 = dec.current_piece.vars.new_var(mem=arg2.get_operand(),value=var1.get_value(True))

                self.duplicated=True
                var1.set_reg(None)

        # constant to reg
        if arg1.is_constant and arg2.is_register:
            # clear variables existing on such register
            dec.current_piece.vars.remove_registers(reg=arg2.get_operand())
            # create a new var on the register
            dec.current_piece.vars.new_var(reg=arg2.get_operand(),value=arg1.get_value())
    
    # emit code for MOV
    def emit_code(self):
        # emit code either on reattribution cases
        if self.reattrib:
            return "// Reatributing %s = %s = %x" % (self.old.get_name(),self.new.get_name(),self.new.get_value())
        # or on duplication
        if self.duplicated:
            return "// Duplicating %s = %s = %x" % (self.old.get_name(),self.new.get_name(),self.old.get_value())

# Operation Class
# general argument handling for arithmetic, shift and so on
class Operation(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(Operation,self).__init__(addr,module,instr,arg1,arg2)
        # flag to mark multiplication overflow
        self.overflow=False

        # ignore cases regarding the stack
        if arg1.check_is_reg_operand("%rsp"):
            return

        if arg2.check_is_reg_operand("%rsp"):
            return

        # arg1 is register and arg2 is None
        # Multiplies arg1 by eax and saves
        # result in eax
        if arg1.is_register and arg2 is None:
            # try to get associated variable
            self.op1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())
            # if not existing
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)

            # var in register
            self.op2 = dec.current_piece.vars.get_var(reg='%eax')
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg='%eax')
                self.op2.set_used(True)
                self.op2.set_init(False)

            # IDEALLY IT IS EDX:EAX...
            # create result on eax
            self.op3 = dec.current_piece.vars.new_var(reg='%eax')
            # remove old from eax to not conflict
            self.op2.set_reg(None)
            # forcely mark as used
            self.op3.set_used(True)

            # check for overflow
            edx_val = self.op1.get_value(True)*self.op2.get_value(True)>>32
            if edx_val > 0:
                # overflow warning
                print("%s Multiplication Overflow %x" % (PROMPT,edx_val))
                # set overflow flag
                self.overflow = True
                # create a new var with the overflow result
                self.over = dec.current_piece.vars.new_var(reg=arg1.get_operand(),value=edx_val)
                # edx must be free
                self.op1.set_reg(None)

        # mem to reg
        elif arg1.is_memory and arg2.is_register:
            # try to get var in memory
            self.op1 = dec.current_piece.vars.get_var(mem=arg1.get_operand())
            # if not exist
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(mem=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)
            else:
                self.op1.set_reg(None)
                self.op1.set_used(True)

            # get var on register
            # we ensure it exists, since a previous operation on it must be occurred
            self.op2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())
            #if not exist
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)
            else:
                self.op2.set_used(True)

            # create a new var in reg
            self.op3 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
            self.op3.set_used(True)
            self.op2.set_reg(None)

        # reg to mem
        elif arg1.is_register and arg2.is_memory:

            # var in register
            self.op1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())
            #if not exist
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)

            # get variable from memory
            self.op2 = dec.current_piece.vars.get_var(mem=arg2.get_operand())
            # if not exist
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(mem=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)

            # store in memory var
            # change to use a new
            self.op3 = self.op2
            self.op3.set_used(True)

        # constant to reg
        elif arg1.is_constant and arg2.is_register:
            # constant
            # now operand and variable have the same methods, just pass the object
            self. op1 = arg1
            # register
            self.op2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())
            # result in a new var
            dec.current_piece.vars.remove_registers(reg=arg2.get_operand())
            self.op3 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
            self.op3.set_used(True)

        # constant to mem
        elif arg1.is_constant and arg2.is_memory:
            # constant
            self.op1 = arg1
            # try to get memory
            self.op2 = dec.current_piece.vars.get_var(mem=arg2.get_operand())
            # check if already exists, if not create
            # you forgot to check on other cases, please check
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(mem=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)
            # result in another var
            # in the same address than the previous
            self.op3 = dec.current_piece.vars.new_var(mem=arg2.get_operand())
            # mark the new variable as used
            self.op3.set_used(True)
            # remove the old one from such address to avoid conflicts
            self.op2.set_mem(None)

        # reg to reg
        elif arg1.is_register and arg2.is_register:
            # reg1 var
            self.op1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)
            # reg2 var
            self.op2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)
            # resulting in a new (SSA)
    		# must remove old from register
            dec.current_piece.vars.remove_registers(reg=arg2.get_operand())
            self.op3 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
            self.op3.set_used(True)
        else:
            print("Instruction not handled")

# SUB Class
class ISub(Operation):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISub,self).__init__(addr,module,instr,arg1,arg2)

    # just emit code for sub operation
    def emit_code(self):
        return "%s = %s - %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())

# ADD Class
class IAdd(Operation):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IAdd,self).__init__(addr,module,instr,arg1,arg2)

    # just emit code for add operation
    def emit_code(self):
        return "%s = %s + %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())

# MUL Class
class IMul(Operation):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IMul,self).__init__(addr,module,instr,arg1,arg2)
        # implement almost the same way as sub and add

    # just emit code for mul operation
    def emit_code(self):
        # empty code string
        code=""
        # emit overflow comment, if needed
        if self.overflow:
            code+="//instruction causes an overflow to (%s=%x)\n" % (self.over.get_name(),self.over.get_value())
        # emit code itself
        code+="%s = %s * %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())
        return code

# DIV Class
class IDiv(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IDiv,self).__init__(addr,module,instr,arg1,arg2)

        # arg1 is memory and arg2 is None
        # Divides the content in %eax by the content
        # in memory and stores in %eax
        if arg1.is_memory and arg2 is None:
            # try to get associated variable
            self.op1 = dec.current_piece.vars.get_var(mem=arg1.get_operand())
            # if not existing
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(mem=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)

            self.op2 = dec.current_piece.vars.get_var(reg='%eax')
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg='%eax')
                self.op2.set_used(True)
                self.op2.set_init(False)
            # create result on eax
            self.op3 = dec.current_piece.vars.new_var(reg='%eax')
            #Save remainder result from %edx to op4
            self.op4 = dec.current_piece.vars.new_var(reg='%edx')
            # remove old from eax to not conflict
            self.op2.set_reg(None)
            # forcely mark as used
            self.op3.set_used(True)
            self.op4.set_used(True)

        # arg1 is register and arg2 is None
        # Divides the content in %eax by the content
        # in register and stores in %eax
        elif arg1.is_register and arg2 is None:
            # try to get associated variable
            var1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())
            # if not existing
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)

            # var in register
            self.op2 = dec.current_piece.vars.get_var(reg='%eax')
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg='%eax')
                self.op2.set_used(True)
                self.op2.set_init(False)
            # create result on eax
            self.op3 = dec.current_piece.vars.new_var(reg='%eax')
            #Save remainder result from %edx to op4
            self.op4 = dec.current_piece.vars.new_var(reg='%edx')
            # remove old from eax to not conflict
            self.op2.set_reg(None)
            # forcely mark as used
            self.op3.set_used(True)
            self.op4.set_used(True)

    # just emit code for div operation
    def emit_code(self):
        #Print only the division operation
        #return "%s = %s / %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())
        #Print the division and remainder operation
        return "%s = %s / %s;%s = %s %% %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name(),self.op4.get_name(),self.op2.get_name(),self.op1.get_name())

# CMP Class
#Saves op1 and op2 from set operations to be used in High Level Compare
#TODO: Are there any missing args?
class ICmp(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ICmp,self).__init__(addr,module,instr,arg1,arg2)

        # mem to reg
        if arg1.is_memory and arg2.is_register:
            # try to get var in memory
            self.op1 = dec.current_piece.vars.get_var(mem=arg1.get_operand())
            # if not exist
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(mem=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)

            # get var on register
            # we ensure it exists, since a previous operation on it must be occurred
            self.op2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)

        # constant to mem
        elif arg1.is_constant and arg2.is_memory:
            # constant
            self.op1 = arg1
            # memory
            self.op2 = dec.current_piece.vars.get_var(mem=arg2.get_operand())
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(mem=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)
           
        elif arg1.is_register and arg2.is_register:
            self.op1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())
            if self.op1 is None:
                self.op1 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)

            # get var on register
            # we ensure it exists, since a previous operation on it must be occurred
            self.op2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)

        elif arg1.is_register and arg2.is_memory:
            # constant
            self.op1=arg1
            # var in memory
            # please, add the error handling here
            self.op2 = dec.current_piece.vars.get_var(mem=arg2.get_operand())

        elif arg1.is_constant and arg2.is_register:
            # constant
            self.op1=arg1
            # var in register
            # please, add the error handling here
            self.op2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())

        else:
            print("Missing arg treatment: ICmp\n")

# Super class for set, saves op3 to be used in High Level Compare
#Should other setxxx be treated? Do they exist only in low level?
class ISet(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISet,self).__init__(addr,module,instr,arg1,arg2)
        if arg1.is_register and arg2 is None:
            # create a new var in reg
            # clear previously set registers
            dec.current_piece.vars.remove_registers(reg=arg1.get_operand())
            # create itself
            var3 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
            self.op3 = var3
            self.op3.set_used(True)

#Set classes, saves operator for use in High Level Compare
class ISete(ISet):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISete,self).__init__(addr,module,instr,arg1,arg2)
        self.operator = "=="

class ISetg(ISet):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISetg,self).__init__(addr,module,instr,arg1,arg2)
        self.operator = ">"

class ISetge(ISet):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISetge,self).__init__(addr,module,instr,arg1,arg2)
        self.operator = ">="

class ISetl(ISet):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISetl,self).__init__(addr,module,instr,arg1,arg2)
        self.operator = "<"

class ISetle(ISet):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISetle,self).__init__(addr,module,instr,arg1,arg2)
        self.operator = "<="

class ISetne(ISet):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ISetne,self).__init__(addr,module,instr,arg1,arg2)
        self.operator = "!="

#Takes info of operands and operator from compare and set
#and emits code for all set operations
class HighLevelCompare():
    def __init__ (self,cmp,set):
        self.op1 = cmp.op1
        self.op2 = cmp.op2
        self.op3 = set.op3
        self.operator = set.operator

    def __heuristic_argc(self):
        return "argc" in self.op2.get_name()

    def emit_code(self):
        if self.__heuristic_argc():
            return "%s = %s %s %s; //Checking the number of arguments (argc)" % (self.op3.get_name(),self.op2.get_name(),self.operator,self.op1.get_name())
        else:
            return "%s = %s %s %s;" % (self.op3.get_name(),self.op2.get_name(),self.operator,self.op1.get_name())

# Parent class for Shift instructions
# Such as SHL,SHR, SAL, SAR
#TODO: Count could possibly be a register, no case found yet - not treated!
class IShift(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IShift,self).__init__(addr,module,instr,arg1,arg2)
        # Memory and None
        # Will shift memory data one bit only
        if arg1.is_memory and arg2 is None:
            #Set constant value as 1
            self.op1 = dec.current_piece.vars.new_var(value=1)
            #forcely mark as used
            self.op1.set_used(True)
            # variable
            self.op2 = dec.current_piece.vars.get_var(mem=arg1.get_operand())
            # create a new one
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(mem=arg1.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)

            # create itself
            self.op3 = dec.current_piece.vars.new_var(mem=arg1.get_operand())
            # remove from memory
            self.op2.set_mem(None)
            # forcely mark as used
            self.op3.set_used(True)

        # Register and None
        # Will shift register data one bit only
        elif arg1.is_register and arg2 is None:
            #Set constant value as 1
            self.op1 = dec.current_piece.vars.new_var(value=1)
            #forcely mark as used
            self.op1.set_used(True)
            # variable
            self.op2 = dec.current_piece.vars.get_var(reg=arg1.get_operand())
            # create a new one
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)

            # create itself
            self.op3 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
            # remove from register
            self.op2.set_reg(None)
            # forcely mark as used
            self.op3.set_used(True)

        # Constant and register
        # Will shift register data $constant bits - different than one
        elif arg1.is_constant and arg2.is_register:
            # constant
            self.op1 = arg1
            # variable
            self.op2 = dec.current_piece.vars.get_var(reg=arg2.get_operand())
            # create a new one
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)

            # create itself
            self.op3 = dec.current_piece.vars.new_var(reg=arg2.get_operand())
            # remove from register
            self.op2.set_reg(None)
            # forcely mark as used
            self.op3.set_used(True)

        # Constant and memory
        # Will shift memory data $constant bits - different than one
        elif arg1.is_constant and arg2.is_memory:
            # constant
            self.op1 = arg1
            # variable
            self.op2 = dec.current_piece.vars.get_var(mem=arg2.get_operand())
            # create a new one
            if self.op2 is None:
                self.op2 = dec.current_piece.vars.new_var(mem=arg2.get_operand())
                self.op2.set_used(True)
                self.op2.set_init(False)

            # create itself
            self.op3 = dec.current_piece.vars.new_var(mem=arg2.get_operand())
            # remove from memory
            self.op2.set_mem(None)
            # forcely mark as used
            self.op3.set_used(True)

# Left shift class - analogous to multiplication
class IShl(IShift):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IShl,self).__init__(addr,module,instr,arg1,arg2)

    def emit_code(self):
        return "%s = %s << %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())

# Right shift class - analogous to division
class IShr(IShift):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IShr,self).__init__(addr,module,instr,arg1,arg2)

    def emit_code(self):
        return "%s = %s >> %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())

#Desnecessaria, logical ops poderiam so pegar de operation
class ILogic(Operation):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ILogic,self).__init__(addr,module,instr,arg1,arg2)

class INot(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(INot,self).__init__(addr,module,instr,arg1,arg2)
        if arg1.is_register and arg2 is None:
            # try to get associated variable
            self.op1 = dec.current_piece.vars.get_var(reg=arg1.get_operand())
            # if not existing
            if self.op1 is None:
                # create an uninit'ed one
                self.op1 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)
            # var in register
            self.op2 = dec.current_piece.vars.new_var(reg=arg1.get_operand())
            # remove old from eax to not conflict
            self.op1.set_reg(None)
            # forcely mark as used
            self.op2.set_used(True)

        elif arg1.is_memory and arg2 is None:
            # try to get associated variable
            self.op1 = dec.current_piece.vars.get_var(mem=arg1.get_operand())
            # if not existing
            if self.op1 is None:
                # create an uninit'ed one
                self.op1 = dec.current_piece.vars.new_var(mem=arg1.get_operand())
                self.op1.set_used(True)
                self.op1.set_init(False)
            # var in register
            self.op2 = dec.current_piece.vars.new_var(mem=arg1.get_operand())
            # forcely mark as used
            self.op2.set_used(True)

    def emit_code(self):
        return "%s = ~ %s;" % (self.op2.get_name(),self.op1.get_name())

class IAnd(ILogic):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IAnd,self).__init__(addr,module,instr,arg1,arg2)

    def emit_code(self):
        return "%s = %s & %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())

class IOr(ILogic):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IOr,self).__init__(addr,module,instr,arg1,arg2)

    def emit_code(self):
        return "%s = %s | %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())

class IXor(ILogic):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IXor,self).__init__(addr,module,instr,arg1,arg2)

    def emit_code(self):
        return "%s = %s ^ %s;" % (self.op3.get_name(),self.op2.get_name(),self.op1.get_name())

# POP Class
class IPop(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IPop,self).__init__(addr,module,instr,arg1,arg2)

# CALL Class
class ICall(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(ICall,self).__init__(addr,module,instr,arg1,arg2)

    def emit_code(self):
        return

# RET Class
class IRet(Instruction):
    def __init__ (self,addr,module,instr,arg1,arg2):
        super(IRet,self).__init__(addr,module,instr,arg1,arg2)
        # save var at this moment, since code generation will occur in the future
        self.var = dec.current_piece.vars.get_var(reg='%eax')

    def emit_code(self):
    # always return eax
    # print return comment if needed
        return "return %s; %s" % (self.var.get_name(),self.__negative_return_check())

    # generate comments
    def __negative_return_check(self):
        # retrieve return value
        try:
            # if value seems negative
            if self.var.get_value() < 0:
                # tell negative returns are not good
                return "// negative return is a problem"
            # if value seems ok, say nothing
            return ""
        # if not possible, we can't say anything
        except:
            return ""

# class variable
# variables will be represented by objects
class Variable():
    # constructor, consider all params
    # not all times available
    def __init__(self,name,reg,value,mem):
        # variable name
        self.set_name(name)
        # register it is
        self.set_reg(reg)
        # initial value
        self.set_value(value)
        # global
        self.set_global(False)
        # memory position
        self.set_mem(mem)
        # use-def chain-like
        self.set_used(False)
        # detect the use of uninit vars
        # initially, consider all as initialized
        # program execution should detect and change
        self.set_init(True)
        # informs whether the var was read from .data section
        self.set_read_from_data(False)

    # check possible overflow
    def check_overflow(self,bits=32):
        _val = self.get_value()
        # check greater than bits
        if _val is not None and (_val >> bits) != 0:
            return True
        return False

    # identify variable type
    def get_type(self):
        # default is to be an int
        _type="int"
        # increase var size in case of possible overflow
        if self.check_overflow(bits=32):
            _type="long int"
        return _type

    # guess variable is global or local
    def guess_global(self,mem):
        return "%rip" in mem

    # getters and setters
    # we should ensure they are used along the code, so it becomes more readable

    # rename variable
    # used to keep previous name
    def rename(self,new_name):
        # check None
        if new_name is None:
            return
        # check Empty
        if new_name == "":
            return
        # append new name to old name
        self.set_name(self.get_name()+"_"+new_name)

    # set variable name
    def set_name(self,name):
        self.name=name

    # get variable name
    def get_name(self):
        return self.name

    # set variable to a register
    def set_reg(self,reg):
        self.reg = reg

    # get register variable is currently in
    def get_reg(self):
        return self.reg

    # set value to the variable
    def set_value(self,value):
        self.value = value

    # get value variable stores
    def get_value(self,retrieve=False):
        # if having value, return it
        if self.value is not None:
            return self.value
        # try to retrieve values if required
        if retrieve:
           # if having register, return the content
           if self.get_reg() is not None:
                return RevReg().invoke(arg=self.get_reg(),from_tty=False)
           # if having memory address, return the content
           if self.get_mem() is not None:
                return RevMemVal().invoke(arg=str("0x%x" % self.get_mem()),from_tty=False) & 0xFFFFFFFF
        # other cases
        return None

    # set value to be stored in the var
    def set_mem(self,mem):
        # check if not None
        if mem is None:
            # store none
            self.mem=None
            return
        # check if it should convert address
        if "%" in str(mem):
            # convert base+offset into pointer
            self.mem=RevMem().invoke(arg=mem,from_tty=False)
        else:
            self.mem=mem
            return
        # check if it is global
        self.set_global(self.guess_global(mem))

    # get valued stored in the variable
    def get_mem(self):
        return self.mem

    # mark variable as used
    def set_used(self,is_used):
        self.used=is_used

    # check whether variable was used or not
    def get_used(self):
        return self.used

    # set var as initialized or not before first read
    def set_init(self,init):
        self.init=init

    # check whether var was initialized before first read
    def get_init(self):
        return self.init

    # set var as read or not from .data section
    def set_read_from_data(self,read):
        self.read_from_data=read

    # check whether var was read from .data section
    def get_read_from_data(self):
        return self.read_from_data

    # mark variable as global
    def set_global(self,is_global):
        self.is_global=is_global

    # check whether variable is global or not
    def get_global(self):
        return self.is_global

# variable management
class VariableManager():
    def __init__(self):
        # set of variable objects
        self.vars=set()

    def debug_print(self):
        for var in self.vars:
            # avoiding None Problems

            # for name
            name=var.get_name()
            if name is None:
                name="NONE"

            # for value
            if var.get_value() is None:
                value="NONE"
            else:
                value="%x" % var.get_value()

            # for reg
            reg=var.get_reg()
            if reg is None:
                reg="NONE"

            # for mem
            mem = var.get_mem()
            if mem is None:
                mem="NONE"
            else:
                mem = "%x" % mem

            # print
            print("NAME: [%s]\tVAL: [%s]\tREG: [%s]\tMEM: [%s]\tGLOBAL: [%d]\tUSED: [%d]\tINIT: [%d]\tDATA: [%d]" % (name,value,reg,mem,var.get_global(),var.get_used(),var.get_init(),var.get_read_from_data()))

    # check a given value is probably a pointer
    def check_is_pointer(self,addr=None):
        # if no args, no pointer
        if addr is not None:
            # first heuristic: check if its some var address
            for var in self.vars:
                try:
                    # if it is
                    if addr == var.get_mem():
                        # return the var
                        return var
                except:
                    pass
        # nothing found
        return None
        

    # remove all variables from a given register
    def remove_registers(self,reg):
        # for all vars
         for var in self.vars:
            # try to get register it is in
            _reg = var.get_reg()
            # if is the same
            if _reg is not None and _reg == reg:
                # remove from register
                # now it is only in memory
                var.set_reg(None)

    # the same for memory position
    # used for SSA
    def remove_mem(self,mem):
        mem_addr=RevMem().invoke(arg=mem,from_tty=False)
        for var in self.vars:
            _mem = var.get_mem()
            if _mem is not None and _mem == mem_addr:
                var.set_mem(None)

    # create a new var
    def new_var(self,reg=None,value=None,mem=None):
        # by now, sequential names
        name = "var"+str(len(self.vars))
        # create a var having the available data
        # some are none (vars only in memory or only in register)
        # maybe we should check and remove other registers here (remove eax when setting rax)
        var = Variable(name,reg,value,mem)
        # add to the list
        self.vars.add(var)
        # optionally some statements will use the returned object
        return var

    # retrieve var in a given register
    # private method
    def __get_var_by_reg(self,reg):
        for var in self.vars:
            _reg = var.get_reg()
            if _reg is not None and _reg == reg:
                var.set_used(True)
                return var
        # nothing found
        return None

    # retrieve var in a given mem position
    # private method
    def __get_var_by_mem(self,mem):
        mem_addr=RevMem().invoke(arg=mem,from_tty=False)
        for var in self.vars:
            _mem = var.get_mem()
            if _mem is not None and _mem == mem_addr:
                var.set_used(True)
                return var
        return None

    # retrieve var in memory or in register
    def get_var(self,reg=None,mem=None):
        # if register
        if reg is not None:
            # call private method
            return self.__get_var_by_reg(reg)
        # if memory
        if mem is not None:
            # call private method
            return self.__get_var_by_mem(mem)
        # error case
        return None

# me class
class CodeFrame():
    # instantiate
    def __init__(self,name):
        # empty context
        self.name=name
        # add to instr
        self.addr_to_instr=dict()
    	# manage variables
        self.vars = VariableManager()
        # list of instructions
        self.instruction_list=[]
        # statistics
        self.stats = None

    # Code generation

    # argc/argv identification heuristics
    # check argc read on main start
    def arg_heuristic(self):
        # number of instruction which will be searched
        self.window = 10
        # get instruction list
        instrs, stats = self.get_instruction_list()
        # for each instruction in the window
        for instr in instrs[:self.window]:
            # try
            try:
                # check only MOV instructions
                if isinstance(instr,IMov):
                    # valid only for main module
                    if "main" in instr.get_module():
                        # get operands
                        op1 = instr.get_operand(n=1)
                        op2 = instr.get_operand(n=2)
                        # edi in first register
                        if op1.get_register() and "%edi" in op1.get_operand():
                            # moving to memory
                            if op2.get_memory():
                                # rename variable
                                try:    
                                    instr.argc.rename("argc")
                                except:
                                    pass
                                # return found
                                return True
            # ignore error cases
            except:
                pass
        # nothing identified
        return False

    # emit libs
    def emit_libs(self):
        libs=set()
        instrs, stats = self.get_instruction_list()
        # for each instruction
        for instr in instrs:
            try:
                libs.add(instr.get_lib())
            except:
                pass
        includes=""
        for lib in libs:
            includes+="#include<%s>\n" % lib
        return includes

    # emit segment
    def emit_segment(self):
        # traverse the var list
        for var in dec.current_piece.vars.vars:
            # check the used ones for overflow
            if var.get_used() and var.check_overflow(bits=60):
                # if some, emit the constant
                return "#define PROBABLY_SEGMENT 0"
        # if none, nothing
        return ""

    # emit variables
    def emit_vars(self,emit_globals=False):
        # list of vars to be emited
        var_list=[]
        # for each var object
        # sort in reverse order, so we emit the var before its pointer
        for var in sorted(dec.current_piece.vars.vars, key=lambda x: x.get_name(),reverse=True):
            # emit only the used ones
            # ignore temporary values
            if var.get_used() and var.get_global()==emit_globals:
                # if has a initial value
                # problems with this gather
                if var.get_value() is not None:
                        # if read from data
                        if var.get_read_from_data():
                            var_list.append("%s %s = 0x%x; //Read from .data" % (var.get_type(),var.get_name(),var.get_value()))
                        # if not read from data
                        else:
                            # Segment register case
                            if var.check_overflow(bits=60):
                                var_list.append("%s %s = PROBABLY_SEGMENT;" % (var.get_type(),var.get_name()))
                            else:
                                # check it is a pointer
                                try:
                                    _ptr = dec.current_piece.vars.check_is_pointer(var.get_value())
                                except:
                                    _ptr = None
                                # it is pointing to a var addr but it is not itself
                                if _ptr is not None and _ptr!=var:
                                    # emit a point of _ptr type and not a var type
                                    var_list.append("%s* %s = &%s;" % (_ptr.get_type(),var.get_name(),_ptr.get_name()))
                                # ordinary cases
                                else:
                                    var_list.append("%s %s = 0x%x;" % (var.get_type(),var.get_name(),var.get_value()))
                # if not have AND
                # was used uninit
                elif var.get_init() == False:
                    # argc heuristic
                    if "argc" in var.get_name():
                        var_list.append("%s %s = argc;" % (var.get_type(),var.get_name()))
                    else:
                        var_list.append("%s %s = PROBABLY_UNINITIALIZED;" % (var.get_type(),var.get_name()))
                # was used after init
                else:
                    var_list.append("%s %s;" % (var.get_type(),var.get_name()))
        return "\n".join(var_list)

    # emit_constant
    def emit_constant(self):
        # emit constant to allow gcc compilation
        return "#define PROBABLY_UNINITIALIZED 0"

    # C head - no library includes by now
    def emit_head(self):
        # try to identify argc/argv usage
        if self.arg_heuristic():
            # found, emit argc,argv
            return "int main(int argc, char *argv[]) //argc/argv use identified\n{"
        # nothing found, emit void
        else:
            return "int main(void) //no args were passed\n{"

    # close C file
    def emit_trail(self):
        return "}"

    # if stopped before returning, assume returned zero
    def emit_return(self):
        return "return 0;"

    # The code now has 2 steps
    # the first check var usage
    def check_uninit(self):
        # check all vars
        for var in dec.current_piece.vars.vars:
            # if some was used uninit
            if var.get_used() and var.get_init() == False:
                return True
        # all were initialized before use
        return False

    # check SSA form
    def check_ssa(self):
        # attribution count dict
        attribution=dict()
        # get instructions
        instrs, stats = self.get_instruction_list()
        # for each instruction
        for instr in instrs:
            # for each one having an assignment
            try:
                try:
                    attribution[instr.op3.get_name()]+=1
                except:
                    attribution[instr.op3.get_name()]=1
                if attribution[instr.op3.get_name()]!=1:
                    print("%s SSA form violation at %s" % (PROMPT,instr.op3.get_name()))
                    return
            # ignore the others
            except:
                pass
        print("%s SSA form OK." % PROMPT)

    # check not emmited instructions
    def check_not_handled(self):
        # statements in serial form
        ilist,stats = self.get_instruction_list()
        not_handled_list = []
        # for each instruction
        for instr in ilist:
            # not handled ones
            if instr.get_handled() == False:
                not_handled_list.append(instr)
        return not_handled_list

    # serialize execution trace
    def get_instruction_list(self):
        # statistics
        stats=dict()
        # serialized list
        ilist = []
	    # we want an object copy to modify, not a pointer to the original one
        addr_to_instr=self.addr_to_instr.copy()
        for addr in self.instruction_list:
            # copy list in that address
            addr_list=addr_to_instr[addr]
            # add list head to the instruction list (next loop iteration)
            ilist.append(addr_list[0])
            # update list to remove the used entry
            addr_to_instr[addr]=addr_list[1:]
            # count loop unrolling, for statistic purposes
            try:
                stats[addr]=stats[addr]+1
            except:
                stats[addr]=1
        # return the serialized list and statistics
        return ilist,stats

    # code emission
    def emit_code(self):

        # open file
        src = dec.fm.create_source(self.get_name())

        # emit library headers
        libs = self.emit_libs()
        if len(libs)!=0:
            src.write(libs)

        # need to emit return 0 ?
        need_return = 1

        # segment
        segment = self.emit_segment()
        if len(segment):
            src.write(segment+'\n')
        # constant
        if self.check_uninit():
            src.write(self.emit_constant()+"\n")
        # global variables
        global_vars=self.emit_vars(emit_globals=True)
        # check if should print
        if len(global_vars)!= 0:
            src.write("//Probably global vars\n"+global_vars+'\n')
        # C head
        src.write(self.emit_head()+"\n")
        # local variables
        local_vars=self.emit_vars(emit_globals=False)
        # check if should emit
        if len(local_vars)!=0:
            src.write("//Probably local vars\n"+local_vars+"\n")

        # retrieve serialized instruction list
        ilist, self.stats = self.get_instruction_list()

        # for each instruction
        for index, instr in enumerate(ilist):
            # if there is a main ret, no need to include another
            if isinstance(instr,IRet):
                if "main" in instr.module:
                    need_return = 0
                # ignore returns from function calls
                else:
                    continue
            # if cmp followed by a control flow, convert into IF
            if isinstance(instr,ICmp):
                ilist[index+1] = HighLevelCompare(instr,ilist[index+1])
                pass
            # other cases, just emit the statement
            try:
                statement = instr.emit_code()
                if statement is not None:
                    src.write(statement+"\n")
            # ignore instructions which dec failed to parse
            except:
                pass

        # check if need emit return
        if need_return:
            src.write(self.emit_return()+"\n")
        # close file
        src.write(self.emit_trail()+"\n")

        # close file
        dec.fm.close_source()

    # print stats
    def print_stats(self):
        if self.stats is None or len(self.stats)==0:
            print("%s No Stats" % PROMPT)
            return
        print("%s ---------- STATISTICS ----------" % PROMPT)
        print("%s The trace has %d instructions" % (PROMPT,len(self.instruction_list)))
        for addr in self.stats:
            if self.stats[addr]!=1:
                print("%s Unrolled %d instr at %x" % (PROMPT,self.stats[addr],addr))
        print("%s ---------- STATISTICS ----------" % PROMPT)

    # getter
    def get_name(self):
        return self.name

# Decompiler Class
class Decompiler():
    def __init__(self):
        # user message
        print("%s Starting Revenge..." % PROMPT)
        # running status
        self.working = True
        self.testing = False
        # zeroing list of decompiled pieces of code
        self.clear_decompiled_pieces()
        self.parser = IParser()
        # no piece being decompile this moment
        self.current_piece = None
        # file manager
        self.fm = FileManager()
        # introspection manager
        self.im = Introspection_Manager()

    # start tracing new piece of code
    def new_piece(self):
        self.current_piece=CodeFrame("piece"+str(len(self.decompiled_pieces)))

    # clear decompiled pieces
    def clear_decompiled_pieces(self):
        self.decompiled_pieces=set()

    # return decompiled pieces as string
    def get_decompiled_pieces(self):
        # return None case empty
        if len(self.decompiled_pieces)==0:
            return "None"
        # otherwise convert to string
        else:
            return ' '.join(self.decompiled_pieces)

    # add new decompiled piece
    def set_decompiled_piece(self):
        try:
            self.decompiled_pieces.add(self.current_piece.get_name())
        except:
            print("%s Failed to create frame..." % PROMPT)
        # clear current piece
        self.curren_piece=None

# BreakPoint Wrapper
class Breakpoint (gdb.Breakpoint):

    def handle_main_bp(self):
        # Say we are Starting
        print("%s Starting from main..." % PROMPT)
        # Print at Screen
        return True

    def handle_exit_bp(self):
        # Say we are going away
        print("%s Finishing..." % PROMPT)
        # Print at screen
        return True

    def handle_libc_entry(self):
        output = gdb.execute("x/13i $rip",to_string=True)
        output = output[:output.find(",%rdi")].split("$")
        dec.program_main = output[-1]
        Breakpoint("*%s" % dec.program_main)

    def handle_other_bp(self):
        # Any other case
        return True

    def check_location(self,interest_bp,current_bp):
        return interest_bp in current_bp

    # When stopping at a given point
    def stop(self):

        # If this is a libc entry point
        if (self.check_location("*%s" % dec.libc_entry,self.location)):
            return self.handle_libc_entry()

        # If this point is main (pre-defined break)
        if (self.check_location("main",self.location)):
            return self.handle_main_bp()

        # If this point is exit (pre-defined break)
        if (self.check_location("exit",self.location)):
            return self.handle_exit_bp()

        return self.handle_other_bp()

# Dec command - Step into instruction
class RevStep(gdb.Command):
    def __init__ (self):
        super(RevStep,self).__init__("revstep",gdb.COMMAND_RUNNING)
        self.parser = IParser()

    # Make GDB step one instruction
    def instruction_step(self):
        # Step one instruction when called
        try:
            output = gdb.execute("stepi", to_string=True)
            return output
        except:
            # errors in this part only come from GDB
            print("%s Debugging not started" % PROMPT)
            return None

    # Make GDB executes until the end of current stack frame
    def step_out(self):
        try:
            output = gdb.execute("finish", to_string=True)
            return output
        except:
            # errors in this part only come from GDB
            print("%s Debugging Error" % PROMPT)
            return None

    # GDB command invocation
    def invoke (self,arg,from_tty):
        # check if decompiler was initalized
        try:
        # check if decompiler is working
            if dec.working == False:
                print("%s Previous Error Detected" % PROMPT)
                return False
        except:
            print("%s Not Initialized..." % PROMPT)
            return False

        # Step 1 instruction
        output = self.instruction_step()

        # check if it stepped. Case not, do not proceed
        if output is None:
            return

        # try to create instruction
        try:
            instr = dec.parser.parse(output)
            # check if it is an external call
            if instr.get_external_module():
                # if it is
                # introspect current function
                f = dec.im.get_function(instr.get_module())
                # if introspection suceeded
                if f is not None:
                    # function instructions are not parsed, get addr from IP
                    iaddr = RevReg().invoke("%rip",from_tty=False)
                    # build external function object from introspected function
                    instr = IFunc(f)
                    # maybe the following construction could be wrapped in a method
                    # try to append instruction to the existing instruction list for that address
                    try:
                        dec.current_piece.addr_to_instr[iaddr].append(instr)
                    # if cannot append, it is the first list entry
                    except:
                        dec.current_piece.addr_to_instr[iaddr]=[instr]
                    # add addr to execution list (ordered)
                    dec.current_piece.instruction_list.append(iaddr)
                    # debug print
                    instr.print()
                else:
                    print("%s Introspection Error" % PROMPT)

                # then, step out
                # output is the first instruction back to the caller
                output = self.step_out()
                # check if no error
                if output is None:
                    return False
                # if ok
                try:
                    # parse instruction, continue
                    instr = dec.parser.parse(output)
                # error cases
                except:
                    print("%s Failed to Create Instruction -- Trace affected" % PROMPT)
                    return False

        except:
            print("%s Failed to Create Instruction -- Trace affected" % PROMPT)
            return False

        try:
            # PC/IP address
            iaddr = instr.get_addr()
            # add instr object to such addr

            # try to append instruction to the existing instruction list for that address
            try:
                dec.current_piece.addr_to_instr[iaddr].append(instr)
            # if cannot append, it is the first list entry
            except:
                dec.current_piece.addr_to_instr[iaddr]=[instr]

            # add addr to execution list (ordered)
            dec.current_piece.instruction_list.append(iaddr)
            # debug print
            instr.print()
            # say everything is fine
            return True
        except:
            # stop decompiler
            dec.working = False

            # if testing, just stop
            # if not testing, error
            if dec.testing == False:
                print("%s Failed to parse" % PROMPT)
            # say it's over!
            return False

# Run command - Step into instruction
class RevRun(gdb.Command):
    def __init__ (self):
        super(RevRun,self).__init__("revrun",gdb.COMMAND_RUNNING)
        self.parser = IParser()

    def instruction_step(self):
        # Step one instruction when called
        output = gdb.execute("start", to_string=True)
        return output

    def invoke (self,arg,from_tty):
        # check if codeframe was initalized
        try:
		# check if decompiler is working
            if dec.working == False:
                print("%s Previous Error Detected" % PROMPT)
                return
        except:
            print("%s Not Initialized..." % PROMPT)
            return

        # Step 1 instruction
        # success case
        try:
            output = self.instruction_step()
        # error case
        # most time it occurs when by running a .c instead a .bin
        except:
            print("%s A problem occurred with GDB step" % PROMPT)
            # on error, stop executing
            return

        # create instruction
        instr = dec.parser.parse(output)
        try:
            # PC/IP address
            iaddr = instr.get_addr()
            # add instr object to such addr

            # try to append instruction to the existing instruction list for that address
            try:
                dec.current_piece.addr_to_instr[iaddr].append(instr)
            # if cannot append, it is the first list entry
            except:
                dec.current_piece.addr_to_instr[iaddr]=[instr]

            # add addr to execution list (ordered)
            dec.current_piece.instruction_list.append(iaddr)
            instr.print()
        except:
            # stop decompiler
            dec.working=False
            print("%s Failed to parse" % PROMPT)

# Start Function/Command - Setup decompilation
class RevStart(gdb.Command):
    def __init__ (self):
        super(RevStart,self).__init__("revstart",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # Instantiate Decompiler
        global dec

        # check if existing
        try:
            # try to access. If not existing, will cause exception
            x = dec
            # if execution continues (it exists), display message and exit
            print("%s Decompiler Already Started!" % PROMPT)
            return
        # case not existing
        except:
                dec = Decompiler()
                # Default Breakpoints
                # check if we have a main        
                if RevSymbol().invoke(arg='main',from_tty=False):
                    print("%s Defining main breakpoint" % PROMPT)
                    b_m = Breakpoint("main")    # Supposing it has a main (typical programs have one) - Ignores which comes before
                # does not have a main
                else:
                    print("dont have a main to break")
                    # i can try to identify
                    RevEntry().invoke(arg=[],from_tty=False)
                # check for exit
                if RevSymbol().invoke(arg="exit",from_tty=False):
                    print("%s Defining exit breakpoint" % PROMPT)
                    b_e = Breakpoint("exit")    # ignores which comes after the exit
                # if it does not have an exit, i cant identify
                # define configs
                gdb.execute("display/i $pc")    # Display instructions disassembly
                # user message
                print ("%s Getting things to decompile" % PROMPT)
                dec.new_piece()

# Stop Function/Command - Decompile things when called
class RevStop(gdb.Command):
    def __init__ (self):
        super(RevStop,self).__init__("revstop",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # try to decompile
        try:
                dec.current_piece.emit_code()
                # add piece to the list
                dec.set_decompiled_piece()
                # User Message
                print ("%s Time to Decompile" % PROMPT)
                RevShow().invoke(arg=[],from_tty=False)
                dec.fm.compile()
        # error
        except:
            print("%s Start the decompiler first!" % PROMPT)

# List decompiled things command
class RevList(gdb.Command):
    def __init__ (self):
        super(RevList,self).__init__("revlist",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # User Message
        # try to retrieve list
        try:
            print("%s %s" % (PROMPT,dec.get_decompiled_pieces()))
        # if empty:
        except:
            print("%s None" % PROMPT)

# clear decompiled things
class RevClear(gdb.Command):
    def __init__ (self):
        super(RevClear,self).__init__("revclear",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # User Message
        print("%s Clearing..." % PROMPT)
        # ask decompiler to clear
        try:
            dec.clear_decompiled_pieces()
        # error case, ignore, as compiler is not instantiated
        except:
            pass

# Show Register Value
class RevReg(gdb.Command):
    def __init__ (self):
        super(RevReg,self).__init__("revreg",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # do not accept empty args
        if len(arg)==0:
            print("%s You must provide a Register Argument" % PROMPT)
            return -1

        # try to parse
        try:
                # only register name
                reg = arg.replace("%","")
                # only specific register
                output = gdb.execute("info registers "+reg, to_string=True)
                try:
                    # only integer value
                    # the second argument is decimal
                    int_val = int(output.strip().split("\t")[-1],10)
                except:
                    # here the second argument is hex
                    int_val = int(output.strip().split("\t")[-1].split("<")[0],16)
                # only print when tty is the caller
                if from_tty:
                    print("%s Reg[%s]=%x" % (PROMPT,reg,int_val))
                return int_val
        # failed to parse
        except:
            if from_tty:
                print("%s Invalid Register Argument" % PROMPT)
            return -1

# Memory pointer from register
class RevMem(gdb.Command):
    def __init__ (self):
        super(RevMem,self).__init__("revmem",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # do not accept empty args
        if len(arg)==0:
            print("%s You must provide a Memory Argument" % PROMPT)
            return -1

        # try tp accept the argument
        try:
                # parse output
                addr = arg.split("(")
                # adjust in case no offset
                if addr[0]=='':
                    offset=0        
                else:
                    # offset
                    offset = int(addr[0],16)

                # base from reg
                base = RevReg().invoke(addr[1].replace(")",""),from_tty=False)
                # mem calculation
                mem_addr = base + offset
                # if indexed by rip, add instruction size
                if "%rip" in addr[1]:
                    mem_addr+=RevISize().invoke(arg="",from_tty=False)
                # only pritint when tty is the caller
                if from_tty:
                    print("%s Mem[%s]=%x" % (PROMPT,arg,mem_addr))
                return mem_addr
        # failure
        except:
            print("%s Invalid Memory Argument" % PROMPT)
            return -1

# get value from memory position
class RevMemVal(gdb.Command):
    def __init__ (self):
        super(RevMemVal,self).__init__("revmemval",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # do not accept empty args
        if len(arg)==0:
            print("%s You must provide a Memory Argument" % PROMPT)
            return -1

        # try tp accept the argument
        try:
                # get address
                addr = int(arg,16)
                # read value (parse output)
                mem_val = int(gdb.execute("x/a "+str(addr),to_string=True).split(":")[1],16)
                # print when required
                if from_tty:
                        print("%s %x" % (PROMPT,mem_val))
                # return memory content
                return mem_val
        # failure
        except:
            print("%s Invalid Memory Argument" % PROMPT)
            return -1

# show source code
class RevShow(gdb.Command):
    def __init__ (self):
        super(RevShow,self).__init__("revshow",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # try to exec
        try:
                # no args, default
                if len(arg)==0:
                    dec.fm.print_source(dec.current_piece.get_name())
                # otherwise, arguments
                else:
                    # consider arg
                    try:
                        dec.fm.print_source(arg)
                    # invalid arg
                    except:
                        print("%s Piece not found" % PROMPT)
        # decompiler error
        except:
            print("%s Start the decompiler first!" % PROMPT)

# execyte decompiled code
class RevExec(gdb.Command):
    def __init__ (self):
        super(RevExec,self).__init__("revexec",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
	# try to execute
        try:
            # no args, default
            if len(arg)==0:
                return dec.fm.exec_bin(dec.current_piece.get_name(),from_tty)
            # otherwise, arguments
            else:
                # consider arg
                try:
                    return dec.fm.exec_bin(arg,from_tty)
                # invalid arg
                except:
                    print("%s Piece not found" % PROMPT)
        # decompiler error
        except:
            print("%s Start the decompiler first" % PROMPT)

# usage()
class RevHelp(gdb.Command):
    def __init__ (self):
        super(RevHelp,self).__init__("revhelp",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        print("%s RevStart          - create a new frame" % PROMPT)
        print("%s RevStop           - close a new frame" % PROMPT)
        print("%s RevStep           - decompile a new instruction" % PROMPT)
        print("%s RevList           - list decompiled frames" % PROMPT)
        print("%s RevClear          - discard decompiled frames" % PROMPT)
        print("%s RevReg            - internal use" % PROMPT)
        print("%s RevRun            - start debugging" % PROMPT)
        print("%s RevHelp           - display this message" % PROMPT)
        print("%s RevShow           - print decompiled code" % PROMPT)
        print("%s RevExec           - execute decompiled code" % PROMPT)
        print("%s RevMem            - internal use" % PROMPT)
        print("%s RevMemVal         - internal use" % PROMPT)
        print("%s RevIgn            - ignored instructions" % PROMPT)
        print("%s RevTest (-v)      - run the test framework" % PROMPT)
        print("%s RevDebug          - debug prints" % PROMPT)
        print("%s RevStats          - statistics prints" % PROMPT)
        print("%s RevAssert         - execution output test" % PROMPT)
        print("%s RevISize          - get instruction size" % PROMPT)
        print("%s RevString         - get string from address" % PROMPT)
        print("%s RevInvertBranch   - invert branch direction" % PROMPT)
        print("%s RevSymbols        - Check binary symbols" % PROMPT)
        print("%s RevEntry          - Identify binary entry point" % PROMPT)

# Show ignored instruction
# the ones not handled by our solution
class RevIgn(gdb.Command):
    def __init__ (self):
        super(RevIgn,self).__init__("revign",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # try to get list
        try:
            not_handled_list = dec.current_piece.check_not_handled()
            # empty list
            if len(not_handled_list) == 0:
                print("%s Ignored Instructions: None" % PROMPT)
            # some instr
            else:
                print("%s Ignored Instructions: " % PROMPT)
                # print each mnemonic
                for instr in not_handled_list:
                    print("[%x] %s" % (instr.addr,instr.instr))
        # not possible
        # maybe decompiler not started
        except:
                print("%s Ignored Instructions: None" % PROMPT)

# Test framework
class RevTest(gdb.Command):
    def __init__ (self):
        super(RevTest,self).__init__("revtest",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # start the decompiler
        RevStart().invoke(arg=[],from_tty=False)
        # tell decompiler we're testing
        dec.testing = True
        # Start program execution
        RevRun().invoke(arg=[],from_tty=False)
        # check if verbose mode is set
        if "-v" in arg:
            # display debug information
            RevDebug().invoke(arg=[],from_tty=False)

        # Step control
        Step = True
        # step until the end
        while(Step):
            Step = RevStep().invoke(arg=[],from_tty=False)
            # check if verbose mode is set
            if "-v" in arg:
                # display debug information
                RevDebug().invoke(arg=[],from_tty=False)

        # emit code in the end
        RevStop().invoke(arg=[],from_tty=False)
        # test SSA form
        RevSSA().invoke(arg=[],from_tty=False)
        # display stats
        RevStats().invoke(arg=[],from_tty=False)
        # test execution
        RevAssert().invoke(arg=[],from_tty=False)

# Debug Print
class RevDebug(gdb.Command):
    def __init__ (self):
        super(RevDebug,self).__init__("revdebug",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # try to display variable information
    	try:
       	    dec.current_piece.vars.debug_print()
    	except:
		    print("%s Start the debugger first!" % PROMPT)

# Statistics Print
class RevStats(gdb.Command):
    def __init__ (self):
        super(RevStats,self).__init__("revstats",gdb.COMMAND_RUNNING)

    def invoke (self,arg,from_tty):
        # try to display variable information
    	try:
       	    dec.current_piece.print_stats()
    	except:
		    print("%s Start the debugger first!" % PROMPT)

# Check Execution Result
class RevAssert(gdb.Command):
    def __init__ (self):
        super(RevAssert,self).__init__("revassert",gdb.COMMAND_RUNNING)

    def invoke(self,arg,from_tty):
        # try to exec decompiled
        try:
                # decompiled output
                exit_decompiled = RevExec().invoke(arg=[],from_tty=False)
                # binary output
                output=subprocess.Popen(gdb.current_progspace().filename)
                exit_original = output.wait()
                # comparison
                if exit_original == exit_decompiled:
                    print("%s SUCCESS. Expected: %d Received: %d" % (PROMPT,exit_original,exit_decompiled))
                else:
                    print("%s ERROR. Expected: %d Received: %d" % (PROMPT,exit_original,exit_decompiled))
        # failed to exec decompiled
        except:
            print("%s Decompile before testing!" % PROMPT)

# Test SSA form
class RevSSA(gdb.Command):
    def __init__ (self):
        super(RevSSA,self).__init__("revssa",gdb.COMMAND_RUNNING)

    def invoke(self,arg,from_tty):
        # try to traverse decompiled instruction
        try:
            dec.current_piece.check_ssa()
        # failed to exec decompiled
        except:
            print("%s Decompile before testing!" % PROMPT)

# Get Instruction Size
class RevISize(gdb.Command):
    def __init__ (self):
        super(RevISize,self).__init__("revisize",gdb.COMMAND_RUNNING)

    def invoke(self,arg,from_tty):
        # try to get argument
        if len(arg)!=0:
            try:
                current_pc = int(arg[0])
            except:
                print("%s Cannot get argument" % PROMPT)
                return
        # case no args, get from rip
        else:
            try:
                current_pc = int(RevReg().invoke(arg="%rip",from_tty=False))
            except:
                print("%s Cannot get current instruction" % PROMPT)
                return
        # try to disasm
        try:
            disasm = gdb.execute("x/2i "+str(current_pc),to_string=True)
            # getting first offset
            val1=disasm.split("+")[1].split(">")[0]
            # getting second offset
            val2=disasm.split("+")[2].split(">")[0]
            # difference
            size = int(val2)-int(val1)
            # print
            if from_tty:
                print("%s %d" % (PROMPT,size))
            # return
            return size
        # failed
        except:
            print("%s Failed to disasm" % PROMPT)

# String from Address
class RevString(gdb.Command):
    def __init__ (self):
        super(RevString,self).__init__("revstring",gdb.COMMAND_RUNNING)

    def invoke(self,arg,from_tty):
        # check if an argument was supplied
        if len(arg)==0:
            print("%s No Address Supplied" % PROMPT)
            return 0
        # ask GDB to interpret memory content as string
        string = gdb.execute("x/s "+arg,to_string=True)
        # ignore address before the :
        string = string[string.find(":")+1:]
        # if from tty, print
        if from_tty:
            print("%s %s" % (PROMPT,string))
        # return
        return string

# Invert Branch Direction
class RevInvertBranch(gdb.Command):
    def __init__ (self):
        super(RevInvertBranch,self).__init__("revinvbranch",gdb.COMMAND_RUNNING)
        # Map Flags to their eflags counterparts
        self.flag_map = dict()
        self.flag_map['CF'] = 0x1
        self.flag_map['PF'] = 0x4
        self.flag_map['AF'] = 0x10
        self.flag_map['ZF'] = 0x40
        self.flag_map['SF'] = 0x80
        self.flag_map['TF'] = 0x100
        self.flag_map['IF'] = 0x200
        self.flag_map['DF'] = 0x400
        self.flag_map['OF'] = 0x800

    # read eflags register
    def __get_flags(self):
        try:
            return gdb.execute("i r eflags",to_string=True).split("[")[1].split("]")[0].strip()
        except:
            return None

    # add a flag to the eflags register
    def __add_flag(self,flag):
            output = gdb.execute("set $eflags|=0x%x" % self.flag_map[flag],to_string=True)

    # remove a flag from the eflags register
    def __remove_flag(self,flag):
            gdb.execute("set $eflags&=~0x%x" % self.flag_map[flag],to_string=True)

    # invert flag routine
    def __invert_flags(self):
        # get current instruction to identify which flags to invert
        current_instruction = gdb.execute("x/i $pc",to_string=True)
        # JE instruction
        if "je" in current_instruction:
            return
        # JNE instruction
        elif "jne" in current_instruction:
            return
        # JLE instruction
        elif "jle" in current_instruction:
            # change ZF flags
            flag = "ZF"
            # both cases, add and remove flags, since we want f^{-1}(f) = I
            # i.e. invertible function, thus bijective
            if flag in self.flags:
                self.__remove_flag(flag)
            elif flag not in self.flags:
                self.__add_flag(flag)
        # JG instruction
        elif "jg" in current_instruction:
            return
        # JGE instruction
        elif "jge" in current_instruction:
            return
        # JA instruction
        elif "ja" in current_instruction:
            return
        # JAE instruction
        elif "jae" in current_instruction:
            return
        # any other instruction
        else:
            print("%s Not a branch" % PROMPT)

    # command itself
    def invoke(self,arg,from_tty):
        # try to get info
        try:
            # get flags
            self.flags = self.__get_flags()
            # failed
            if self.flags is None:
                print("%s Cannot retrieve flags" % PROMPT)
                return False
            # if tty, print
            if from_tty:
                print("%s Flags before: %s" % (PROMPT,self.flags))
            # invert itself
            self.__invert_flags()
            # get flags after
            self.flags = self.__get_flags()
            # check errors
            if self.flags is None:
                print("%s Cannot retrieve flags" % PROMPT)
                return False
            # print, if tty
            if from_tty:
                print("%s Flags after: %s" % (PROMPT,self.flags))
            # return ok
            return True
        # failed
        except:
            print("%s Cannot retrieve flags" % PROMPT)

# Check binary symbols
class RevSymbol(gdb.Command):
    def __init__ (self):
        super(RevSymbol,self).__init__("revsymbol",gdb.COMMAND_RUNNING)

    def invoke(self,arg,from_tty):
        # check if an argument was supplied
        if arg is None or len(arg)==0:
            print("%s Provide a symbol" % PROMPT)
            return False
        # try to get symbol
        try:
            # if succeded, it was found
            output = gdb.execute("i sy %s" % arg,to_string=True)
            # print, if tty
            if from_tty:
                print("%s Symbol Found" % PROMPT)
            return True
        # not found
        except: 
           # print if tty
           if from_tty:
                print("%s Symbol Not Found" % PROMPT)
           return False
 
# Identify Binary Entry Point
class RevEntry(gdb.Command):
    def __init__ (self):
        super(RevEntry,self).__init__("reventry",gdb.COMMAND_RUNNING)

    def invoke(self,arg,from_tty):
        print("Entry Point Identification (TBD)")
        output = gdb.execute("i files",to_string=True)
        dec.libc_entry = output.split("point:")[1].split("\n")[0].strip()
        Breakpoint("*%s" % dec.libc_entry)
        output = gdb.execute("r",to_string=False)
        print("%s Identified Entry Point: 0x%s" % (PROMPT,dec.program_main))

# Startup Banner - Not a GDB command
def banner():
    print("""         _           _     _          _       _            _             _              _      
        /\ \        /\ \  /\ \    _ / /\     /\ \         /\ \     _    /\ \           /\ \    
       /  \ \      /  \ \ \ \ \  /_/ / /    /  \ \       /  \ \   /\_\ /  \ \         /  \ \   
      / /\ \ \    / /\ \ \ \ \ \ \___\/    / /\ \ \     / /\ \ \_/ / // /\ \_\       / /\ \ \  
     / / /\ \_\  / / /\ \_\/ / /  \ \ \   / / /\ \_\   / / /\ \___/ // / /\/_/      / / /\ \_\ 
    / / /_/ / / / /_/_ \/_/\ \ \   \_\ \ / /_/_ \/_/  / / /  \/____// / / ______   / /_/_ \/_/ 
   / / /__\/ / / /____/\    \ \ \  / / // /____/\    / / /    / / // / / /\_____\ / /____/\    
  / / /_____/ / /\____\/     \ \ \/ / // /\____\/   / / /    / / // / /  \/____ // /\____\/    
 / / /\ \ \  / / /______      \ \ \/ // / /______  / / /    / / // / /_____/ / // / /______    
/ / /  \ \ \/ / /_______\      \ \  // / /_______\/ / /    / / // / /______\/ // / /_______\   
\/_/    \_\/\/__________/       \_\/ \/__________/\/_/     \/_/ \/___________/ \/__________/   
                                                                                               """)
 
# Adding new commands
RevStart()          # indicates the first instruction to be decompiled
RevStop()           # indicates the last instruction to be decompiled (and descompiles them)
RevStep()           # step-into instructions. One can call stop after ANY instruction.
RevList()           # list decompiled pieces
RevClear()          # clear and discard decompiled pieces
RevReg()            # Show registers
RevRun()            # Start execution
RevHelp()           # Show usage
RevShow()           # Print decompiled code
RevExec()           # Execute decompiled code
RevMem()            # base+offset to memory
RevMemVal()         # value in memory position
RevIgn()            # show ignored instructions
RevTest()           # Test framework
RevDebug()          # Debug Print
RevStats()          # Stats Print
RevAssert()         # Test Execution Result
RevSSA()            # Test SSA form
RevISize()          # Get Instruction Size
RevString()         # Get String from Address
RevInvertBranch()   # Invert branch direction
RevSymbol()         # Check if a symbol is defined
RevEntry()          # Identify function entry point
banner()            # Display Banner at Startup
