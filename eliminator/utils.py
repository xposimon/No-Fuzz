from constant import *
from copy import deepcopy
import os
import time
import subprocess
import re
import ctypes
import inspect

import sys

def logprint(*args):
    with open("runtime.log", "w") as f:
        args = list(map(str, args))
        message = ' '.join(args)
        f.write("["+time.ctime(time.time())+"] : "+ message + "\n")

def replace_input_placeholder(target_opts, input_file,
                              input_placeholder='@@'):
    if target_opts == None:
        return None

    if input_file == None or input_placeholder == None:
        raise ValueError("input_file and input_placeholder could not be None")

    if not isinstance(input_placeholder, str) or \
       not isinstance(input_file, str) :
        raise ValueError("input_file and input_placeholder must be of str type")
    
    return [input_file if e == input_placeholder else e for e in target_opts]


def toSigned(n):
    if n & 0xffff0000:
        return n | (-(n & 0x80000000))
    if n & 0xff00:
        return n | (-(n & 0x8000))
    return n | (-(n & 0x80))


def _parse_ins(opcode, ins):
    try:
        res = re.search(r"%s\s([\w\ \+-\[\]]+),\s([\w\ \+-\[\]]+)"%opcode, ins)
        op1, comp_key = res.groups()
        #print(op1, comp_key)
        op1 = op1.strip()
        comp_key = comp_key.strip()
        return (op1, comp_key)
    except:
        return None

def _retrieve_value(r2, symbol, type="cmp"):

    compared_value = r2.cmd("dr " + symbol)

    # pr 4 @ebp-0x34
    # cmp dword [ebp - 0x34], 0x184ch
    if (compared_value == ''):
        if symbol.startswith("dword"):
            byte_num = 4
        elif symbol.startswith("word"):
            byte_num = 2
        elif symbol.startswith("byte"):
            byte_num = 1
        else:
            print("Not recognized pattern")
            return None

        exp = re.search(r".*\[([\w\ \+-]+)\].*", symbol)
        exp = exp.groups()[0]
        compared_value = r2.cmd("pr " + str(byte_num) + " @" + exp)
        pattern_segment = compared_value
    else:
        # symbol store ptr
        print(symbol, compared_value)
        tmp_compared_value = int(compared_value, 16)
        pattern_segment = ''
        while tmp_compared_value > 0:
            char = tmp_compared_value & 0xff
            pattern_segment = pattern_segment + chr(char)
            tmp_compared_value >>= 8

    if type == "cmp":
        return pattern_segment

def _jump_satisfy(instruction, eflag):

    eflag = int(eflag.strip(), 16)
    for name, bit in EFLAGS.items():
        res = eflag & bit
        if res != 0:
            res = 1
        locals()[name] = res

    __judge = {'ja'   : locals()['CF']==0 and locals()['ZF']==0,
               'jae'  : locals()['CF']==0,
               'jb'   : locals()['CF']==1,
               'jbe'  : locals()['CF']==1 or locals()['ZF']==1,
               'jc'   : locals()['CF']==1,
               'je'   : locals()['ZF']==1,
               'jg'   : locals()['ZF']==0 and locals()['SF']==locals()['OF'],
               'jge'  : locals()['SF']==locals()['OF'],
               'jl'   : locals()['SF']!=locals()['OF'],
               'jle'  : locals()['ZF']==1 or locals()['SF']!=locals()['OF'],
               'jo'   : locals()['OF']==1,
               'jp'   : locals()['PF']==1,
               'jpe'  : locals()['PF']==1,
               'jpo'  : locals()['PF']==0,
               'js'   : locals()['SF']==1,
               'jz'   : locals()['ZF']==1,
               }

    tmp = deepcopy(__judge)
    for ins, res in tmp.items():
        __judge[ins[0]+"n"+ins[1:]] = not res

    return __judge[instruction]


def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stop_thread(thread):
    _async_raise(thread.ident, SystemExit)


if __name__ == "__main__":
    print(_jump_satisfy("jle", "0x00000287"))