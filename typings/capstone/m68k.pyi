"""
This type stub file was generated by pyright.
"""

import ctypes
from .m68k_const import *

class M68KOpMem(ctypes.Structure):
    _fields_ = ...


class M68KOpRegPair(ctypes.Structure):
    _fields_ = ...


class M68KOpValue(ctypes.Union):
    _fields_ = ...


class M68KOpBrDisp(ctypes.Structure):
    _fields_ = ...


class M68KOp(ctypes.Structure):
    _fields_ = ...
    @property
    def imm(self): # -> Any:
        ...
    
    @property
    def dimm(self): # -> Any:
        ...
    
    @property
    def simm(self): # -> Any:
        ...
    
    @property
    def reg(self): # -> Any:
        ...
    
    @property
    def mem(self):
        ...
    
    @property
    def register_bits(self):
        ...
    


class M68KOpSize(ctypes.Structure):
    _fields_ = ...
    def get(a):
        ...
    


class CsM68K(ctypes.Structure):
    M68K_OPERAND_COUNT = ...
    _fields_ = ...


def get_arch_info(a): # -> tuple[list[Any], Unknown]:
    ...
