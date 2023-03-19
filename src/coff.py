'''
@file coff.py
@author Drew Wheeler

@brief Contains definitions for the CoffHeader class.

The COFF header stores various data about a PE file. The most interesting of these are the
target machine, the number of sections in the executable, and the list of characterisitics of the
executable. Other data are also present in this section that are ancillary, but important
nonetheless.

The CoffHeader class is a component of the PortableExecutable class, which is the enveloping
structure that actually utilizes its functionality.

@see pe.py

'''


from datetime import datetime, timezone
from typing import List

import lief


class CoffHeader (object):

    # Initializer
    def __init__ (self, header: lief.PE.Header = None) -> None:
        self.__target_machine: lief.PE.MACHINE_TYPES = None
        self.__section_quantity: int = 0
        self.__timestamp: datetime = datetime(1970, 1, 1, tzinfo=timezone.utc) # Init to epoch
        self.__sym_table_ptr: int = 0       # Normally Unused; COFF DBGing Deprecated
        self.__symbol_quantity: int = 0     # Normally Unused; COFF DBGing Deprecated
        self.__opt_header_size: int = 0
        self.__characteristics: List[lief.PE.HEADER_CHARACTERISTICS] = []
        # Try to extract data from header
        self.setup (header)


    # Header extraction methods
    def setup (self, header: lief.PE.Header) -> None:
        if header is not None:
            self.extract_machine (header)
            self.extract_section_quant (header)
            self.extract_timestamp (header)
            self.extract_sym_tab_ptr (header)
            self.extract_symbol_quant (header)
            self.extract_opt_head_size (header)
            self.extract_characteristics (header)

    def extract_machine (self, header: lief.PE.Header) -> None:
        self.target_machine = header.machine

    def extract_section_quant (self, header: lief.PE.Header) -> None:
        self.section_quantity = header.numberof_sections
    
    def extract_timestamp (self, header: lief.PE.Header) -> None:
        self.timestamp = datetime.fromtimestamp(header.time_date_stamps).strftime('%Y-%m-%d %H:%M:%S')

    def extract_characteristics (self, header: lief.PE.Header) -> None:
        self.characteristics = header.characteristics_list

    def extract_sym_tab_ptr (self, header: lief.PE.Header) -> None:
        self.sym_table_ptr = header.pointerto_symbol_table

    def extract_symbol_quant (self, header: lief.PE.Header) -> None:
        self.symbol_quantity = header.numberof_symbols

    def extract_opt_head_size (self, header: lief.PE.Header) -> None:
        self.opt_header_size = header.sizeof_optional_header


    # Accessors and mutators
    @property
    def target_machine (self) -> lief.PE.MACHINE_TYPES:
        return self.__target_machine
    
    @property
    def section_quantity (self) -> int:
        return self.__section_quantity
    
    @property
    def timestamp (self) -> datetime:
        return self.__timestamp
    
    @property
    def characteristics (self) -> List[lief.PE.HEADER_CHARACTERISTICS]:
        return self.__characteristics

    @property
    def sym_table_ptr (self) -> int:
        return self.__sym_table_ptr

    @property
    def symbol_quantity (self) -> int:
        return self.__symbol_quantity

    @property
    def opt_header_size (self) -> int:
        return self.__opt_header_size
    
    @target_machine.setter
    def target_machine (self, t_mchn: lief.PE.MACHINE_TYPES) -> None:
        self.__target_machine = t_mchn

    @section_quantity.setter
    def section_quantity (self, sec_quant: int) -> None:
        self.__section_quantity = sec_quant
    
    @timestamp.setter
    def timestamp (self, ts: datetime) -> None:
        self.__timestamp = ts

    @characteristics.setter
    def characteristics (self, c: List[lief.PE.HEADER_CHARACTERISTICS]) -> None:
        self.__characteristics = c

    @sym_table_ptr.setter
    def sym_table_ptr (self, ptr: int) -> None:
        self.__sym_table_ptr = ptr

    @symbol_quantity.setter
    def symbol_quantity (self, quant: int) -> None:
        self.__symbol_quantity = quant

    @opt_header_size.setter
    def opt_header_size (self, s: int) -> None:
        self.__opt_header_size = s


    # Overloads
    def __str__ (self) -> str:
        return ("\nMachine     : " + str (self.target_machine) + 
                "\nSec Quant   : " + str (self.section_quantity) +
                "\nTimeStamp   : " + str (self.timestamp) +
                "\nSym Tab Ptr : " + str (self.sym_table_ptr) +
                "\nSym Quant   : " + str (self.symbol_quantity) +
                "\nOpt Head Sz : " + str (self.opt_header_size) +
                "\nCharacteris : " + str (self.characteristics))
    


if __name__ == "__main__":
    test_coff = CoffHeader()
