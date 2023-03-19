'''
@file optionalheader.py
@author Drew Wheeler

@brief Contains definitions for the OptionalHeader class.

The optional header is a header found in PE files, but not necessarily object files (hence the
"optional" designation). It contains a wide variety of information valuable to malware analysis. The
primary data extracted in this situation are related to code structure, simple linker informaiton,
and characteristics of the target machine.

A large portion of the optional header is used as part of malware analysis, as it contains a general
overview of the program. In this instance, the OptionalHeader class is used as part of the larger
PortableExecutable class.

@see pe.py

'''

import lief

class OptionalHeader (object):

    def __init__ (self, opt_header: lief.PE.OptionalHeader = None) -> None:
        # Standard information
        self.__magic: hex = 0x0000
        self.__maj_link_ver: int = 0
        self.__min_link_ver: int = 0
        self.__code_size = None
        self.__init_data_size = None
        self.__unint_data_size = None
        self.__code_base = None
        self.__dll_properties: lief.PE.DLL_CHARACTERISTICS = None
        # Windows-specific fields
        self.__imagebase: int = 0
        self.__file_alignment: int = 0
        self.__image_size: int = 0
        self.__header_size: int = 0
        self.__stack_reserve_size: int = 0
        self.__subsystem: lief.PE.SUBSYSTEM = None
        self.__maj_subsys_ver: int = 0
        self.__min_subsys_ver: int = 0
        self.__maj_os_ver: int = 0
        self.__min_os_ver: int = 0
        # Extract relevant information
        self.setup (opt_header)


    def setup (self, opt_header: lief.PE.OptionalHeader) -> None:
        if opt_header is not None:
            # This seems a bit excessive, wonder if way to condense them
            self.extract_magic            (opt_header)
            self.extract_maj_link_ver     (opt_header)
            self.extract_min_link_ver     (opt_header)
            self.extract_code_size        (opt_header)
            self.extract_init_data_size   (opt_header)
            self.extract_uninit_data_size (opt_header)
            self.extract_code_base        (opt_header)
            self.extract_dll_properties   (opt_header)
            self.extract_imagebase        (opt_header)
            self.extract_file_alignment   (opt_header)
            self.extract_image_size       (opt_header)
            self.extract_header_size      (opt_header)
            self.extract_stack_reserve_size (opt_header)
            self.extract_full_subsystem   (opt_header)
            self.extract_maj_os_ver       (opt_header)
            self.extract_min_os_ver       (opt_header)

    def extract_magic (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.magic = opt_header.magic

    def extract_maj_link_ver (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.maj_link_ver = opt_header.major_linker_version

    def extract_min_link_ver (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.min_link_ver = opt_header.minor_linker_version

    def extract_code_size (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.code_size = opt_header.sizeof_code
    
    def extract_init_data_size (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.init_data_size = opt_header.sizeof_initialized_data

    def extract_uninit_data_size (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.uninit_data_size = opt_header.sizeof_uninitialized_data

    def extract_code_base (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.code_base = opt_header.baseof_code

    def extract_dll_properties (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.dll_properties = opt_header.dll_characteristics

    def extract_imagebase (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.imagebase = opt_header.imagebase

    def extract_file_alignment (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.file_alignment = opt_header.file_alignment

    def extract_image_size (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.image_size = opt_header.sizeof_image

    def extract_header_size (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.header_size = opt_header.sizeof_headers

    def extract_stack_reserve_size (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.stack_reserve_size = opt_header.sizeof_stack_reserve

    def extract_full_subsystem (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.extract_subsystem      (opt_header)
        self.extract_maj_subsys_ver (opt_header)
        self.extract_min_subsys_ver (opt_header)

    def extract_subsystem (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.subsystem = opt_header.subsystem

    def extract_maj_subsys_ver (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.maj_subsys_ver = opt_header.major_subsystem_version

    def extract_min_subsys_ver (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.min_subsys_ver = opt_header.minor_subsystem_version

    def extract_maj_os_ver (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.maj_os_ver = opt_header.major_operating_system_version

    def extract_min_os_ver (self, opt_header: lief.PE.OptionalHeader) -> None:
        self.min_os_ver = opt_header.minor_operating_system_version


    # Accessors and mutators
    @property
    def magic (self):
        return self.__magic

    @property
    def maj_link_ver (self):
        return self.__maj_link_ver

    @property
    def min_link_ver (self):
        return self.__min_link_ver

    @property
    def code_size (self):
        return self.__code_size

    @property
    def init_data_size (self):
        return self.__init_data_size

    @property
    def unint_data_size (self):
        return self.__unint_data_size

    @property
    def code_base (self):
        return self.__code_base
    
    @property
    def dll_properties (self) -> lief.PE.DLL_CHARACTERISTICS:
        return self.__dll_properties
    
    @property
    def imagebase (self) -> int:
        return self.__imagebase

    @property
    def file_alignment (self) -> int:
        return self.__file_alignment

    @property
    def image_size (self) -> int:
        return self.__image_size

    @property
    def header_size (self) -> int:
        return self.__header_size
    
    @property
    def stack_reserve_size (self) -> int:
        return self.__stack_reserve_size
    
    @property
    def subsystem (self) -> lief.PE.SUBSYSTEM:
        return self.__subsystem
    
    @property
    def maj_subsys_ver (self) -> int:
        return self.__maj_subsys_ver
    
    @property
    def min_subsys_ver (self) -> int:
        return self.__min_subsys_ver
    
    @property
    def maj_os_ver (self) -> int:
        return self.__maj_os_ver
    
    @property
    def min_os_ver (self) -> int:
        return self.__min_os_ver
    
    @magic.setter
    def magic (self, m) -> None:
        self.__magic = m

    @maj_link_ver.setter
    def maj_link_ver (self, v) -> None:
        self.__maj_link_ver = v

    @min_link_ver.setter
    def min_link_ver (self, v) -> None:
        self.__min_link_ver = v

    @code_size.setter
    def code_size (self, s) -> None:
        self.__code_size = s

    @init_data_size.setter
    def init_data_size (self, s) -> None:
        self.__init_data_size = s

    @unint_data_size.setter
    def uninit_data_size (self, s) -> None:
        self.__unint_data_size = s

    @code_base.setter
    def code_base (self, b) -> None:
        self.__code_base = b

    @dll_properties.setter
    def dll_properties (self, p: lief.PE.DLL_CHARACTERISTICS) -> None:
        self.__dll_properties = p

    @imagebase.setter
    def imagebase (self, ib: int) -> None:
        self.__imagebase = ib

    @file_alignment.setter
    def file_alignment (self, fa: int) -> None:
        self.__file_alignment = fa

    @image_size.setter
    def image_size (self, s: int) -> None:
        self.__image_size = s

    @header_size.setter
    def header_size (self, s: int) -> None:
        self.__header_size = s

    @stack_reserve_size.setter
    def stack_reserve_size (self, s: int) -> None:
        self.__stack_reserve_size = s

    @subsystem.setter
    def subsystem (self, s: lief.PE.SUBSYSTEM) -> None:
        self.__subsystem = s

    @maj_subsys_ver.setter
    def maj_subsys_ver (self, v: int) -> None:
        self.__maj_subsys_ver = v

    @min_subsys_ver.setter
    def min_subsys_ver (self, v: int) -> None:
        self.__min_subsys_ver = v

    @maj_os_ver.setter
    def maj_os_ver (self, v: int) -> None:
        self.__maj_os_ver = v

    @min_os_ver.setter
    def min_os_ver (self, v: int) -> None:
        self.__min_os_ver = v

    
    # Overloads
    def __str__ (self) -> str:
        return ("Magic: " + str( hex (self.magic)) +
                "\nLinker Version: " + str (self.maj_link_ver) + '.' + str (self.min_link_ver) +
                "\nCode Size: " + str (self.code_size) +
                "\nInit. Data Size: " + str (self.init_data_size) +
                "\nUninit. Data Size: " + str (self.uninit_data_size) +
                "\nCode Base: " + str (hex (self.code_base)) +
                "\nDLL Characts: " + str ( bin (self.dll_properties)) +
                "\nImage Base: " + str ( hex (self.imagebase)) +
                "\nFile Align: " + str (self.file_alignment) +
                "\n Img Size : " + str (self.image_size) +
                "\nHead Size : " + str( self.header_size) +
                "\nStk Res Size: " + str (self.stack_reserve_size) +
                "\nSubsystem : " + str (self.subsystem) +
                "\nSubsys Versi: " + str (self.maj_subsys_ver) + "." + str (self.min_subsys_ver) +
                "\nOS Version  : " + str (self.maj_os_ver) + "." + str (self.min_os_ver))



if __name__ == "__main__":
    pass
