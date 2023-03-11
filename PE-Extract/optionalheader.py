import lief

class OptionalHeader (object):

    def __init__ (self) -> None:
        self.__magic = None
        self.__maj_link_ver = None
        self.__min_link_ver = None
        self.__code_size = None
        self.__init_data_size = None
        self.__unint_data_size = None
        self.__code_base = None
        self.__dll_properties: lief.PE.DLL_CHARACTERISTICS = None

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
    
    @magic.setter
    def magic (self, m) -> None:
        self.__magic = m

    @maj_link_ver.setter
    def maj_link_ver (self, v) -> None:
        self.__maj_link_ver = v

    @min_link_ver.setter
    def min_link_ver (self, v) -> None:
        self.__min_link_ver

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
        self.__code_base

    @dll_properties.setter
    def dll_properties (self, p: lief.PE.DLL_CHARACTERISTICS) -> None:
        self.__dll_properties



if __name__ == "__main__":
    pass
