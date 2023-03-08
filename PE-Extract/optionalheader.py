import lief

class OptionalHeader (object):

    def __init__ (self) -> None:
        self.dll_properties: lief.PE.DLL_CHARACTERISTICS = None

