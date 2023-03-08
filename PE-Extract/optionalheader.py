from multipledispatch import dispatch

import lief

class OptionalHeader ():

    @dispatch()
    def __init__ (self) -> None:
        self.dll_properties: lief.PE.DLL_CHARACTERISTICS = None

