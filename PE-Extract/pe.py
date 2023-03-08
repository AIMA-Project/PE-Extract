from coff import CoffHeader
from multipledispatch import dispatch
from optionalheader import OptionalHeader

from hashlib import sha256


class PortableExecutable (object):

    @dispatch()
    def __init__ (self) -> None:
        # General imformation about the executable
        self.__name: str = ""
        self.__size: int = 0
        self.__sha256: sha256 = None
        # Header data
        self.__coff_header: CoffHeader = CoffHeader()
        self.__opt_header: OptionalHeader = OptionalHeader()


    # Accessors and mutators
    @property
    def name (self) -> str:
        return self.__name
    
    @property
    def size (self) -> int:
        return self.__size
    
    @property
    def sha256 (self) -> sha256:
        return self.__sha256
    
    @property
    def coff_header (self) -> CoffHeader:
        return self.__coff_header
    
    @property
    def opt_header (self) -> OptionalHeader:
        return self.__opt_header


if __name__ == "__main__":
    test_executable = PortableExecutable()
