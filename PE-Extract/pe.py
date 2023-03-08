from coff import CoffHeader
from hashlib import sha256
from multipledispatch import dispatch
from optionalheader import OptionalHeader
from os import path
from sys import argv


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

    @dispatch(str)
    def __init__ (self, file: str) -> None:
        # General information about the executable
        self.__name: str = file
        self.__size: int = 0
        self.check_size() # Get size of specified file
        self.__sha256: sha256 = None
        # Header data
        self.__coff_header: CoffHeader = CoffHeader()
        self.__opt_header: OptionalHeader = OptionalHeader()


    def check_size (self) -> None:
        self.size = path.getsize (self.name)

    def calculate_sha256 (self) -> None:
        # TODO: Do the code here
        self.sha256 = None


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
    
    @name.setter
    def name (self, n: str) -> None:
        self.__name = n

    @size.setter
    def size (self, s: int) -> None:
        self.__size = s


    def __str__ (self) -> str:
        return ("Name: " + self.name + "\nSize: " + str (self.size))









if __name__ == "__main__":
    test_executable = PortableExecutable(argv[1])
    print (test_executable)

