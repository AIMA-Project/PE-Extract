from coff import CoffHeader
from hashlib import md5, sha1, sha256
from optionalheader import OptionalHeader
from os import path
from section import Section
from sys import argv
from typing import List

import lief


class PortableExecutable (object):

    def __init__ (self, file: str = "") -> None:
        # General imformation about the executable
        self.__name: str = file
        self.__size: int = 0
        self.__md5: str = ""
        self.__sha1: str = ""
        self.__sha256: str = ""
        # Header data
        self.__coff_header: CoffHeader = None
        self.__opt_header: OptionalHeader = None
        # Sections
        self.__sec_list: List[Section] = []
        self.setup()


    def setup (self) -> None:
        if self.name != "":
            self.check_size()
            self.calculate_md5()
            self.calculate_sha1()
            self.calculate_sha256()
            binary = lief.parse (self.name)
            self.coff_header = CoffHeader (header = binary.header)
            self.opt_header = OptionalHeader (binary.optional_header)

    def check_size (self) -> None:
        self.size = path.getsize (self.name)

    def calculate_md5 (self) -> None:
        hasher = md5()
        with open (self.name, "rb") as f_read:
            block = True
            while block:
                block = f_read.read (4096)
                hasher.update (block)
        self.md5 = hasher.hexdigest()

    def calculate_sha1 (self) -> None:
        hasher = sha1()
        with open (self.name, "rb") as f_read:
            block = True
            while block:
                block = f_read.read (4096)
                hasher.update (block)
        self.sha1 = hasher.hexdigest()

    def calculate_sha256 (self) -> None:
        hasher = sha256()
        with open (self.name, "rb") as f_read:
            block = True
            while block:
                block = f_read.read (4096)
                hasher.update (block)
        self.sha256 = hasher.hexdigest()


    # Accessors and mutators
    @property
    def name (self) -> str:
        return self.__name
    
    @property
    def size (self) -> int:
        return self.__size
    
    @property
    def md5 (self) -> str:
        return self.__md5
    
    @property
    def sha1 (self) -> str:
        return self.__sha1
    
    @property
    def sha256 (self) -> str:
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

    @md5.setter
    def md5 (self, h: str) -> None:
        self.__md5 = h

    @sha1.setter
    def sha1 (self, h: str) -> None:
        self.__sha1 = h

    @sha256.setter
    def sha256 (self, h: str) -> None:
        self.__sha256 = h

    @coff_header.setter
    def coff_header (self, ch: CoffHeader) -> None:
        self.__coff_header = ch

    @opt_header.setter
    def opt_header (self, oh: OptionalHeader) -> None:
        self.__opt_header = oh


    def __str__ (self) -> str:
        return ("Name: " + self.name + "\nSize: " + str (self.size) + " bytes" + "\nMD5 : " +
                 self.md5 + "\nSHA1: " + self.sha1 +  "\nS256: " + self.sha256)




if __name__ == "__main__":
    test_executable = PortableExecutable(file = argv[1])
    # print (test_executable)
    # print (test_executable.coff_header)
    print (test_executable.opt_header)
