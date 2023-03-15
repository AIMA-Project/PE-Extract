from coff import CoffHeader
from hashlib import md5, sha1, sha256
from loadconfig import LoadConfigDirectory
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
        # Data size info
        self.__virtual_size: int = 0
        # DOS header data
        self.__e_lfanew: hex(int) = 0
        # Header data
        self.__coff_header: CoffHeader = None
        self.__opt_header: OptionalHeader = None
        # Sections
        self.__sec_list: List[Section] = []
        self.__sec_min_entropy: float = 0.0
        self.__sec_avg_entropy: float = 0.0
        self.__sec_max_entropy: float = 0.0
        # Load configuration
        self.__has_cfg: bool = False
        self.__load_cfg: LoadConfigDirectory = None
        # Load in data from PE file
        self.setup()


    def setup (self) -> None:
        if self.name != "":
            self.check_size()
            self.calc_md5()
            self.calc_sha1()
            self.calc_sha256()
            binary = lief.parse (self.name)
            self.extract_virtual_size (binary)
            self.e_lfanew = binary.dos_header.addressof_new_exeheader
            self.coff_header = CoffHeader (header = binary.header)
            self.opt_header = OptionalHeader (binary.optional_header)
            self.init_sec_list (binary.sections)
            self.calc_sec_entropy()
            self.has_cfg = binary.has_configuration
            if (self.has_cfg):
                self.load_cfg = LoadConfigDirectory (load_cfg = binary.load_configuration)


    def check_size (self) -> None:
        self.size = path.getsize (self.name)

    def calc_md5 (self) -> None:
        hasher = md5()
        with open (self.name, "rb") as f_read:
            block = True
            while block:
                block = f_read.read (4096)
                hasher.update (block)
        self.md5 = hasher.hexdigest()

    def calc_sha1 (self) -> None:
        hasher = sha1()
        with open (self.name, "rb") as f_read:
            block = True
            while block:
                block = f_read.read (4096)
                hasher.update (block)
        self.sha1 = hasher.hexdigest()

    def extract_virtual_size (self, bin: lief.PE.Binary) -> None:
        self.virtual_size = bin.virtual_size

    def calc_sha256 (self) -> None:
        hasher = sha256()
        with open (self.name, "rb") as f_read:
            block = True
            while block:
                block = f_read.read (4096)
                hasher.update (block)
        self.sha256 = hasher.hexdigest()

    def calc_sec_entropy (self) -> None:
        entropy_list: List[int] = []
        for s in self.sec_list:
            entropy_list.append (s.entropy)
        self.sec_min_entropy = min (entropy_list)
        self.sec_avg_entropy = (sum (entropy_list) / len (entropy_list))
        self.sec_max_entropy = max (entropy_list)

    def init_sec_list (self, sections: lief.PE.Binary.it_section) -> int:
        for sec in sections:
            new_section = Section (section_info = sec)
            self.sec_list.append(new_section)
        return len (self.sec_list)
    
    def append_section (self, sec: Section) -> int:
        self.sec_list.append(sec)
        return len (self.sec_list)
    

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
    def virtual_size (self) -> int:
        return self.__virtual_size

    @property
    def e_lfanew (self) -> int:
        return self.__e_lfanew
    
    @property
    def coff_header (self) -> CoffHeader:
        return self.__coff_header
    
    @property
    def opt_header (self) -> OptionalHeader:
        return self.__opt_header
    
    @property
    def sec_list (self) -> List[Section]:
        return self.__sec_list
    
    @property
    def sec_min_entropy (self) -> float:
        return self.__sec_min_entropy
    @property
    def sec_avg_entropy (self) -> float:
        return self.__sec_avg_entropy
    @property
    def sec_max_entropy (self) -> float:
        return self.__sec_max_entropy

    @property
    def has_cfg (self) -> bool:
        return self.__has_cfg

    @property
    def load_cfg (self) -> LoadConfigDirectory:
        return self.__load_cfg
    
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

    @virtual_size.setter
    def virtual_size (self, vs: int) -> None:
        self.__virtual_size = vs

    @e_lfanew.setter
    def e_lfanew (self, n: int) -> None:
        self.__e_lfanew = n

    @coff_header.setter
    def coff_header (self, ch: CoffHeader) -> None:
        self.__coff_header = ch

    @opt_header.setter
    def opt_header (self, oh: OptionalHeader) -> None:
        self.__opt_header = oh
    
    @sec_list.setter
    def sec_list (self, sl: List[Section]) -> None:
        self.__sec_list = sl
    
    @sec_min_entropy.setter
    def sec_min_entropy (self, e: float) -> None:
        self.__sec_min_entropy = e

    @sec_avg_entropy.setter
    def sec_avg_entropy (self, e: float) -> None:
        self.__sec_avg_entropy = e

    @sec_max_entropy.setter
    def sec_max_entropy (self, e: float) -> None:
        self.__sec_max_entropy = e
    
    @has_cfg.setter
    def has_cfg (self, tf: bool) -> None:
        self.__has_cfg = tf

    @load_cfg.setter
    def load_cfg (self, lc: LoadConfigDirectory) -> None:
        self.__load_cfg = lc



    def __str__ (self) -> str:
        return ("Name: " + self.name +
                "\nSize:  " + str (self.size) + " bytes" +
                "\nVSize: " + str (self.virtual_size) + " bytes" +
                "\nMD5 : " + (self.md5) +
                "\nSHA1: " + (self.sha1) + 
                "\nS256: " + str (self.sha256) +
                "\ne_lfanew: " + str (hex (self.e_lfanew)) +
                "\nEntropy: " +
                "\n\tMin: " + str (self.sec_min_entropy) +
                "\n\tAvg: " + str (self.sec_avg_entropy) +
                "\n\tMax: " + str (self.sec_max_entropy) +
                "\nHas Load Cfg: " + str (self.has_cfg)
               )




if __name__ == "__main__":
    test_executable = PortableExecutable(file = argv[1])
    print (test_executable)
    print (test_executable.coff_header)
    print (test_executable.opt_header)
    for s in test_executable.sec_list:
        print (s)
    if test_executable.has_cfg == True:
        print (test_executable.load_cfg)
