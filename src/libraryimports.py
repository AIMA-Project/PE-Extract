'''
@file libraryimports.py
@author Drew Wheeler

@brief Contains definitions for the LibraryImport class.

An external library import in Windows allows PE files to call functions defined in files not
native to the program. These functions are often stored in .dll (dynamic link library) files. For
the system to allow a program to call these files, it most have both the file name and the
functions being called. The LibraryImport file stores a single import containing the file name and
the list of functions it calls.

An important aspect of malware analysis is understanding how it interacts with the system. A list of
system calls can be used as part of the analysis process. In addition, sometimes the quantity of
imports made by an executable can tip off if it is malware.

@see pe.py

'''

from typing import List

import lief


class LibraryImport (object):
    def __init__ (self, name: str = "", functions: List[str] = []) -> None:
        self.__import_name: str = name
        self.__import_functions: List[str] = functions


    # Methods
    def append_function (self, function: str) -> None:
        self.import_functions.append (function)


    # Accessors and mutators    
    @property
    def import_name (self) -> str:
        return self.__import_name

    @property
    def import_functions (self) -> List[str]:
        return self.__import_functions

    @import_name.setter
    def import_name (self, name: str) -> None:
        self.__import_name = name

    @import_functions.setter
    def import_functions (self, functs: List[str]) -> None:
        self.__import_functions = functs

    
    # Overloads
    def __str__ (self) -> str:
        function_string: str = ""
        for f in self.import_functions:
            function_string += "\n\t" + str (f)
        return ("\nName: " + self.import_name +
                "\nFunctions: " + function_string)





if __name__ == "__main__":
    pass
