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
