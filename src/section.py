import lief


class Section (object):

    # Initializer
    def __init__ (self, section_info: lief.PE.Section) -> None:
        self.__full_name: str = ""
        self.__characteristics: lief.PE.Section.characteristics_lists = []
        self.__entropy: float = 0
        self.setup (section_info)


    # Methods
    def setup (self, s_info: lief.PE.Section) -> None:
        self.full_name = s_info.fullname
        self.characteristics = s_info.characteristics_lists
        self.entropy = s_info.entropy


    # Accessors and mutators
    @property
    def full_name (self) -> str:
        return self.__full_name

    @property    
    def characteristics (self) -> lief.PE.Section.characteristics_lists:
        return self.__characteristics
    
    @property
    def entropy (self) -> float:
        return self.__entropy
    
    @full_name.setter
    def full_name (self, n: str) -> None:
        self.__full_name = n

    @characteristics.setter
    def characteristics (self, c: lief.PE.Section.characteristics_lists) -> None:
        self.__characteristics = c

    @entropy.setter
    def entropy (self, e: float) -> None:
        self.__entropy = e

    
    # Overloads
    def __str__ (self) -> str:
        return ("\nSection Name   : " + str (self.full_name) +
                "\nCharacteristics: " + str (self.characteristics) +
                "\nSection Entropy: " + str (self.entropy)
                )
