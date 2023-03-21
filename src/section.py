'''
@file section.py
@author Drew Wheeler

@brief Contains definitions for the Section class.

An executable program is comprised of several sections containing various instructions and data
needed by the executable. A section has various characteristics that identify attributes pertaining
to the section itself. In addition, each section has a calculated entropy value that indicates the
"randomness" of its data.

The theory behind malware detection using sections is that more complex malware will have greater
section entropy. This is a byproduct of obfuscation techniques being used to hide the executable's
true purpose. Calculating entropy can be used as part of a larger examination system to aid in the
detection of malicious files.

The Section class is a component of the PortableExecutable class, with several Sections being
maintained in a list. Minimum, average, and maximum entropy for an executable's sections are
obtained using this list as part of the data collection process.

@see pe.py

'''

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
