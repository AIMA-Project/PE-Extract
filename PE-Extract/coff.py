from datetime import datetime
from multipledispatch import dispatch

import lief


class CoffHeader (object):

    @dispatch()
    def __init__ (self) -> None:
        self.__target_machine: lief.PE.MACHINE_TYPES = None
        self.__timestamp: datetime = None

    
    def find_timestamp (self, header: lief.PE.Header) -> None:
        self.timestamp = header.time_date_stamps


    # Accessors and mutators
    @property
    def target_machine (self) -> lief.PE.MACHINE_TYPES:
        return self.__target_machine
    
    @property
    def timestamp (self) -> datetime:
        return self.__timestamp
    
    @target_machine.setter
    def target_machine (self, t_mchn: lief.PE.MACHINE_TYPES) -> None:
        self.__target_machine = t_mchn
    
    @timestamp.setter
    def timestamp (self, ts: datetime) -> None:
        self.__timestamp = ts


    def __str__ (self) -> str:
        return "Mchn: " + str (self.target_machine) + "\nTime: " + str (self.timestamp)
    


if __name__ == "__main__":
    test_coff = CoffHeader()
    print(test_coff)
