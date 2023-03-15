from pe import PortableExecutable
from sys import argv

import json
import vtapi


class AnalysisEngine (object):

    # Initializers
    def __init__ (self, file: str = "", api_key_dir: str = "./") -> None:
        self.__input_file: str = file
        self.__executable: PortableExecutable = PortableExecutable (file)
        self.__vt_api_key: str = vtapi.vt_load_api_key (key_file = (api_key_dir + "virustotal.key"))
        # Flags indicating potentially malicious attributes
        self.__flag_mismatched_sizes: bool = False
        self.__flag_vt_match: bool = False


    # Methods
    def validate_sizes (self) -> None:
        virtual_size: int = self.executable.virtual_size
        image_size: int = self.executable.opt_header.image_size
        if (virtual_size != image_size):
            self.__flag_mismatched_sizes = True
        else:
            self.__flag_mismatched_sizes = False

    def query_vt_api (self) -> None:
        report = vtapi.vt_hash_request (self.executable.sha256, self.vt_api_key)
        if report is not None:
            json_report = json.loads (report.text)
            hits = json_report["data"]["attributes"]["last_analysis_stats"]["malicious"]
            misses = json_report["data"]["attributes"]["last_analysis_stats"]["undetected"]
            if hits >= misses:
                self.flag_vt_match = True
            else:
                self.flag_vt_match = False
        else:
            self.flag_vt_match = False


    # Accessors and mutators
    @property
    def input_file (self) -> str:
        return self.__input_file
    
    @property
    def executable (self) -> PortableExecutable:
        return self.__executable

    @property
    def vt_api_key (self) -> str:
        return self.__vt_api_key

    @property
    def flag_mismatched_sizes (self) -> bool:
        return self.__flag_mismatched_sizes

    @property
    def flag_vt_match (self) -> bool:
        return self.__flag_vt_match

    @input_file.setter
    def input_file (self, file: str) -> None:
        self.__input_file = file
    
    @executable.setter
    def executable (self, exe: PortableExecutable) -> None:
        self.__executable = exe

    @vt_api_key.setter
    def vt_api_key (self, api_key: str) -> None:
        self.__vt_api_key = api_key

    @flag_mismatched_sizes.setter
    def flag_mismatched_sizes (self, flag: bool) -> None:
        self.__flag_mismatched_sizes = flag
    
    @flag_vt_match.setter
    def flag_vt_match (self, flag: bool) -> None:
        self.__flag_vt_match = flag


    # Overloads
    def __str__ (self) -> str:
        return ("\nFile : " + self.input_file +
                "\nFlags: " +
                "\n\tMismatched Sizes: " + str (self.flag_mismatched_sizes) +
                "\n\tVirusTotal Match: " + str (self.flag_vt_match)
               )





if __name__ == "__main__":
    analysis = AnalysisEngine (file = argv[1])
    analysis.validate_sizes ()
    analysis.query_vt_api ()
    print (analysis)

