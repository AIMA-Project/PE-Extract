from pe import PortableExecutable
from sys import argv

import json
import lief
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
        self.__flag_packed_sections: bool = False
        # Information relating to potentially malicious attributes
        self.__vt_match_ratio: float = 0.0
        self.__packing_type: str = "Not Packed"
        self.__packed_section_count: int = 0
        '''
        TODO:
            - Check for small number of library imports to indiacte packed/obfuscated content.
            - Locate OEP (original entry point) of packed executables.
            - Find IAP?
            - Detect the following packers:
                [x] UPX
                [ ] Themida
                [ ] The Enigma Protector
                [ ] VMProtect
                [ ] Obsidium
                [ ] MPRESS
                [ ] Exe Packer 2.300
                [ ] ExeStealth
        '''


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
            # Try calculate ratio, if no misses, set ratio to number of hits
            try:
                self.vt_match_ratio = hits / misses
            except ZeroDivisionError:
                self.vt_match_ratio = hits
            # Set flag based on if there are more hits or misses in API
            if hits >= misses:
                self.flag_vt_match = True
            else:
                self.flag_vt_match = False
        else:
            self.flag_vt_match = False

    def check_section_names (self) -> None:
        for sections in self.executable.sec_list:
            if (sections.full_name[0:3] == "UPX"):
                self.flag_packed_sections = True
                self.packing_type = "UPX"
                self.packed_section_count += 1


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

    @property
    def flag_packed_sections (self) -> bool:
        return self.__flag_packed_sections

    @property
    def vt_match_ratio (self) -> float:
        return self.__vt_match_ratio

    @property
    def packing_type (self) -> str:
        return self.__packing_type

    @property
    def packed_section_count (self) -> int:
        return self.__packed_section_count

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

    @flag_packed_sections.setter
    def flag_packed_sections (self, flag: bool) -> None:
        self.__flag_packed_sections = flag
    
    @vt_match_ratio.setter
    def vt_match_ratio (self, ratio: float) -> None:
        self.__vt_match_ratio = ratio

    @packing_type.setter
    def packing_type (self, packing: str) -> None:
        self.__packing_type = packing

    @packed_section_count.setter
    def packed_section_count (self, count: int) -> None:
        self.__packed_section_count = count


    # Overloads
    def __str__ (self) -> str:
        return ("\nFile : " + self.input_file +
                "\nFlags: " +
                "\n\tMismatched Sizes: " + str (self.flag_mismatched_sizes) +
                "\n\tIs Packed       : " + str (self.flag_packed_sections) +
                "\n\tPacking Type    : " + str (self.packing_type) +
                "\n\tPacked Sections : " + str (self.packed_section_count) +
                "\n\tVirusTotal Match: " + str (self.flag_vt_match) +
                "\n\tVT Match Ratio  : " + str (self.vt_match_ratio)
               )





if __name__ == "__main__":
    analysis = AnalysisEngine (file = argv[1])
    analysis.validate_sizes ()
    analysis.query_vt_api ()
    analysis.check_section_names ()
    print (analysis)
