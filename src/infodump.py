'''
@file analysisengine.py
@author Drew Wheeler

@brief Contains definitions for the InfoDump class.

The InfoDump class enables data collected through the analysis of PE files to be exported from the
classes that store it into a JSON file for portability.

@see pe.py

'''


from analysisengine import AnalysisEngine
from sys import argv

import json


class InfoDump (object):
    def __init__ (self, target_file: str = "", do_api_checks: bool = False) -> None:
        self.__analyzer: AnalysisEngine = AnalysisEngine(file = target_file,
                                                         do_api_checks = do_api_checks)
        self.__api_checks: bool = do_api_checks
        self.setup()


    def setup (self) -> None:
        if (self.__api_checks):
            self.__analyzer.query_vt_api ()
        self.__analyzer.validate_sizes ()
        self.__analyzer.check_section_names ()

    def export_and_write (self, output_file:str = "out.json") -> None:
        with open (output_file, 'w') as exporter:
            # Generate dictionaries containing component data
            a_eng =self.export_analysis_engine ()
            pe = self.export_portable_executable ()
            ch = self.export_coff_header ()
            opt = self.export_optional_header ()
            sec = self.export_sections ()
            cfg = None
            if (self.__analyzer.executable.has_cfg == True):
                cfg = self.export_load_config ()
            l_imp = self.export_library_imports ()
            # Aggregate data and prepare to be written to JSON
            export_dict = {
                "file" : self.__analyzer.input_file,
                "analysis" : a_eng,
                "overview" : pe,
                "coff" : ch,
                "optional" : opt,
                "sections" : sec,
                "load config" : cfg,
                "library imports" : l_imp
            }
            json.dump (export_dict, exporter, indent = 4)

    def export_analysis_engine (self) -> dict():
        out_dict = {
            "mismatched sizes" : self.__analyzer.flag_mismatched_sizes,
            "is packed" : self.__analyzer.flag_packed_sections,
            "packing type" : self.__analyzer.packing_type,
            "packed sections" : self.__analyzer.packed_section_count,
            "vt called" : self.__api_checks,
            "vt match" : self.__analyzer.flag_vt_match,
            "vt match ratio" : self.__analyzer.vt_match_ratio
        }
        return out_dict
    
    def export_coff_header (self) -> dict():
        out_dict = {
            "target machine" : str(self.__analyzer.executable.coff_header.target_machine),
            "section quantity" : self.__analyzer.executable.coff_header.section_quantity,
            "timestamp" : self.__analyzer.executable.coff_header.timestamp,
            "sym table ptr" : self.__analyzer.executable.coff_header.sym_table_ptr,
            "sym quantity" : self.__analyzer.executable.coff_header.symbol_quantity,
            "opt header size" : self.__analyzer.executable.coff_header.opt_header_size,
            # TODO: Serialize the characteristics list
            "characteristics" : str(self.__analyzer.executable.coff_header.characteristics)
        }
        return out_dict

    def export_portable_executable (self) -> dict():
        out_dict = {
            "size" : self.__analyzer.executable.size,
            "virtual size" : self.__analyzer.executable.virtual_size,
            "md5" : self.__analyzer.executable.md5,
            "sha1" : self.__analyzer.executable.sha1,
            "sha256" : self.__analyzer.executable.sha256,
            "e_lfanew" : self.__analyzer.executable.e_lfanew,
            "min entropy" : self.__analyzer.executable.sec_min_entropy,
            "avg entropy" : self.__analyzer.executable.sec_avg_entropy,
            "max entropy" : self.__analyzer.executable.sec_max_entropy,
            "has load cfg" : self.__analyzer.executable.has_cfg
        }
        return out_dict

    def export_optional_header (self) -> dict():
        out_dict = {
            "magic" : hex (self.__analyzer.executable.opt_header.magic),
            "maj link ver" : self.__analyzer.executable.opt_header.maj_link_ver,
            "min link ver" : self.__analyzer.executable.opt_header.min_link_ver,
            "code size" : self.__analyzer.executable.opt_header.code_size,
            "init dat size" : self.__analyzer.executable.opt_header.init_data_size,
            "uninit dat size" : self.__analyzer.executable.opt_header.uninit_data_size,
            "code base" : self.__analyzer.executable.opt_header.code_base,
            "dll properties" : hex (self.__analyzer.executable.opt_header.dll_properties),
            "imagebase" : self.__analyzer.executable.opt_header.imagebase,
            "file align" : self.__analyzer.executable.opt_header.file_alignment,
            "image size" : self.__analyzer.executable.opt_header.image_size,
            "header size" : self.__analyzer.executable.opt_header.header_size,
            "stack reserve" : self.__analyzer.executable.opt_header.stack_reserve_size,
            "subsystem" : str (self.__analyzer.executable.opt_header.subsystem),
            "maj subsys ver" : self.__analyzer.executable.opt_header.maj_subsys_ver,
            "min subsys ver" : self.__analyzer.executable.opt_header.min_subsys_ver,
            "maj os ver" : self.__analyzer.executable.opt_header.maj_os_ver,
            "min os ver" : self.__analyzer.executable.opt_header.min_os_ver
        }
        return out_dict

    def export_sections (self) -> dict():
        ret_dict = {}
        for sec in self.__analyzer.executable.sec_list:
            # TODO: Serialize the elements of characteristics
            ret_dict[sec.full_name.replace('\00', '')] = {"characteristics" : str(sec.characteristics),
                                                          "entropy" : sec.entropy}
        return ret_dict
    
    def export_load_config (self) -> dict():
        ret_dict = {
            "security cookie" : str(self.__analyzer.executable.load_cfg.security_cookie)
        }
        return ret_dict
    
    def export_library_imports (self) -> dict():
        ret_dict = {}
        for imp in self.__analyzer.executable.imports:
            ret_dict[imp.import_name] = list(imp.import_functions)
        return ret_dict
    
    # Accessor and Mutators
    @property
    def analyzer (self) -> AnalysisEngine:
        return self.__analyzer
    
    @property
    def api_checks (self) -> bool:
        return self.__api_checks
    
    @analyzer.setter
    def analyzer (self, engine_instance: AnalysisEngine) -> None:
        self.__analyzer = engine_instance

    @api_checks.setter
    def api_checks (self, do_checks: bool) -> None:
        self.__api_checks = do_checks
        



if __name__ == "__main__":
    export_data = InfoDump (target_file = argv[1], do_api_checks = False)
    export_data.export_and_write (output_file = "analysis.json")
