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

    def export_all (self, output_file:str = "out.json") -> None:
        with open (output_file, 'w') as exporter:
            self.export_analysis_engine (export_stream = exporter)

    def export_analysis_engine (self, export_stream = None) -> None:
        # Only export if the stream passed in is active
        if export_stream is not None:
            # Create a temporary dictionary to allow for json.dump to work
            out_dict = {
                "file" : self.__analyzer.input_file,
                "mismatched sizes" : self.__analyzer.flag_mismatched_sizes,
                "is packed" : self.__analyzer.flag_packed_sections,
                "packing type" : self.__analyzer.packing_type,
                "packed sections" : self.__analyzer.packed_section_count,
                "vt called" : self.__api_checks,
                "vt match" : self.__analyzer.flag_vt_match,
                "vt match ratio" : self.__analyzer.vt_match_ratio
            }
            json.dump (out_dict, export_stream)

    
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
    export_data.export_all (output_file = "analysis.json")
