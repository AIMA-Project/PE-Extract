/**
 * @author Drew Wheeler
 * @date 2023-02-26
 * 
 */


#ifndef HEADEREXTRACT_HPP
#define HEADEREXTRACT_HPP

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>

const char MS_DOS []= "This program cannot be run in DOS mode.";
const unsigned int MS_DOS_LEN = 39;
const char PE_HEADER [] = "PE\0\0";
const unsigned int PE_HEADER_LEN = 4;


class HeaderInfo
{
public:
    HeaderInfo();
    HeaderInfo (std::string);


    bool analyze_file();

    void find_ms_dos (std::ifstream&);
    void find_pe (std::ifstream&);
    void load_coff (std::ifstream&);


    void reset_flags();
    void reset_coff();


    void print_info();

private:
    std::string file_name;

    uint8_t pe_addr;
    bool has_msdos, has_pe;

    // COFF File Header Information
    uint8_t machine_type [2] = {'\0'};
    uint16_t section_quant;
    uint32_t time_stamp;
    uint32_t sym_tab_ptr;
    uint32_t sym_quant;
    uint16_t opt_header_size;
    uint16_t characteristics;

};


#endif