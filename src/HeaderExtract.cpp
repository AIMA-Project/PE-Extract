/**
 * @author Drew Wheeler
 * @date 2023-02-26
 * 
 */


#include "HeaderExtract.hpp"


HeaderInfo::HeaderInfo()
{
    file_name = "";
    pe_addr = 0x00;
    reset_flags();
    reset_coff();
}

HeaderInfo::HeaderInfo (std::string file)
{
    HeaderInfo();
    file_name = file;
}


bool HeaderInfo::analyze_file()
{
    // Open file to be analyzed using an ifstream buffer
    std::ifstream file_buffer (file_name.c_str(), std::ifstream::in |
                                                  std::ios::binary);
    if (!file_buffer.is_open())
        return false;

    // Specify that whitespace should be presevered as reading
    file_buffer >> std::noskipws;

    // Check for various header information
    find_ms_dos (file_buffer);
    find_pe (file_buffer);
    load_coff (file_buffer);

    // Close file and return
    file_buffer.close();
    return true;
}


void HeaderInfo::find_ms_dos (std::ifstream& buffer)
{
    char buffer_char = ' ';

    buffer.seekg(0x4e, std::ios::beg);
    for (unsigned i = 0; i < MS_DOS_LEN; i++)
    {
        buffer >> buffer_char;
        if (buffer_char != MS_DOS[i])
            break;
        else if (i == MS_DOS_LEN - 1)
            has_msdos = true;
    }
}


void HeaderInfo::find_pe (std::ifstream& buffer)
{
    char buffer_char = ' ';

    // Look for the PE address in the header @ addr 0x3c
    buffer.seekg(0x3c, std::ios::beg);
    pe_addr = (uint8_t)buffer.get();

    // Go to address specified above and try to read in PE\0\0
    buffer.seekg(pe_addr, std::ios::beg);
    for (unsigned int i = 0; i < PE_HEADER_LEN; i++)
    {
        buffer >> buffer_char;
        if (buffer_char != PE_HEADER[i])
            break;
        else if (i == PE_HEADER_LEN - 1)
            has_pe = true;
    }
}

void HeaderInfo::load_coff (std::ifstream& buffer)
{
    buffer.seekg(pe_addr + 4, std::ios::beg);

    buffer.read((char*) machine_type, 2);
}


void HeaderInfo::reset_flags()
{
    has_msdos = false;
    has_pe = false;
}


void HeaderInfo::reset_coff()
{
    machine_type[0] = machine_type[1] = '\0';
    section_quant = 0x0000;
    time_stamp = sym_tab_ptr = sym_quant = 0x00000000;
    opt_header_size = characteristics = 0x0000;
}



void HeaderInfo::print_info()
{
    std::cout << "Report for " << file_name
              << "\nMS DOS Flag: " << has_msdos
              << "\nPE Flag:     " << has_pe
              << "\n\nCOFF Header" << std::hex
              << "\nMachine Type: " << machine_type[0] << machine_type[1]
              << "\nSections    : " << section_quant
              << "\nTime Stamp  : " << time_stamp
              << "\nSym Tab Ptr : " << sym_tab_ptr
              << "\nNo of Symbol: " << sym_quant
              << "\nOpt. Head Sz: " << opt_header_size
              << "\nCharacterist: " << characteristics
              << std::endl;
}
