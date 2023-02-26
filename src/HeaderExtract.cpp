/**
 * @author Drew Wheeler
 * @date 2023-02-26
 * 
 */

#include "BinManip.hpp"

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

    // Look for the MS-DOS indicator at addr 0x4e
    buffer.seekg(0x4e, std::ios::beg);
    for (unsigned i = 0; i < MS_DOS_LEN; i++)
    {
        buffer >> buffer_char;
        // Inconsistent header, stop looking
        if (buffer_char != MS_DOS[i])
            break;
        // MS-DOS string was found
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
        // Inconsistent header, stop looking
        if (buffer_char != PE_HEADER[i])
            break;
        // PE\0\0 was found
        else if (i == PE_HEADER_LEN - 1)
            has_pe = true;
    }
}

void HeaderInfo::load_coff (std::ifstream& buffer)
{
    buffer.seekg(pe_addr + 4, std::ios::beg);

    uint8_t word[2];
    uint8_t dword[4];

    // TODO: Put each of these reads into its own function

    // Read each attribute of the COFF section
    buffer.read((char*) word, 2);
    swap_endian(word, 2);
    bitstring_to_word (&machine, word);

    buffer.read((char*) word, 2);
    swap_endian(word, 2);
    bitstring_to_word (&number_of_sections, word);

    buffer.read((char*) dword, 4);
    swap_endian(dword, 4);
    bitstring_to_dword (&time_date_stamp, dword);

    buffer.read((char*) dword, 4);
    swap_endian(dword, 4);
    bitstring_to_dword (&pointer_to_symbol_table, dword);

    buffer.read((char*) dword, 4);
    swap_endian(dword, 4);
    bitstring_to_dword (&number_of_symbols, dword);

    buffer.read((char*) word, 2);
    swap_endian(word, 2);
    bitstring_to_word (&size_of_optional_header, word);

    buffer.read((char*) word, 2);
    swap_endian(word, 2);
    bitstring_to_word (&characteristics, word);
}


void HeaderInfo::reset_flags()
{
    has_msdos = false;
    has_pe = false;
}


void HeaderInfo::reset_coff()
{
    machine = 0x0000;
    number_of_sections = 0x0000;
    time_date_stamp = 0x00000000;
    pointer_to_symbol_table = 0x00000000;
    number_of_symbols = 0x00000000;
    size_of_optional_header = 0x0000;
    characteristics = 0x0000;
}



void HeaderInfo::print_info()
{
    std::cout << "Report for " << file_name
              << "\nMS DOS Flag: " << has_msdos
              << "\nPE Flag:     " << has_pe
              << std::endl;
}


void HeaderInfo::print_coff()
{
    std::cout             << "\nCOFF Header"
                          << "\n========================="
              << std::hex << "\nMachine Type: 0x" << machine
              << std::dec << "\nNum of Sects: " << number_of_sections
              << std::hex << "\nTime Stamp  : " << time_date_stamp
              << std::hex << "\nSym Tab Ptr : 0x" << pointer_to_symbol_table
              << std::dec << "\nNum of Symbs: " << number_of_symbols
                          << "\nOpt Headr Sz: " << size_of_optional_header
              << std::hex << "\nCharacterist: 0x" << characteristics
              << std::endl << std::dec;

}
