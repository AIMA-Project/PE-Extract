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

    buffer.read((char*) machine, 2);
}


void HeaderInfo::reset_flags()
{
    has_msdos = false;
    has_pe = false;
}


void HeaderInfo::reset_coff()
{
    for (unsigned int i = 0; i < 4; i++)
    {
        // Zero out 16-bit variables
        if (i % 2 == 0)
        {
            machine[i / 2] = 0x00;
            number_of_sections[i / 2] = 0x00;
            size_of_optional_header[i / 2] = 0x00;
            characteristics[i / 2] = 0x00;
        }
        // Zero out 32-bit variables
        time_date_stamp[i] = 0x00;
        pointer_to_symbol_table[i] = 0x00;
        number_of_symbols[i] = 0x00;
    }
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
    std::cout << "\n\nCOFF Header" << std::hex;

    // Declare loop var here so isn't reinstantiated every loop
    unsigned int i = 0;

    std::cout << "\nMachine Type: ";
    for (i = 0; i < 2; i++)
        std::cout << (uint16_t) machine[i];

    std::cout << "\nNum of Sects: ";
    for (i = 0; i < 2; i++)
        std::cout << (uint16_t) number_of_sections[i];

    std::cout << "\nTime Stamp  : ";
    for (i = 0; i < 4; i++)
        std::cout << (uint16_t) time_date_stamp[i];

    std::cout << "\nSym Tab Ptr : ";
    for (i = 0; i < 4; i++)
        std::cout << (uint16_t) pointer_to_symbol_table[i];

    std::cout << "\nNum of Symbs: ";
    for (i = 0; i < 4; i++)
        std::cout << (uint16_t) number_of_symbols[i];

    std::cout << "\nOpt Head Sz : ";
    for (i = 0; i < 2; i++)
        std::cout << (uint16_t) size_of_optional_header[i];

    std::cout << "\nCharacterist: ";
    for (i = 0; i < 2; i++)
        std::cout << (uint16_t) characteristics[i];

    std::cout << std::endl << std::dec;

}
