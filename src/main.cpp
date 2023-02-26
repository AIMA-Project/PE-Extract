/**
 * @author Drew Wheeler
 * @date 2023-02-26
 * 
 */

#include "HeaderExtract.hpp"

int main (int argc, char** argv)
{
    std::string file = "testfiles/rufus.exe";
    HeaderInfo hf (file);
    if (hf.analyze_file())
        hf.print_coff();
        //hf.print_info();
    else
        std::cerr << "\nWas unable to open file." << std::endl;

    return 0;
}