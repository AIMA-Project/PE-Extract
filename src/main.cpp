/**
 * @author Drew Wheeler
 * @date 2023-02-26
 * 
 */

#include "HeaderExtract.hpp"

int main (int argc, char** argv)
{
    HeaderInfo hf ("TestFiles/rufus.exe");
    hf.analyze_file();
    hf.print_info();

    return 0;
}