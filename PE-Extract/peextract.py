"""
PE-Extract

    This script is designed to pull information from a Windows PE-format executable and print the
    metadata it contains to console. Data printed out includes:
        DOS Header
        Optional Header
        Data Directory
        Section Information


    Usage: python3 peextract.py [executable]
        - The name of the executable file to be analyzed is the only parameter that can be entered,
          and it is required.

    Dependencies:
        datetime
        sys
        lief
    See requirements.txt for more information.

"""


import lief
from datetime import datetime
from sys import argv

if __name__ == "__main__":
    port_exe = lief.PE.parse(argv[1])

    # Stop execution if a bad file name was passed
    if (port_exe is None):
        print ("Bad argument! Please provide a file.")
        exit()

    print ("\nDOS Header")
    print ('=' * 64)
    # Target machine
    mchn = port_exe.header.machine
    print ("Machine: {m}".format(m = mchn))
    if (mchn == lief.PE.MACHINE_TYPES.I386):
        print ("\tArchitecture is 32-bit")
    else:
        print ("\tArchitecture is 64-bit")

    # Timedate header info
    td_stamp = port_exe.header.time_date_stamps # Stored as seconds since epoch
    td_stamp = datetime.fromtimestamp(td_stamp).strftime('%Y-%m-%d %H:%M:%S')
    print ("Time & Date Stamp: {tds}".format(tds = td_stamp))

    # Section quantity
    sec_quant = port_exe.header.numberof_sections
    print ("Number of Sections: {sec}".format(sec = sec_quant))

    # Characteristic flags
    chara_flags = port_exe.header.characteristics_list
    print ("Characterisitcs: {ch_quant}".format(ch_quant = len (chara_flags)))
    for c in chara_flags:
        print("\t" + str(c))
    print ('\n')

    # Optional header content
    opt_head = port_exe.optional_header
    print ("\nOptional Header Content")
    print ('=' * 64)
    print ("Magic                   : " + str(opt_head.magic))
    print ("Image Base              : " + str (opt_head.imagebase))
    print ("Section Alignment       : " + str (opt_head.section_alignment))
    print ("File Alignment          : " + str (opt_head.file_alignment))
    print ("Size of Image           : " + str (opt_head.sizeof_image))
    print ("DLL Characteristic Flags: " + str (hex(opt_head.dll_characteristics)) + '\n')

    # Data directory part of optional header
    dat_dir = port_exe.data_directories
    print ("\nData Directory ")
    print ('=' * 64)
    for d in dat_dir:
        print (str(d.type))
        print ("\tSize: " + str(int(d.size)))
        print ("\tVirt. Addr.: " + str(hex(d.rva)) + '\n')

    # Individual section header information
    sec_head = port_exe.sections
    print ("\nSection Information")
    print ('=' * 64)
    for s in sec_head:
        print (s.fullname)
        print ("\tVirt. Size : " + str(s.virtual_size))
        print ("\tVirt. Addr.: " + str(hex(s.virtual_address)))
        print ("\tSize of Raw: " + str(s.sizeof_raw_data))
        print ("\tSec Offset : " + str(s.offset))
        print ("\tCharacteris: " + str(hex(s.characteristics)) + '\n')
