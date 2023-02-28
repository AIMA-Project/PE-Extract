import lief
from datetime import datetime

if __name__ == "__main__":
    port_exe = lief.PE.parse("TestExe/Client.exe")

    # Target machine
    mchn = port_exe.header.machine
    print ("Machine: {m}".format(m = mchn))
    if (mchn == lief.PE.MACHINE_TYPES.I386):
        print ("\tArchitecture is 32-bit")
    else:
        print ("\tArchitecture is 64-bit")

    print

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
