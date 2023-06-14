import sys
import struct

'''Program se koristi putem komandne linije, uz ime programa navodi se i ime datoteke (s ekstenzijom) kao parametar.
Sve strukture formirane su uz pomoc klasa. '''

exe = open(sys.argv[1], "rb")
##file = exe.read()
##print file


def offset(RVA, SectionRVA, PointerToRawData):
    return RVA - SectionRVA + PointerToRawData

def LEtoBEtohex(*args):
    a = list(args)
    a = [s[::-1] for s in a]
    a = [s.encode('hex') for s in a]
    a = [int(i, 16) for i in a]
    args = a
    return args


class MS_DOS_HEADER():
    def __init__(self, e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc,
                 e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno,
                 e_res, e_oemid, e_oeminfo, e_res2, e_lfanew):
        self.e_magic = e_magic
        self.e_cblp = e_cblp
        self.e_cp = e_cp
        self.e_crlc = e_crlc
        self.e_cparhdr = e_cparhdr
        self.e_minalloc = e_minalloc
        self.e_maxalloc = e_maxalloc
        self.e_ss = e_ss
        self.e_sp = e_sp
        self.e_csum = e_csum
        self.e_ip = e_ip
        self.e_cs = e_cs
        self.e_lfarlc = e_lfarlc
        self.e_ovno = e_ovno
        self.e_res = e_res
        self.e_oemid = e_oemid
        self.e_oeminfo = e_oeminfo
        self.e_res2 = e_res2
        self.e_lfanew = e_lfanew
        return

##exe.seek(0)
##
##MS = exe.read(0x40)
##print MS

exe.seek(0)
e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp,\
e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, e_oeminfo, e_res2,\
e_lfanew = exe.read(2), exe.read(2), exe.read(2), exe.read(2), exe.read(2),\
exe.read(2), exe.read(2), exe.read(2), exe.read(2), exe.read(2), exe.read(2),\
exe.read(2), exe.read(2), exe.read(2), exe.read(8), exe.read(2), exe.read(2),\
exe.read(20), exe.read(4)

##e_lfanew = struct.unpack('>{}f

##a = [e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp,\
##e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, e_oeminfo, e_res2,\
##e_lfanew]
##a = [s[::-1] for s in a]
##a = [s.encode('hex') for s in a]
##
##a = [int(i, 16) for i in a]
##[e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp,\
##e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, e_oeminfo, e_res2,\
##e_lfanew] = a

[e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp,\
e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, e_oeminfo, e_res2,\
e_lfanew] = LEtoBEtohex(e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, \
e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, \
e_oeminfo, e_res2, e_lfanew)

MS_DOS = MS_DOS_HEADER(e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc,
                  e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc,
                  e_ovno, e_res, e_oemid, e_oeminfo, e_res2, e_lfanew)
print('''MZ Header
=========
    Magic:                      {:#x} --> "MZ"
    Bytes on Last Page of File: 0x{:04x}
    PagesInFile:                0x{:04x}
    Relocations:                0x{:04x}
    SizeOfHeaderInParagraphs:   0x{:04x}
    Minimum Extra Paragraphs:   0x{:04x}
    Maximum Extra Paragraphs:   0x{:04x}
    Initial (relative) SS:      0x{:04x}
    Initial SP value:           0x{:04x}
    Checksum:                   0x{:04x}
    Initial IP value:           0x{:04x}
    Initial (relative) CS:      0x{:04x}
    Offset to relocation table: 0x{:04x}
    Overlay number:             0x{:04x}
    Reserved words:             0x{:016x}
    OEM identifier:             0x{:04x}
    OEM information:            0x{:04x}
    Reserved words (2):         0x{:040x}
    Offset to PEHeader:         0x{:08x}\n'''.format(MS_DOS.e_magic, MS_DOS.e_cblp, \
    MS_DOS.e_cp, MS_DOS.e_crlc, MS_DOS.e_cparhdr, MS_DOS.e_minalloc, MS_DOS.e_maxalloc, \
    MS_DOS.e_ss, MS_DOS.e_sp, MS_DOS.e_csum, MS_DOS.e_ip, MS_DOS.e_cs, MS_DOS.e_lfarlc, \
    MS_DOS.e_ovno, MS_DOS.e_res, MS_DOS.e_oemid, MS_DOS.e_oeminfo, MS_DOS.e_res2, MS_DOS.e_lfanew))

class _IMAGE_NT_HEADERS():
    signature = "PE\0\0"
    def __init__(self, FileHeader, OptionalHeader):
        self.FileHeader = FileHeader
        self.OptionalHeader = OptionalHeader

class PE_HEADER():
    def __init__(self, Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
                 NumberOfSymbols,SizeOfOptionalHeader, Characteristics):
        self.Machine = Machine                              #procesor: 0x14c za i386, 0x8664 za AMD64
        self.NumberOfSections = NumberOfSections            #broj sekcija
        self.TimeDateStamp = TimeDateStamp                  #timestamp pri prevodenju
        self.PointerToSymbolTable = PointerToSymbolTable    
        self.NumberOfSymbols = NumberOfSymbols
        self.SizeOfOptionalHeader = SizeOfOptionalHeader    #velicina Optional Headera ([Section Table] -
### - [Optional Header], stvarna velicina korisnih informacija moze biti i manja
        self.Characteristics = Characteristics              #karakteristike, .exe, .dll ili sto vec
        return

exe.seek(MS_DOS.e_lfanew)

signature, Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, \
NumberOfSymbols, SizeOfOptionalHeader, Characteristics = exe.read(4), \
exe.read(2), exe.read(2), exe.read(4), exe.read(4), exe.read(4), exe.read(2),\
exe.read(2)

if (signature != _IMAGE_NT_HEADERS.signature):
    print("File is not in PE format")
    
[signature, Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, \
NumberOfSymbols, SizeOfOptionalHeader, Characteristics] = LEtoBEtohex(signature, \
Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, \
NumberOfSymbols, SizeOfOptionalHeader, Characteristics)

PE = PE_HEADER(Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, \
NumberOfSymbols, SizeOfOptionalHeader, Characteristics)

print('''PE Header
=========
    Signature:                  0x{:08x} --> "PE" (phys: 0x{:08x})
    Machine:                    0x{:04x}
    NumberOfSections:           0x{:04x}
    TimeDateStamp:              0x{:08x}
    PointerToSymbolTable:       0x{:08x}
    NumberOfSymbols:            0x{:08x}
    SizeOfOptionalHeader:       0x{:04x}
    Characteristics:            0x{:04x}\n'''.format(signature, MS_DOS.e_lfanew, \
    PE.Machine, PE.NumberOfSections, PE.TimeDateStamp, PE.PointerToSymbolTable, \
    PE.NumberOfSymbols, PE.SizeOfOptionalHeader, PE.Characteristics))

class OPTIONAL_HEADER():
    def __init__(self, Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, 
                 SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, 
                 BaseOfCode, BaseOfData, ImageBase, SectionAlignment, FileAlignment,
                 MajorOperatingSystemVersion, MinorOperatingSystemVersion,
                 MajorImageVersion, MinorImageVersion, MajorSubsystemVersion,
                 MinorSubsystemVersion, Win32VersionValue, SizeOfImage, SizeOfHeaders,
                 CheckSum, Subsystem, DllCharacteristics, SizeOfStackReserve,
                 SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags,
                 NumberOfRvaAndSizes, DataDirectory):
        self.Magic = Magic                              #0x010b za x86, 0x020b za x64
        self.MajorLinkerVersion = MajorLinkerVersion    #verzija linkera
        self.MinorLinkerVersion = MinorLinkerVersion    #verzija linkera
        self.SizeOfCode = SizeOfCode
        self.SizeOfInitializedData = SizeOfInitializedData
        self.SizeOfUninitializedData = SizeOfUninitializedData
        self.AddressOfEntryPoint = AddressOfEntryPoint
        self.BaseOfCode = BaseOfCode
        self.BaseOfData = BaseOfData
        self.ImageBase = ImageBase                      #adresa mapiranja u memoriju
        self.SectionAlignment = SectionAlignment        #poravnanje sekcija u M
        self.FileAlignment = FileAlignment              #poravnanje sekcija u datoteci (fizicki)
        self.MajorOperatingSystemVersion = MajorOperatingSystemVersion
        self.MinorOperatingSystemVersion = MinorOperatingSystemVersion
        self.MajorImageVersion = MajorImageVersion
        self.MinorImageVersion = MinorImageVersion
        self.MajorSubsystemVersion = MajorSubsystemVersion #generacija Win jezgre
        self.MinorSubsystemVersion = MinorSubsystemVersion
        self.Win32VersionValue = Win32VersionValue
        self.SizeOfImage = SizeOfImage
        self.SizeOfHeaders = SizeOfHeaders              #ukupna velicina headera (svih)
        self.CheckSum = CheckSum                        #kontrolna suma
        self.Subsystem = Subsystem                      #Driver, WinGUI ili WinCUI
        self.DllCharacteristics = DllCharacteristics
        self.SizeOfStackReserve = SizeOfStackReserve
        self.SizeOfStackCommit = SizeOfStackCommit
        self.SizeOfHeapReserve = SizeOfHeapReserve
        self.SizeOfHeapCommit = SizeOfHeapCommit
        self.LoaderFlags = LoaderFlags
        self.NumberOfRvaAndSizes = NumberOfRvaAndSizes  #broj zapisa u DataDirectory
        self.DataDirectory = DataDirectory
        return

OptionalOffset = exe.tell()

Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData, \
SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase, \
SectionAlignment, FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion, \
MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, \
Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, \
SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, \
NumberOfRvaAndSizes = exe.read(2), exe.read(1), exe.read(1), exe.read(4), \
exe.read(4), exe.read(4), exe.read(4), exe.read(4), exe.read(4), exe.read(4), \
exe.read(4), exe.read(4), exe.read(2), exe.read(2), exe.read(2), exe.read(2), \
exe.read(2), exe.read(2), exe.read(4), exe.read(4), exe.read(4), exe.read(4), \
exe.read(2), exe.read(2), exe.read(4), exe.read(4), exe.read(4), exe.read(4), \
exe.read(4), exe.read(4)

[Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData, \
SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase, \
SectionAlignment, FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion, \
MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, \
Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, \
SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, \
NumberOfRvaAndSizes] = LEtoBEtohex(Magic, MajorLinkerVersion, MinorLinkerVersion, \
SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, \
BaseOfData, ImageBase, SectionAlignment, FileAlignment, MajorOperatingSystemVersion, \
MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, \
MinorSubsystemVersion, Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, \
DllCharacteristics, SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, \
LoaderFlags, NumberOfRvaAndSizes)

if(Magic == 0x020b):
    print("Datoteka je 64-bitna")
    exit()

class _IMAGE_DATA_DIRECTORY ():
    def __init__(self, VirtualAddress, Size):
        self.VirtualAddress = VirtualAddress            #virtualna adresa pocetka
        self.Size = Size                                #velicina
        return

DataDirectory = []
for i in range(16):
    VirtualAddress, Size = exe.read(4), exe.read(4)
    [VirtualAddress, Size] = LEtoBEtohex(VirtualAddress, Size)
    DataDirectory.append(_IMAGE_DATA_DIRECTORY(VirtualAddress, Size))

    
Optional = OPTIONAL_HEADER(Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, 
                 SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, 
                 BaseOfCode, BaseOfData, ImageBase, SectionAlignment, FileAlignment,
                 MajorOperatingSystemVersion, MinorOperatingSystemVersion,
                 MajorImageVersion, MinorImageVersion, MajorSubsystemVersion,
                 MinorSubsystemVersion, Win32VersionValue, SizeOfImage, SizeOfHeaders,
                 CheckSum, Subsystem, DllCharacteristics, SizeOfStackReserve,
                 SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags,
                 NumberOfRvaAndSizes, DataDirectory)

print('''Optional Header
============
    Magic:                      0x{:04x} (phys: {:08x})
    MajorLinkerVersion:         0x{:02x}
    MinorLinkerVersion:         0x{:02x}
    SizeOfCode:                 0x{:08x}
    SizeOfInitializedData:      0x{:08x}
    SizeOfUninitializedData:    0x{:08x}
    AddressOfEntryPoint:        0x{:08x}
    BaseOfCode:                 0x{:08x}
    BaseOfData:                 0x{:08x}
    ImageBase:                  0x{:08x}
    SectionAlignment:           0x{:08x}
    FileAlignment:              0x{:08x}
    MajorOperatingSystemVer:    0x{:08x}
    MinorOperatingSystemVer:    0x{:08x}
    MajorImageVersion:          0x{:04x}
    MinorImageVersion:          0x{:04x}
    MajorSubsystemVersion:      0x{:04x}
    MinorSubsystemVersion:      0x{:04x}
    Win32VersionValue:          0x{:08x}
    SizeOfImage:                0x{:08x}
    SizeOfHeaders:              0x{:08x}
    CheckSum:                   0x{:08x}
    Subsystem:                  0x{:04x}
    DllCharacteristics:         0x{:04x}
    SizeOfStackReserve:         0x{:08x}
    SizeOfStackCommit:          0x{:08x}
    SizeOfHeapReserve:          0x{:08x}
    SizeOfHeapCommit:           0x{:08x}
    LoaderFlags:                0x{:08x}
    NumberOfRvaAndSizes:        0x{:08x}\n'''.format(Optional.Magic, OptionalOffset, Optional.MajorLinkerVersion, Optional.MinorLinkerVersion, Optional.SizeOfCode,
                 Optional.SizeOfInitializedData, Optional.SizeOfUninitializedData, Optional.AddressOfEntryPoint,
                 Optional.BaseOfCode, Optional.BaseOfData, Optional.ImageBase, Optional.SectionAlignment, Optional.FileAlignment,
                 Optional.MajorOperatingSystemVersion, Optional.MinorOperatingSystemVersion,
                 Optional.MajorImageVersion, Optional.MinorImageVersion, Optional.MajorSubsystemVersion,
                 Optional.MinorSubsystemVersion, Optional.Win32VersionValue, Optional.SizeOfImage, Optional.SizeOfHeaders,
                 Optional.CheckSum, Optional.Subsystem, Optional.DllCharacteristics, Optional.SizeOfStackReserve,
                 Optional.SizeOfStackCommit, Optional.SizeOfHeapReserve, Optional.SizeOfHeapCommit, Optional.LoaderFlags,
                 Optional.NumberOfRvaAndSizes))

exe.seek(PE.SizeOfOptionalHeader + OptionalOffset)

class _IMAGE_SECTION_HEADER():
    def __init__(self, Name, VirtualSize, VirtualAddress, SizeOfRawData, PtrToRawData,
                 PtrToRelocations, PtrToLineNumbers, NumberOfRelocations,
                 NumberOfLinenumbers, Characteristics):
        self.Name = Name                                    #Ime sekcije
        self.VirtualSize = VirtualSize                      #Velicina sekcije u memoriji
        self.VirtualAddress = VirtualAddress                #RVA sekcije
        self.SizeOfRawData = SizeOfRawData                  #Velicina fizickih podataka
        self.PtrToRawData = PtrToRawData                    #pokazivac na prvu od sekcija
        self.PtrToRelocations = PtrToRelocations        
        self.PtrToLinenumbers = PtrToLinenumbers
        self.NumberOfRelocations = NumberOfRelocations
        self.NumberOfLinenumbers = NumberOfLinenumbers
        self.Characteristics = Characteristics              #karakteristike sekcije (EXECUTABLE, READ, WRITE...)
        return

Sections = []

for i in range(PE.NumberOfSections):
    Name, VirtualSize, VirtualAddress, SizeOfRawData, PtrToRawData, \
    PtrToRelocations, PtrToLinenumbers, NumberOfRelocations, \
    NumberOfLinenumbers, Characteristics = exe.read(8), exe.read(4), \
    exe.read(4), exe.read(4), exe.read(4), exe.read(4), exe.read(4), \
    exe.read(2), exe.read(2), exe.read(4)

    [VirtualSize, VirtualAddress, SizeOfRawData, PtrToRawData, \
    PtrToRelocations, PtrToLinenumbers, NumberOfRelocations, \
    NumberOfLinenumbers, Characteristics] = LEtoBEtohex(VirtualSize, VirtualAddress, SizeOfRawData, PtrToRawData, \
    PtrToRelocations, PtrToLinenumbers, NumberOfRelocations, \
    NumberOfLinenumbers, Characteristics)
    
    Sections.append(_IMAGE_SECTION_HEADER(Name, VirtualSize, VirtualAddress, SizeOfRawData, PtrToRawData, \
    PtrToRelocations, PtrToLinenumbers, NumberOfRelocations, \
    NumberOfLinenumbers, Characteristics))
print('''Section Headers
============\n''')
for section in Sections:
    print('''    Name:                       {}
    VirtualSize:                0x{:08x}
    VirtualAddress:             0x{:08x}
    SizeOfRawData:              0x{:08x}
    PointerToRawData:           0x{:08x}
    PointerToRelocations:       0x{:08x}
    PointerToLineNumbers:       0x{:08x}
    NumberOfRelocations:        0x{:04x}
    NumberOfLinenumbers:        0x{:04x}
    Characteristics:            0x{:08x}\n'''.format(section.Name, section.VirtualSize, section.VirtualAddress, section.SizeOfRawData, \
    section.PtrToRawData, section.PtrToRelocations, section.PtrToLinenumbers, \
    section.NumberOfRelocations, section.NumberOfLinenumbers, section.Characteristics))

#import
ImportRVA = DataDirectory[1].VirtualAddress

for i in range(PE.NumberOfSections):
    if ((i+1)*Optional.SectionAlignment <= DataDirectory[1].VirtualAddress):
        SectionRVA = Sections[i].VirtualAddress
        PtrToRawData = Sections[i].PtrToRawData
    else:
        break

ImportOffset = offset(ImportRVA, SectionRVA, PtrToRawData)

class _IMAGE_IMPORT_DESCRIPTOR():
    def __init__(self, OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk):
        self.OriginalFirstThunk = OriginalFirstThunk    #RVA to original IAT
        self.TimeDateStamp = TimeDateStamp
        self.ForwarderChain = ForwarderChain
        self.Name = Name
        self.FirstThunk = FirstThunk                    #RVA to IAT
        return

exe.seek(ImportOffset)

ImportDirectory = []
while(True):
    if (exe.read(20) == '\0'*20):
        break
    exe.seek(exe.tell()-20)
    OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk = exe.read(4), \
    exe.read(4), exe.read(4), exe.read(4), exe.read(4)

    [OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk] = \
    LEtoBEtohex(OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk)

    ImportDirectory.append(_IMAGE_IMPORT_DESCRIPTOR(OriginalFirstThunk, TimeDateStamp, \
        ForwarderChain, Name, FirstThunk))

class _IMAGE_IMPORT_BY_NAME():
    def __init__(self, Hint, Name):
        self.Hint = Hint
        self.Name = Name

print('''Import Table
=========''')

for Lib in ImportDirectory:
    exe.seek(offset(Lib.Name, SectionRVA, PtrToRawData))
    LibraryName = ''
    data = exe.read(1)
    while data != "\x00":
        LibraryName += str(struct.unpack("c", data)[0])
        data = exe.read(1)
    
    print('''    ImportDirectory
    ===========
        OriginalFirstThunk:     0x{:08x} (phys: 0x{:08x})
        TimeDateStamp:          0x{:08x} (phys: 0x{:08x})
        ForwarderChain:         0x{:08x} (phys: 0x{:08x})
        LibraryName:            0x{:08x} (phys: 0x{:08x}) --> {}
        FirstThunk:             0x{:08x} (phys: 0x{:08x})\n'''.format(Lib.OriginalFirstThunk, ImportOffset, \
            Lib.TimeDateStamp, ImportOffset + 4, Lib.ForwarderChain, ImportOffset + 8, \
            Lib.Name, ImportOffset + 12, LibraryName, Lib.FirstThunk, ImportOffset + 16)) 
    
    IAT = Lib.OriginalFirstThunk
    if (Lib.OriginalFirstThunk == '\0'*4):
        IAT = Lib.FirstThunk
   # print(hex(IAT))
    ThunkRVAs = []
    exe.seek(offset(IAT, SectionRVA, PtrToRawData))
    while(True):
        if (exe.read(4) == '\0'*4):
            break
        exe.seek(exe.tell()-4)
        ThunkRVA = LEtoBEtohex (exe.read(4))[0]
        ThunkRVAs.append(ThunkRVA)
    print('''        ImportThunks
        ==========''')
    for ThunkRVA in ThunkRVAs:
        ThunkOffset = offset(ThunkRVA, SectionRVA, PtrToRawData)
        exe.seek(ThunkOffset)
        Thunk = exe.read(8)
        if (Thunk[0] == 1):
            ordinal = Thunk[1:]
        else:
            hint = Thunk[:2]
            hint = hint[::-1]
            exe.seek(exe.tell() - 6)
            FuncName = ''
            data = exe.read(1)
            while data != "\x00":
                FuncName += str(struct.unpack("c", data)[0])
                data = exe.read(1)
            print('''            Api: 0x{:08x} (phys: 0x{:08x}) --> Hint: 0x{}, Name: {}\n'''.format(ThunkRVA, ThunkOffset, hint.encode('hex'), FuncName))

#Export
ExportRVA = DataDirectory[0].VirtualAddress
if (ExportRVA != '\0'*8):
    print ("Export Table")

    class _IMAGE_EXPORT_DIRECTORY():
        def __init__(self, Characteristics, TimeDateStamp, MajorVersion, MinorVersion, Name, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals):
        
            self.Characteristics = Characteristics
            self.TimeDateStamp = TimeDateStamp
            self.MajorVersion = MajorVersion
            self.MinorVersion = MinorVersion
            self.Name = Name
            self.Base = Base
            self.NumberOfFunctions = NumberOfFunctions
            self.NumberOfNames = NumberOfNames
            self.AddressOfFunctions = AddressOfFunctions
            self.AddressOfNames = AddressOfNames
            self.AddressOfNameOrdinals = AddressOfNameOrdinals
        




