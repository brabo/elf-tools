Small collection of ELF related tools.

readelf - reads and parses ELF files
	- clearly is a pile of shit atm..

get_sc	- extracts shellcode from a binaries .text section
	- is less crap, but still..

packer	- demo ELF packer, copies ELF while encoding .text and prepending shellcode
	  to decode before execution
