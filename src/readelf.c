/*
 * readelf - read and parse ELF files, output some info to stdout
 * Copyright (C) 2015 brabo <brabo.sil@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <gelf.h>
//#include <libelf.h>

/* Function: parse_opts
 * --------------------
 *  Parses arguments, returns input file.
 *
 *  argc:		Argument count.
 *  **argv:		Arguments.
 *  *inf:		Our input file.
 *
 *  Returns:		0 on success
 *
 *  Exits:		4 on unknown argument.
 */
int parse_opts(int argc, char **argv, unsigned char *inf)
{
	char c;

	while ((c = getopt (argc, argv, "i:")) != -1) {
		switch (c) {
		case 'i':
			strncpy(inf, optarg, 64);
			break;
		case '?':
			fprintf(stderr, "Unknown argument: %c\n", optopt);
			exit(4);
		default:
			abort();
		}
	}

	return 0;
}

/* Function: main
 * --------------
 *  Main function. Parses arguments. Extracts and shows ELF headers/sections.
 *
 *  argc:		Argument count.
 *  **argv:		Arguments.
 *
 *  Returns:		0 on success.
 *			1 on parse opts error.
 *			2 on input file open error.
 */
int main(int argc, char **argv)
{
	char inf[64];
	int infp;

	Elf *e;
	char *k;
	Elf_Kind ek;
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;

	Elf_Scn *scn;
	char *name, *p;
	Elf_Data *data;
	GElf_Shdr shdr;
	size_t n, shstrndx;



	if (parse_opts(argc, argv, inf)) {
		exit(1);
	}


	infp = open(inf, O_RDONLY, 0);
	if (infp < 0) {
		printf("Fail to open %s for reading.\n", inf);
		exit(2);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
 		errx(EXIT_FAILURE, "ELF library initialization failed: %s", elf_errmsg(-1));
 	}

	if ((e = elf_begin(infp, ELF_C_READ, NULL)) < 0) {
		errx(EXIT_FAILURE, "elf_begin() failed: %s.", elf_errmsg(-1));
	}

 	ek = elf_kind(e);

	switch (ek) {
	case ELF_K_AR:
		k = "ar(1) archive";
		break;
	case ELF_K_ELF:
		k = "elf object";
		break;
	case ELF_K_NONE:
		k = "data";
		break;
	default:
		k = "unrecognized";
	}

	printf("%s: %s\n", inf, k);


	if (gelf_getehdr(e, &ehdr) < 0) {
		errx(EXIT_FAILURE, "getehdr() failed: %s.", elf_errmsg(-1));
	}

	printf("bits:       %i\n", ehdr.e_ident[4]);
	printf("type:       %i\n", ehdr.e_type);
	printf("machine:    %i\n", ehdr.e_machine);
	printf("version:    %i\n", ehdr.e_version);
	printf("ph offset:  %08X\n", ehdr.e_phoff);
	printf("ph num:     %08X\n", ehdr.e_phnum);
	printf("sh offset:  %08X\n", ehdr.e_shoff);
	printf("sh num:     %08X\n", ehdr.e_shnum);
	printf("sh strndx:  %08X\n", ehdr.e_shstrndx);

	if (elf_getphdrnum(e, &n) < 0) {
		errx(EXIT_FAILURE, "getphdrnum() failed: %s.", elf_errmsg(-1));
	}

	for (int i = 0; i < n; i++) {
		if (gelf_getphdr(e, i, &phdr) != &phdr) {
			errx(EXIT_FAILURE, "getphdr() failed: %s.", elf_errmsg(-1));
		}
		// size per ph = 0x38
		printf("PH #%d type:    %08X\n", i, phdr.p_type);   // 4 byte
		printf("PH #%d flags:   %08X\n", i, phdr.p_flags);  // 4 byte
		printf("PH #%d offset:  %08X\n", i, phdr.p_offset); // 8 byte
		printf("PH #%d vaddr:   %08X\n", i, phdr.p_vaddr);  // 8 byte
		printf("PH #%d paddr:   %08X\n", i, phdr.p_paddr);  // 8 byte
		printf("PH #%d fsize:   %08X\n", i, phdr.p_filesz); // 8 byte
		printf("PH #%d memsize: %08X\n", i, phdr.p_memsz);  // 8 byte
		printf("PH #%d align:   %08X\n", i, phdr.p_align);  // 8 byte

	}


	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));
	}

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			errx(EXIT_FAILURE, "getshdr() failed: %s.", elf_errmsg(-1));
		}

		if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL) {
			errx(EXIT_FAILURE, "elf_strptr() failed: %s.", elf_errmsg(-1));
		}


		printf("Section %-4.4jd %s\n", (uintmax_t)elf_ndxscn(scn), name);
		printf("  type:       %08X\n", shdr.sh_type);
		printf("  flags:      %08X\n", shdr.sh_flags);
		printf("  addres:     %08X\n", shdr.sh_addr);
		printf("  offset:     %04X\n", shdr.sh_offset);
		printf("  size:       %04X\n", shdr.sh_size);
		printf("  link:       %04X\n", shdr.sh_link);
		printf("  info:       %04X\n", shdr.sh_info);
		printf("  addralign:  %04X\n", shdr.sh_addralign);
		printf("  entsize:    %04X\n", shdr.sh_entsize);
	}

	if ((scn = elf_getscn(e, shstrndx)) == NULL) {
		errx(EXIT_FAILURE, "getscn() failed: %s.", elf_errmsg(-1));
	}

	if (gelf_getshdr(scn, &shdr) != &shdr) {
		errx(EXIT_FAILURE, "getshdr(shstrndx) failed: %s.", elf_errmsg(-1));
	}

	printf(".shstrab: size=%jd\n", (uintmax_t)shdr.sh_size);

	data = NULL;
	n = 0;
	while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
		p = (char *) data->d_buf;
		while (p < (char *) data->d_buf + data->d_size) {
			//if (vis(pc, *p, VIS_WHITE, 0)) {
				printf("%c", *p);
			//}
			n++;
			p++;
			//if ((n % 16) == 0) {
			//	printf("\n");
			//}/
			//putchar((n % 16) ? ' ' : '\n');
			//printf("\n");
		}
		printf("\n");
	}





	elf_end(e);
	close(infp);

	exit(EXIT_SUCCESS);
}
