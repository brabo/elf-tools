/*
 * get_sc - extract shellcode from a binaries .text section and output it to stdout
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
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <err.h>
#include <gelf.h>
#include <libelf.h>

/* Function: parse_opts
 * --------------------
 *  Parses arguments, returns input file.
 *
 *  argc:		Argument count.
 *  **argv:		Arguments.
 *  *inf:		Our input file.
 *
 *  Returns:		0 on success.
 *
 *  Exits:		4 on unknown argument.
 *			5 on missing input file.
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

	if (inf[0] == 0x00) {
		printf("Must have an input file (-i infile)\n");
		exit(5);
	}

	return 0;
}

/* Function: get_text
 * ------------------
 *  get_text function. Extract and return an ELF files .text section.
 *
 *  *textf:		ELF file.
 *  *text:		.text to return.
 *
 *  Returns:		.text size on success.
 *			Should probably return some sub 1 value in case of errors...
 *  Exits:		2 on failure to open input file.
 */
int get_text(char *textf, char *text)
{
	Elf *texte;
	Elf_Scn *textscn;
	Elf_Data *textdata;
	GElf_Shdr textshdr;
	char *p;
	size_t textsz, n, shstrndx;
	int textfp = 0;

	textfp = open(textf, O_RDONLY);
	if (textfp == 0) {
		printf("Fail to open input file %s for reading.\n", textf);
		exit(2);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
 		errx(EXIT_FAILURE, "ELF library initialization failed: %s", elf_errmsg(-1));
 	}

	if ((texte = elf_begin(textfp, ELF_C_READ, NULL)) < 0) {
		errx(EXIT_FAILURE, "elf_begin(get_text) failed: %s.", elf_errmsg(-1));
	}


	if (elf_getshdrstrndx(texte, &shstrndx) != 0) {
		errx(EXIT_FAILURE, "elf_getshdrstrndx(get_text) failed: %s.", elf_errmsg(-1));
	}

	textscn = NULL;
	while ((textscn = elf_nextscn(texte, textscn)) != NULL) {
		if (gelf_getshdr(textscn, &textshdr) != &textshdr) {
			errx(EXIT_FAILURE, "gelf_getshdr(get_text) failed: %s.", elf_errmsg(-1));
		}

		if (textshdr.sh_type == 1) {
			printf("found .text section..\n");

			textdata = NULL;
			n = 0;
			while (n < textshdr.sh_size && (textdata = elf_getdata(textscn, textdata)) != NULL) {
				p = (char *) textdata->d_buf;
				while (p < (char *) textdata->d_buf + textdata->d_size) {
					//printf("%02X", (*p & 0xFF));
					text[n]= (*p & 0xFF);
					n++;
					p++;
				}
				//printf("\n");
			}

			textsz = n;

		}
	}
	elf_end(texte);
	close(textfp);
	return textsz;

}

/* Function: main
 * --------------
 *  Main function. Parses arguments.
 *
 *  argc:		Argument count.
 *  **argv:		Arguments.
 *
 *  Returns:		0 on success.
 *			1 on missing input file.
 */
int main(int argc, char **argv)
{
	char inf[64];
	inf[0] = 0x00;
	unsigned char sc[512];

	size_t sc_sz;

	if (parse_opts(argc, argv, inf)) {
		exit(1);
	}

 	sc_sz = get_text(inf, sc);

	printf("shellcode size: %08X\n", sc_sz);
	for (int k = 0; k < sc_sz; k++) {
		printf("\\x%02X", (sc[k] & 0xFF));
	}
	printf("\n");

	return 0;
}
