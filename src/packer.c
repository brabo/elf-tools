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

//#define BUFFER_SIZE 256

/* Function: parse_opts
 * --------------------
 *  Parses arguments, puts them in piss structure.
 *
 *  argc:		Argument count.
 *  **argv:		Arguments.
 *  *piss:		Our piss.
 *
 *  Returns:		0 on success
 *
 *  Exits:		1 on invalid delay.
 *			4 on unknown argument.
 *			5 on missing input file.
 *			6 on missing output file.
 *			7 on missing decryptor file.
 */
int parse_opts(int argc, char **argv, unsigned char *inf, unsigned char *outf, unsigned char *decf)
{
	char c;

	// whole while loop in parse_args, send pointer to a struct to fill in (code reusability in future)
	while ((c = getopt (argc, argv, "i:o:d:")) != -1) {
		switch (c) {
		case 'i':
			strncpy(inf, optarg, 64);
			break;
		case 'o':
			strncpy(outf, optarg, 64);
			break;
		case 'd':
			strncpy(decf, optarg, 64);
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

	if (outf[0] == 0x00) {
		printf("Must have an output file (-o outfile)\n");
		exit(6);
	}

	if (decf[0] == 0x00) {
		printf("Must have a decryptor file (-d decfile)\n");
		exit(7);
	}

	//if (!outf) {
	//	printf("Must have an output file (-o outfile)\n");
	//	exit(6);
	//}


	return 0;
}

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
		printf("Fail to open decryptor file %s for reading.\n", textf);
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
 *			1 on missing server address.
 *			2 on log open error.
 *			3 on unknown argument.
 */
int main(int argc, char **argv)
{
	//unsigned char buffer[BUFFER_SIZE];
	//FILE *fp;
	char inf[64], outf[64], decf[64], dec[65536];
	char *p, *decfp = dec;
	int infp = 0, outfp = 0;
	inf[0] = outf[0] = decf[0] = 0x00;


	Elf *ine;
	Elf *oute;
	Elf64_Ehdr *inehdr, *outehdr;
	Elf64_Phdr *inphdr, *outphdr;

	Elf_Scn *inscn, *outscn;
	Elf_Data *indata, *outdata;
	GElf_Shdr *inshdr, *outshdr;
	size_t n, shstrndx, decsz, insz;

	if (parse_opts(argc, argv, inf, outf, decf)) {
		exit(1);
	}

	infp = open(inf, O_RDONLY, 0);
	if (infp == 0) {
		printf("Fail to open input file %s for reading.\n", inf);
		exit(2);
	}

	outfp = open(outf, O_WRONLY|O_CREAT, 0700);
	if (outfp == 0) {
		printf("Fail open output file %s for writing.\n", outf);
		exit(3);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
 		errx(EXIT_FAILURE, "ELF library initialization failed: %s", elf_errmsg(-1));
 	}

 	decsz = get_text(decf, dec) - 1;

	for (int k = 0; k < decsz; k++) {
		printf("%02X", (dec[k] & 0xFF));
	}
	printf("\n");
	printf("decsz: %08X\n", decsz);

	if ((ine = elf_begin(infp, ELF_C_READ, NULL)) < 0) {
		errx(EXIT_FAILURE, "elf_begin(ine) failed: %s.", elf_errmsg(-1));
	}

	if ((oute = elf_begin(outfp, ELF_C_WRITE, NULL)) < 0) {
		errx(EXIT_FAILURE, "elf_begin(oute) failed: %s.", elf_errmsg(-1));
	}

	if ((inehdr = elf64_getehdr(ine)) == NULL) {
		errx(EXIT_FAILURE, "elf64_getehdr(inehdr) failed: %s.", elf_errmsg(-1));
	}

	if ((outehdr = elf64_newehdr(oute)) == NULL) {
		errx(EXIT_FAILURE, "elf64_newehdr(outehdr) failed: %s.", elf_errmsg(-1));
	}

	memcpy(outehdr, inehdr, sizeof(*inehdr));

	printf("bits:       %i\n", outehdr->e_ident[4]);
	printf("type:       %i\n", outehdr->e_type);
	printf("machine:    %i\n", outehdr->e_machine);
	printf("version:    %i\n", outehdr->e_version);
	printf("ph offset:  %08X\n", outehdr->e_phoff);
	printf("ph num:     %08X\n", outehdr->e_phnum);
	printf("sh offset:  %08X\n", outehdr->e_shoff);
	printf("sh num:     %08X\n", outehdr->e_shnum);
	printf("sh strndx:  %08X\n", outehdr->e_shstrndx);



	if (elf_getshdrstrndx(ine, &shstrndx) != 0) {
		errx(EXIT_FAILURE, "elf_getshdrstrndx(ine) failed: %s.", elf_errmsg(-1));
	}

	int l = 0;
	inscn = NULL;
	while ((inscn = elf_nextscn(ine, inscn)) != NULL) {
		if ((inshdr = elf64_getshdr(inscn)) == NULL) {
			errx(EXIT_FAILURE, "elf64_getshdr(inscn) failed: %s.", elf_errmsg(-1));
		}

		if ((outscn = elf_newscn(oute)) == NULL) {
			errx(EXIT_FAILURE, "elf_newscn(oute) failed: %s.", elf_errmsg(-1));
		}

		if ((outdata = elf_newdata(outscn)) == NULL) {
			errx(EXIT_FAILURE, "elf_newdata(outscn) failed: %s.", elf_errmsg(-1));
		}

		indata = NULL;

		indata = elf_rawdata(inscn, indata);
		memcpy(outdata, indata, sizeof(*indata));

		printf("indata  #%d version:    %04X\n", l, indata->d_version);   // 4 byte
		printf("outdata #%d version:    %04X\n", l, outdata->d_version);   // 4 byte
		outdata->d_version = EV_CURRENT;

		if (( outshdr = elf64_getshdr(outscn)) == NULL) {
			errx(EXIT_FAILURE, "elf64_getshdr(outscn) failed: %s.", elf_errmsg(-1));
		}

		memcpy(outshdr, inshdr, sizeof(*inshdr));

		printf("section header type:  %04X\n", outshdr->sh_type);
		if (outshdr->sh_type == 1) {
			insz = inshdr->sh_size;
			p = (char *) outdata->d_buf;
			for (int k = decsz; k < (decsz + outshdr->sh_size); k++) {
				dec[k] = (*p & 0xFF) + 2;
				printf("%02X", (dec[k] & 0xFF));
				p++;
			}
			printf("\n");
			decsz += outshdr->sh_size;

			for (int k = 0; k < decsz; k++) {
				printf("%02X", (dec[k] & 0xFF));
			}
			printf("\n");
			printf("size: %08X\n", decsz);
			outdata->d_buf = malloc(decsz);
			p = (char *) outdata->d_buf;
			for (int k = 0; k < decsz; k++) {
				*p = dec[k];
				p++;
			}
			outshdr->sh_size = outdata->d_size = decsz;
		}


		if (elf_update(oute, ELF_C_NULL) < 0) {
			errx(EXIT_FAILURE, "elf_update(NULL) failed: %s.", elf_errmsg(-1));
		}
		l++;

	}

	if (elf_getphdrnum(ine, &n) < 0) {
		errx(EXIT_FAILURE, "elf_getphdrnum(ine) failed: %s.", elf_errmsg(-1));
	}


	if ((elf64_newphdr(oute, n)) == NULL) {
		errx(EXIT_FAILURE, "elf64_newphdr(oute) failed: %s.", elf_errmsg(-1));
	}


	if ((inphdr = elf64_getphdr(ine)) == NULL) {
		errx(EXIT_FAILURE, "elf64_getphdr(ine) failed: %s.", elf_errmsg(-1));
	}

	if ((outphdr = elf64_getphdr(oute)) == NULL) {
		errx(EXIT_FAILURE, "elf64_getphdr(oute) failed: %s.", elf_errmsg(-1));
	}

	for (int i = 0; i < n; i++) {
		memcpy(outphdr, inphdr, sizeof(*inphdr));
		if (outphdr->p_type == 1 ) {
			outphdr->p_flags = 7;
			outphdr->p_filesz = decsz;
			outphdr->p_memsz = decsz;
		}

		printf("PH #%d type:    %08X\n", i, outphdr->p_type);   // 4 byte
		printf("PH #%d flags:   %08X\n", i, outphdr->p_flags);  // 4 byte
		printf("PH #%d offset:  %08X\n", i, outphdr->p_offset); // 8 byte
		printf("PH #%d vaddr:   %08X\n", i, outphdr->p_vaddr);  // 8 byte
		printf("PH #%d paddr:   %08X\n", i, outphdr->p_paddr);  // 8 byte
		printf("PH #%d fsize:   %08X\n", i, outphdr->p_filesz); // 8 byte
		printf("PH #%d memsize: %08X\n", i, outphdr->p_memsz);  // 8 byte
		printf("PH #%d align:   %08X\n", i, outphdr->p_align);  // 8 byte

		if (elf_update(oute, ELF_C_NULL) < 0) {
			errx(EXIT_FAILURE, "elf_update(NULL) failed: %s.", elf_errmsg(-1));
		}

		inphdr++;
		outphdr++;
	}


	if (elf_update(oute, ELF_C_NULL) < 0) {
		errx(EXIT_FAILURE, "elf_update(NULL) failed: %s.", elf_errmsg(-1));
	}

	if (elf_update(oute, ELF_C_WRITE) < 0) {
		errx(EXIT_FAILURE, "elf_update(WRITE) failed: %s.", elf_errmsg(-1));
	}

	elf_end(ine);
	elf_end(oute);
	lseek(outfp, 0xe7, SEEK_SET);
	write(outfp, &insz, 8);
	/* close the file */
	close(infp);
	close(outfp);

	//FILE *fp;
	//fp = fopen(outf, "w");
	//if (fp == NULL) {
	//	printf("Fail open %s for writing.\n", outf);
	//	exit(8);
	//}
	//fseek(fp, 0xe6, SEEK_SET);
	//fwrite(&insz, 1, sizeof(uint8_t), fp);
	//fclose(fp);

	return 0;

}
