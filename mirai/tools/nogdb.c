#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/procfs.h>
#include <fcntl.h>

int main(int argc, char** argv) {
    int f;
    static Elf32_Ehdr* header;

    printf(".: Elf corrupt :.\n");

    if(argc < 2){
        printf("Usage: %s file", argv[0]);
        return 1;
    }

    if((f = open(argv[1], O_RDWR)) < 0){
        perror("open");
        return 1;
    }

    //MAP_SHARED is required to actually update the file
    if((header = (Elf32_Ehdr *) mmap(NULL, sizeof(header), PROT_READ | PROT_WRITE, MAP_SHARED, f, 0)) == MAP_FAILED){
        perror("mmap");
        close(f);
        return 1;
    }

    printf("[*] Current header values:\n");
    printf("\te_shoff:%d\n\te_shnum:%d\n\te_shstrndx:%d\n",
            header->e_shoff, header->e_shnum, header->e_shstrndx);

    header->e_shoff = 0xffff;
    header->e_shnum = 0xffff;
    header->e_shstrndx = 0xffff;

    printf("[*] Patched header values:\n");
    printf("\te_shoff:%d\n\te_shnum:%d\n\te_shstrndx:%d\n",
            header->e_shoff, header->e_shnum, header->e_shstrndx);

    if(msync(NULL, 0, MS_SYNC) == -1){
        perror("msync");
        close(f);
        return 1;
    }

    close(f);
    munmap(header, 0);
    printf("You should no more be able to run \"%s\" inside GDB\n", argv[1]);
    return 0;
}