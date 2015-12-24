/*
 * Copyright (c) 2015, Ryan O'Neill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "private.h"

static unsigned long int r_next = 1;

int _rand(void) // RAND_MAX assumed to be 32767
{
	r_next = r_next * 1103515245 + 12345;
	return (unsigned int)(r_next / 65536) & 32767;
}

void _srand(unsigned int seed)
{
	r_next = seed;
}

void Memset(void *mem, unsigned char byte, unsigned int len)
{
        unsigned char *p = (unsigned char *)mem; 
        int i = len;
        while (i--) {
                *p = byte;
                p++;
        }
}


char * _fgets(char *s, size_t size, int fd, long *offset)
{
        size_t b, i = 0;
        char *p, *buf = s, byte;
        long off = *offset;

        do {
                b = _read(fd, (char *)&byte, 1);
                _lseek(fd, ++off, SEEK_SET);
                if (b < 1)
                        break;
                buf[i++] = byte;
                if (i == size || byte == '\n') {
                        buf[i++] = '\0';
                        break;
                }

        } while(1);

        *offset = off;
        return s;
}

int _sprintf(char *buf, char *fmt, ...)
{
        int in_p, index = 0, len;
        unsigned long dword;
        unsigned int word;
	char *s;
        char numbuf[26] = {0};
        __builtin_va_list alist;
        in_p;

        __builtin_va_start((alist), (fmt));

        in_p = 0;
        while(*fmt) {
                if (*fmt!='%' && !in_p) {
			buf[index++] = *(char *)fmt;
                        in_p = 0;
                }
                else if (*fmt!='%') {
                        switch(*fmt) {
                                case 's':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
					s = itoa(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)itoa(word, numbuf), len);
					index += len;
                                        break;
                                case 'u':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
					s = itoa(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)s, len);
                                        index += len;
                                        break;
                                case 'd':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
					s = itoa(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)s, len);
                                        index += len;
                                        break;
                                case 'x':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
					s = itox(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)s, len);
                                        index += len;
                                        break;
                                default:	
					buf[index++] = *(char *)fmt;
                                        break;
                        }
                        in_p = 0;
                }
                else {
                        in_p = 1;
                }
                fmt++;
        }
	return 1;

}


int _printf(char *fmt, ...)
{
        int in_p;
        unsigned long dword;
        unsigned int word;
        char numbuf[26] = {0};
        __builtin_va_list alist;

        in_p;
        __builtin_va_start((alist), (fmt));

        in_p = 0;
        while(*fmt) {
                if (*fmt!='%' && !in_p) {
                        _write(1, fmt, 1);
                        in_p = 0;
                }
                else if (*fmt!='%') {
                        switch(*fmt) {
                                case 's':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts((char *)dword);
                                        break;
                                case 'u':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
				case 'd':
					word = (unsigned int) __builtin_va_arg(alist, int);
					_puts(itoa(word, numbuf));
					break;
                                case 'x':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts(itox(dword, numbuf));
                                        break;
                                default:
                                        _write(1, fmt, 1);
                                        break;
                        }
                        in_p = 0;
                }
                else {
                        in_p = 1;
	 	}
                fmt++;
        }
        return 1;
}

char * itoa(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 10) + '0';
                x /= 10;
                i++;
        } while (x!=0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}

char * itox(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 16);

                /* char conversion */
                if (t[i] > 9)
                        t[i] = (t[i] - 10) + 'a';
                else
                        t[i] += '0';

                x /= 16;
                i++;
        } while (x != 0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}

int _puts(char *str)
{
        _write(1, str, _strlen(str));
        _fsync(1);

        return 1;
}

size_t _strlen(char *s)
{
        size_t sz;

        for (sz=0;s[sz];sz++);
        return sz;
}

     
char *_strchr(const char *s, int c)
{
    const char ch = c;

    for ( ; *s != ch; s++)
        if (*s == '\0')
            return 0;
    return (char *)s;
}

char * _strrchr(const char *cp, int ch)
{
    char *save;
    char c;

    for (save = (char *) 0; (c = *cp); cp++) {
	if (c == ch)
	    save = (char *) cp;
    }

    return save;
}
      
int _strncmp(const char *s1, const char *s2, size_t n)
{
    for ( ; n > 0; s1++, s2++, --n)
	if (*s1 != *s2)
	    return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
	else if (*s1 == '\0')
	    return 0;
    return 0;
}
                                               
int _strcmp(const char *s1, const char *s2)
{
        int r = 0;

        while (!(r = (*s1 - *s2) && *s2))
                s1++, s2++;
        if (!r)
                return r;
        return r = (r < 0) ? -1 : 1;
}

int _memcmp(const void *s1, const void *s2, unsigned int n)
{
	unsigned char u1, u2;

	for ( ; n-- ; s1++, s2++) {
		u1 = * (unsigned char *) s1;
		u2 = * (unsigned char *) s2;
	if ( u1 != u2) {
		return (u1-u2);
	}
    }
    return 0;
}

void _memcpy(void *dst, void *src, unsigned int len)
{
        int i;
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;

        for (i = 0; i < len; i++) {
                *d = *s;
                s++, d++;
        }

}

static unsigned long createStack(void)
{
        uint8_t *mem;
        mem = _mmap(0, STACK_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS, -1, 0);
        if(mem == MAP_FAILED) {
                _printf("[!] libdarkley: stack allocation failed for thread\n");
                Exit(-1);
        }
        return (unsigned long)(mem + STACK_SIZE);
}

int create_thread(void (*fn)(void *), void *data)
{
        long retval;
        void **newstack;


        newstack = (void **)createStack();
        *--newstack = data;

        __asm__ __volatile__(
                "syscall        \n\t"
                "test %0,%0     \n\t"        /* check return value */
                "jne 1f         \n\t"            /* jump if parent */
                "call *%3       \n\t"          /* start subthread function */
                "mov %2,%0      \n\t"
                "xor %%r10, %%r10\n\t"
                "xor %%r8, %%r8\n\t"
                "xor %%r9, %%r9 \n\t"
                "int $0x80      \n\t"           /* exit system call: exit subthread */
                "1:\t"
                :"=a" (retval)
                :"0" (__NR_clone),"i" (__NR_exit),
                 "g" (fn),
                 "D" (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_UNTRACED| SIGCHLD),
                 "S" (newstack));

        if (retval < 0) {
                errno = -retval;
                retval = -1;
        }
        return retval;
}

void exit_thread(void)
{
        Exit(0);
}

/*
 * Return instruction pointer
 */
unsigned long get_rip(void)
{
        asm(
          "call get_ip   \n"
          ".globl get_ip \n"
          "get_ip:      \n"
          "pop %rax"
        );
}

