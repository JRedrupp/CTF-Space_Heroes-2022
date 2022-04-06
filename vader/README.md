# Vader

## Description

Submit flag from /flag.txt from 0.cloud.chals.io:20712

## Walkthrough

### File Analysis
I have recieved a vader file

#### File Type

```bash
file vader

vader: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7d60f442a159c7fce6d6d5463b2200444210d82a, for GNU/Linux 3.2.0, not stripped
```

#### Reverse It
I need to try and reverse the executable - I'll need to find the entrypoint
```bash
readelf -h vader

ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4010a0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          18728 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 29
```

From this I think the entrypoint is `0x4010a0`

I'll use gdb to set a break on the entrypoint of the file

```gdb
sudo gdb vader

break *0x4010a0
>>> Breakpoint 1 at 0x4010a0

run
Starting program: /home/kali/ctf/space_heroes/vader/vader 
zsh:1: permission denied: /home/kali/ctf/space_heroes/vader/vader

```

Didn't have much luck with gdb - trying to open it up in Ghidra results in this

```c#
void vader(char *param_1,char *param_2,char *param_3,char *param_4,char *param_5)

{
  int iVar1;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  FILE *local_10;
  
  iVar1 = strcmp(param_1,"DARK");
  if (iVar1 == 0) {
    iVar1 = strcmp(param_2,"S1D3");
    if (iVar1 == 0) {
      iVar1 = strcmp(param_3,"OF");
      if (iVar1 == 0) {
        iVar1 = strcmp(param_4,"TH3");
        if (iVar1 == 0) {
          iVar1 = strcmp(param_5,"FORC3");
          if (iVar1 == 0) {
            local_38 = 0;
            local_30 = 0;
            local_28 = 0;
            local_20 = 0;
            local_10 = (FILE *)0x0;
            local_10 = fopen("flag.txt","r");
            fgets((char *)&local_38,0x30,local_10);
            printf("<<< %s\n",&local_38);
          }
        }
      }
    }
    else {
      printf("You are a wretched thing, of weakness and fear.");
    }
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```

I have to find a way to enter this Vader function.
I try entering in these params in the get request but get the same response back.

http://0.cloud.chals.io:20712/?1=DARK&2=S1D3&3=OF&4=TH3&5=FORC3

## Lessons Learnt
So I wasn't able to solve it - I wasn't sure of how to get these params into the program.
Looking at examples online this is an example of a ROP (Return Oriented Programming) Eploiot.
https://en.wikipedia.org/wiki/Return-oriented_programming
In ROP exploits you take advantage og that fact that in 64 Bit architecture the parameters in a function are added into particular registers before calling a function - so you can do a buffer overflow to set those parameters before the function gets called.

The Exploit makes use of 'gadgets' (Small snippets of assembly yhat pop registers off the stack and then call ret)

For example, if we needed control of both RDI and RSI, we might find two gadgets in our program that look like this (using a tool like rp++ or ROPgadget):

```bash
0x400c01: pop rdi; ret
0x400c03: pop rsi; pop r15; ret
```

Using a tool like autorop - https://github.com/mariuszskon/autorop - We can automate the finding of gadgets and exploiting the suystem.

We could have run:
```bash
autorop ./vader 0.cloud.chals.io 20712 
```
And then we would have had access to the system.

Credit to Leonuz's writeup for showing me how it's done
https://leonuz.github.io/blog/Vader/