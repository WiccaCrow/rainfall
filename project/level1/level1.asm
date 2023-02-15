gdb ./level1 opq hhww www
Excess command line arguments ignored. (hhww ...)
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
/home/user/level1/opq: No such file or directory.
(gdb) disassemble
_DYNAMIC                   __do_global_ctors_aux      __libc_start_main@got.plt  fwrite
_GLOBAL_OFFSET_TABLE_      __do_global_dtors_aux      __libc_start_main@plt      fwrite@got.plt
_IO_stdin_used             __dso_handle               _edata                     fwrite@plt
__CTOR_END__               __gmon_start__             _end                       gets
__CTOR_LIST__              __gmon_start__@got.plt     _fini                      gets@got.plt
__DTOR_END__               __gmon_start__@plt         _fp_hw                     gets@plt
__DTOR_LIST__              __i686.get_pc_thunk.bx     _init                      main
__FRAME_END__              __init_array_end           _start                     run
__JCR_END__                __init_array_start         completed.6159             stdout@@GLIBC_2.0
__JCR_LIST__               __libc_csu_fini            data_start                 system
__bss_start                __libc_csu_init            dtor_idx.6161              system@got.plt
__data_start               __libc_start_main          frame_dummy                system@plt
(gdb) disassemble gets
Dump of assembler code for function gets@plt:
   0x08048340 <+0>:	jmp    *0x8049798
   0x08048346 <+6>:	push   $0x0
   0x0804834b <+11>:	jmp    0x8048330
End of assembler dump.
(gdb)


(gdb) disassemble main
Dump of assembler code for function main:
   0x08048480 <+0>:	push   %ebp
   0x08048481 <+1>:	mov    %esp,%ebp
   0x08048483 <+3>:	and    $0xfffffff0,%esp
   0x08048486 <+6>:	sub    $0x50,%esp
   0x08048489 <+9>:	lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave
   0x08048496 <+22>:	ret
End of assembler dump.

