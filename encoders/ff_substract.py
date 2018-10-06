#!/usr/bin/python2.7

class Encoder:
	name = 'ff_substract'
	description = 'Substracts value of each instruction from 0xff'
	arch = 'x86'
	rank = 'manual'
	def encode(self, payload):
		def stub():
			stub = "\xeb\x0d\x5e\x8a\x1e\x80\xf3\xff\x74\x0a\x88\x1e\x46\xeb\xf4\xe8\xee\xff\xff\xff"
			return stub
		encoded = ''
		for char in bytearray(payload):
			char = 0xff - char
			encoded += chr(char) 
		return encoded + '\xff', stub()
