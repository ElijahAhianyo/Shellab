#!/usr/bin/python2.7


class Encoder:
	name = 'single_incr'
	description = 'Single incrementation encoder'
	arch = 'x86'
	rank = 'good'
	def encode(self, payload):
		def stub():
			stub ="\x32\xc1\x32\xdc\x32\xca\x32\xd3"
			stub +="\xb3\x0a\x6b\x0b\x69\x75\x69\x62"
			stub +="\x6f\x69\x6b\x70\x6f\x62\x8a\xe2"
			stub +="\xb4\x02\xb1\x05\xce\x81\x32\xdc"
			stub +="\xb1\x02\xce\x81"
			return stub
		encoded = ''
		for char in bytearray(payload):
			char += 1
			encoded += chr(char) # It was chr(char)
		return encoded, stub()

