#!/usr/bin/python3
import random

def x86(length, use_non_canonical):
        single_nop = '\x90'
        nops = ['\x41\x49', '\x40\x48', '\x42\x4A', '\x43\x4B', '\x44\x4C'
                '\x45\x4D', '\x46\x4E', '\x47\x4F', '\x50\x58', '\x51\x59',
                '\x52\x5A', '\x53\x5B', '\x54\x5C', '\x55\x5D', '\x56\x5E',
                '\x57\x5F', '\x61\x60']
        nopsled = ''
        if use_non_canonical:
            for l in range(0,length/2):
                nopsled += nops[random.choice(range(0,len(nops)))]
            if length % 2 != 0:
                nopsled += '\x90'
        else:
            nopsled += '\x90' * length
        return nopsled

def x64(length, use_non_canonical):
    single_nop = '\x90'
    nops = ["\x91","\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\x9B","\x9C","\x9D","\x9E",
            "\x9F","\xFC","\xFD","\xF8","\xF9","\x50","\x51","\x52","\x53","\x54","\x55","\x56","\x57",
            "\x58","\x59","\x5A","\x5B","\x5C","\x5D","\x5E","\x5F","\x04",         
            "\x80\xC3",     
            "\x80\xC1",     
            "\x80\xC2",     
            "\x80\xC4",     
            "\x80\xC7",     
            "\x80\xC5",     
            "\x80\xC6",     
            "\x66\x05",       
            "\x66\x81\xC3",   
            "\x66\x81\xC1",   
            "\x66\x81\xC2",   
            "\x66\x81\xC6",   
            "\x66\x81\xC7",   
            "\x66\x41\x81\xC0",
            "\x66\x41\x81\xC1",
            "\x66\x41\x81\xC2", 
            "\x66\x41\x81\xC3", 
            "\x66\x41\x81\xC4", 
            "\x66\x41\x81\xC5", 
            "\x66\x41\x81\xC6", 
            "\x66\x41\x81\xC7", 
            "\x05",             
            "\x81\xC3",         
            "\x81\xC1",         
            "\x81\xC2",         
            "\x81\xC6",         
            "\x81\xC7",         
            "\x41\x81\xC0",     
            "\x41\x81\xC1",     
            "\x41\x81\xC2",
            "\x41\x81\xC3",
            "\x41\x81\xC4",
            "\x41\x81\xC5",
            "\x41\x81\xC6",
            "\x41\x81\xC7",
            "\x48\xB8",         
            "\x48\xBB",         
            "\x48\xB9",         
            "\x48\xBA",         
            "\x48\xBE",         
            "\x48\xBF",         
            "\x49\xB8",        
            "\x49\xB9",        
            "\x49\xBA",         
            "\x49\xBB",         
            "\x49\xBC",         
            "\x49\xBD",         
            "\x49\xBE",         
            "\x49\xBF"]
    if use_non_canonical:
        nopsled_len = 0
        nopsled = []
        while nopsled_len < length:
            nop = nops[random.choice(range(0,len(nops)))]
            nopsled.append(nop)
            nopsled_len += len(nop)
        addition = nopsled_len%length
        print(addition)
        if addition != 0:
            last_element = nopsled[-1]
            print(len(last_element))
            del nopsled[-1]
            nopsled = ''.join(nopsled) + single_nop * (len(last_element)-addition)
        else:
            nopsled = ''.join(nopsled)
    else:
        nopsled += '\x90' * length
    return nopsled
  