## Linux syscall ABI


[32-bit SYSENTER entry](https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_32.S)

32-bit system calls through the vDSO's __kernel_vsyscall enter here
if X86_FEATURE_SEP is available.  This is the preferred system call
entry on 32-bit systems.

The SYSENTER instruction, in principle, should *only* occur in the
vDSO.  In practice, a small number of Android devices were shipped
with a copy of Bionic that inlined a SYSENTER instruction.  This
never happened in any of Google's Bionic versions -- it only happened
in a narrow range of Intel-provided versions.

SYSENTER loads SS, ESP, CS, and EIP from previously programmed MSRs.
IF and VM in RFLAGS are cleared (IOW: interrupts are off).
SYSENTER does not save anything on the stack,
and does not save old EIP (!!!), ESP, or EFLAGS.

To avoid losing track of EFLAGS.VM (and thus potentially corrupting
user and/or vm86 state), we explicitly disable the SYSENTER
instruction in vm86 mode by reprogramming the MSRs.

```
Arguments:
eax  system call number
ebx  arg1
ecx  arg2
edx  arg3
esi  arg4
edi  arg5
ebp  user stack
0(%ebp) arg6
```



[64-bit SYSCALL instruction entry](https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_64.S)

64-bit SYSCALL instruction entry. Up to 6 arguments in registers.

This is the only entry point used for 64-bit system calls.  The
hardware interface is reasonably well designed and the register to
argument mapping Linux uses fits well with the registers that are
available when SYSCALL is used.

SYSCALL instructions can be found inlined in libc implementations as
well as some other programs and libraries.  There are also a handful
of SYSCALL instructions in the vDSO used, for example, as a
clock_gettimeofday fallback.

64-bit SYSCALL saves rip to rcx, clears rflags.RF, then saves rflags to r11,
then loads new ss, cs, and rip from previously programmed MSRs.
rflags gets masked by a value from another MSR (so CLD and CLAC
are not needed). SYSCALL does not save anything on the stack
and does not change rsp.

```
Registers on entry:
rax  system call number
rcx  return address
r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
rdi  arg0
rsi  arg1
rdx  arg2
r10  arg3 (needs to be moved to rcx to conform to C ABI)
r8   arg4
r9   arg5
(note: r12-r15, rbp, rbx are callee-preserved in C ABI)
```

Only called from user space.

When user can change pt_regs->foo always force IRET. That is because
it deals with uncanonical addresses better. SYSRET has trouble
with them due to bugs in both AMD and Intel CPUs.

### Linux kernel - X86_32

#### int 80h

The kernel abi allows up to 6 register arguments

value	| storage
--- | ---
syscall nr	| eax
arg 1	| ebx
arg 2	| ecx
arg 3	| edx
arg 4	| esi
arg 5	| edi
arg 6	| ebp


After the syscall, the return value is stored in eax, and execution continues after the int 80h instruction. All other register values are preserved.


```asm
mov eax, __NR_write
mov ebx, 1
mov ecx, string_label
mov edx, string_length
int 80h
ret
```

#### sysenter

I think this instruction is specific to Intel CPUs.

value |storage
--- | ---
syscall nr | eax
arg 1 | ebx
arg 2 | ecx
arg 3 | edx
arg 4 | esi
arg 5 | edi
arg 6 | dword ptr [ebp]

Due to the CPU design, after the syscall execution resumes at a fixed address, which under linux is defined at boot to be somewhere in the vdso.

The kernel restores esp to the value ebp had during sysenter, and jumps to the following code :

```asm
pop ebp
pop edx
pop ecx
ret
```

This means that after the syscall, the situation is:

final value	values at sysenter

eax	syscall | return value
--- | ---
eip | dword ptr [ebp+12]
ecx | dword ptr [ebp+8]
edx | dword ptr [ebp+4]
ebp | dword ptr [ebp]
esp | ebp+16



```asm
mov eax, __NR_write
mov ebx, 1
mov ecx, string_label
mov edx, string_length

push syscall_ret
sub esp, 12
mov ebp, esp
sysenter
ud2

syscall_ret:
ret
```



I'm not sure how all this would work in the event of a sys_restart.

Also note that ebp must point to valid memory, even if the syscall does not return nor uses stack arguments (e.g. __NR_exit)

#### syscall

This instruction is specific to AMD CPUs.

I was not able to test this one, which I believe to be similar to sysenter, except that syscall saves its return address, so the kernel resumes execution right after the syscall instruction instead of the fixed vdso address.

#### gs:[10h]

The correct way to make a syscall under linux is to use the vdso trampoline, that the kernel will initialize with the correct opcode sequence for your CPU.

The ABI is the same as the int 80h one.

Note that the glibc loader is responsible for setting up gs:10h, the kernel will *not* do that on its own. The dynamic loader ld-linux.so initializes this pointer using set_thread_area() with the vdso base address found in the auxiliary vector at the process entrypoint.

```asm
mov eax, __NR_write
mov ebx, 1
mov ecx, string_label
mov edx, string_length
call gs:[10h]
ret
```

### Linux kernel - X86_64

#### syscall

Both AMD and Intel use the syscall instruction.

value | storage
--- | ---
syscall nr | rax
arg 1 | rdi
arg 2 | rsi
arg 3 | rdx
arg 4 | r10
arg 5 | r9
arg 6 | r8

Execution resumes after the syscall instruction, with the return value in the rax register.

rcx and r11 values are not preserved across the syscall, all others are.


```asm
mov rax, __NR_write
mov rdi, 1
mov rsi, string_label
mov rdx, string_length
syscall
ret
```

#### int 80h

On kernels compiled with the 'CONFIG_IA32_EMULATION' feature, X64 code can call legacy 32-bit syscalls using int 80h.

The ABI is the same as for x86 (arg 0 in ebx, ...)

Note that this mode can not reference memory above 0xffffffff, and that the syscall number stored in eax is the X86 one.

#### sysenter

It is possible to use the sysenter instruction in X64 binaries, but I dont know the ABI here. The kernel seems to segfault every time, and I did not investigate more.
