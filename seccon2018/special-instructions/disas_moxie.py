import string
from pwn import *
context.log_level = 'critical'

def disas(code, address, base_address, e):
    s = code
    base = base_address

    def reg(x):
        if x == 0:
            return "$fp"
        elif x == 1:
            return "$sp"
        elif x <= 15:
            return "$r%d" % (x-2)
        return "$r???"

    def addr(start, length):
        x = ''.join([chr(s[i]) for i in xrange(start, start+length)])
        x = x[::-1]
        if length == 1:
            a = u8(x)
        elif length == 2:
            a = u16(x)
        elif length == 4:
            a = u32(x)
        elif length == 8:
            a = u64(x)
        else:
            assert False
        for name, value in e.symbols.items():
            if value == a:
                return name

        st = ""
        cur = a
        while 1:
            try:
                c = e.read(cur, 1)
            except:
                return hex(a)
            if ord(c) == 0:
                break
            if c not in string.printable:
                return hex(a)
            st += c
            cur += 1
        return '"%s"' % st.replace("\n", "\\n")

    s = [ord(c) for c in s]
    i = 0
    while i < len(s):
        ins = s[i]
        ins = bin(ins)[2:]
        ins = ins.zfill(8)
        add = 0

        if ins.startswith("00100110"):
            mnemonic = "and %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00000101"):
            mnemonic = "add %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00101000"):
            mnemonic = "ashl %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00101101"):
            mnemonic = "ashr %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("110000"):
            mnemonic = "beq 0x???"
        elif ins.startswith("110110"):
            mnemonic = "bge 0x???"
        elif ins.startswith("111000"):
            mnemonic = "bgeu 0x???"
        elif ins.startswith("110011"):
            mnemonic = "bgt 0x???"
        elif ins.startswith("110101"):
            mnemonic = "bgtu 0x???"
        elif ins.startswith("110111"):
            mnemonic = "ble 0x???"
        elif ins.startswith("111001"):
            mnemonic = "bleu 0x???"
        elif ins.startswith("110010"):
            mnemonic = "blt 0x???"
        elif ins.startswith("110100"):
            mnemonic = "bltu 0x???"
        elif ins.startswith("110001"):
            mnemonic = "bne 0x???"
        elif ins.startswith("00110101"):
            mnemonic = "brk"
        elif ins.startswith("00001110"):
            mnemonic = "cmp %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("1001"):
            mnemonic = "dec %s, 0x%s" % (reg(s[i] & 0xF), s[i+1])
        elif ins.startswith("00110001"):
            mnemonic = "div %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("1010"):
            mnemonic = "gsr %s, %s" % (reg(s[i] & 0xF), reg(s[i+1]))
        elif ins.startswith("1000"):
            mnemonic = "inc %s, %s" % (reg(s[i] & 0xF), hex(s[i+1]))
        elif ins.startswith("00100101"):
            mnemonic = "jmp %s" % (reg(s[i+1] & 0xF))
        elif ins.startswith("00011010"):
            mnemonic = "jmpa 0x???"
            add = 4
        elif ins.startswith("00011001"):
            mnemonic = "jsr %s" % (reg(s[i+1] >> 4))
        elif ins.startswith("00000011"):
            mnemonic = "jsra %s" % (addr(i+2, 4))
            add = 4
        elif ins.startswith("00011100"):
            mnemonic = "ld.b %s, (%s)" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00001010"):
            mnemonic = "ld.l %s, (%s)" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00100001"):
            mnemonic = "ld.s %s, (%s)" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00011101"):
            mnemonic = "lda.b"
            add = 4
        elif ins.startswith("00001000"):
            mnemonic = "lda.l"
            add = 4
        elif ins.startswith("00100010"):
            mnemonic = "lda.s"
            add = 4
        elif ins.startswith("00000001"):
            mnemonic = "ldi.l %s, %s" % (reg(s[i+1] >> 4), addr(i+2, 4))
            add = 4
        elif ins.startswith("00011011"):
            mnemonic = "ldi.b"
            add = 4
        elif ins.startswith("00100000"):
            mnemonic = "ldi.s"
            add = 4
        elif ins.startswith("00110110"):
            mnemonic = "ldo.b"
            add = 2
        elif ins.startswith("00001100"):
            mnemonic = "ldo.l"
            add = 2
        elif ins.startswith("00111000"):
            mnemonic = "ldo.s"
            add = 2
        elif ins.startswith("00100111"):
            mnemonic = "lshr %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00110011"):
            mnemonic = "mod %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00000010"):
            mnemonic = "mov %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00101111"):
            mnemonic = "mul %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00010101"):
            mnemonic = "mul.x %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00101010"):
            mnemonic = "neg %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00001111"):
            mnemonic = "nop"
        elif ins.startswith("00101100"):
            mnemonic = "not %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00101011"):
            mnemonic = "or %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00000111"):
            mnemonic = "pop %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00000110"):
            mnemonic = "push %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00000100"):
            mnemonic = "ret"
        elif ins.startswith("00010000"):
            mnemonic = "sex.b %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00010001"):
            mnemonic = "sex.s %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("1011"):
            mnemonic = "ssr %s, %s" % (reg(s[i] & 0xF), reg(s[i+1]))
        elif ins.startswith("00011110"):
            mnemonic = "st.b (%s), %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00001011"):
            mnemonic = "st.l (%s), %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00100011"):
            mnemonic = "st.s (%s), %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00011111"):
            mnemonic = "sta.b 0x???"
            add = 4
        elif ins.startswith("00001001"):
            mnemonic = "sta.l 0x???"
            add = 4
        elif ins.startswith("00100100"):
            mnemonic = "sta.s 0x???"
            add = 4
        elif ins.startswith("00110111"):
            mnemonic = "sto.b 0x???"
            add = 2
        elif ins.startswith("00001101"):
            mnemonic = "sto.l 0x???"
            add = 2
        elif ins.startswith("00111001"):
            mnemonic = "sto.s 0x???"
            add = 2
        elif ins.startswith("00101001"):
            mnemonic = "sub %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00110000"):
            mnemonic = "swi ???"
            add = 4
        elif ins.startswith("00110010"):
            mnemonic = "udiv %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00110100"):
            mnemonic = "umod %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00010100"):
            mnemonic = "umul.x %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00101110"):
            mnemonic = "xor %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00010010"):
            mnemonic = "zex.b %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        elif ins.startswith("00010011"):
            mnemonic = "zex.s %s, %s" % (reg(s[i+1] >> 4), reg(s[i+1] & 0xF))
        else:
            mnemonic = "???"
        print("%s:\t%s\t%s" % (hex(base+i), hex(s[i])[2:].zfill(2) + " " + hex(s[i+1])[2:].zfill(2), mnemonic))
        i += add + 2
    print

e = ELF('runme_f3abe874e1d795ffb6a3eed7898ddcbcd929b7be')

base = 0x0000136c
def disas_function(name, address, length):
    print "function", name
    disas(e.read(address, length), address, base, e)

def print_symbol(name, address, length):
    print "%s:" % name, e.read(address, length).encode('hex')

disas_function("main", 0x000015a2, 156)
disas_function("decode", 0x00001552, 80)
disas_function("set_random_seed", 0x0000154a, 4)
disas_function("get_random_value", 0x0000154e, 4)
print_symbol("flag", e.symbols['flag'], 32)
print_symbol("randval", e.symbols['randval'], 32)
