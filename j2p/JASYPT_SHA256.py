

class SHA256HASH(object):
    """

        Reverse-Engineered SHA 256 (From the Java library Jasypt)

        References:
            Jasypt Grails Plugin: http://grails.org/plugin/jasypt-encryption
            Bouncy Castle (Java)

        Reasons For Reverse Engineering:
            The SHA 256 library used by Jasypt implemented a specific version of the update(byte[]), update(byte),
            and final() methods. These methods DO have implementations in their Python counterpart, however they are
            slightly different - which makes them useless for reverse engineering the Jasypt library (as the
            functionality would have to change significantly).


        THIS LIBRARY IS FOR EXTERNAL USE ONLY!!! (Converting from old grails DB to new Python DB)

        DO NOT USE THIS LIBRARY IN PRODUCTION CODE!!! USE THE PYTHON LIBRARIES!!!

        Author: Caleb Shortt
                November 2014

    """

    BYTE_LENGTH = 64

    # byte[]
    x_buf = [0x00]*4

    # int
    x_buff_off = 0
    byte_count = 0

    x_off = 0

    H1 = 0x6a09e667
    H2 = 0xbb67ae85
    H3 = 0x3c6ef372
    H4 = 0xa54ff53a
    H5 = 0x510e527f
    H6 = 0x9b05688c
    H7 = 0x1f83d9ab
    H8 = 0x5be0cd19

    # int[]
    X = [0x00]*64

    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        self.reset()

    def process_word(self, bytes_in, in_off):
        """

        :param bytes_in: byte[]
        :param in_off: int
        :return:
        """

        n = int(bytes_in[in_off] << 24)
        in_off += 1
        n |= int((bytes_in[in_off] & 0xff) << 16)
        in_off += 1
        n |= int((bytes_in[in_off] & 0xff) << 8)
        in_off += 1
        n |= int((bytes_in[in_off] & 0xff))

        self.X[self.x_off] = int(n)
        self.x_off += 1

        if self.x_off == 16:
            self.process_block()

    def process_block(self):

        for t in range(16, 64):

            ta0 = self.X[t-2]
            ta = self.theta_1(ta0)
            tb = self.X[t-7]
            tc0 = self.X[t-15]
            tc = self.theta_0(tc0)
            td = self.X[t-16]

            result = (ta + tb + tc + td) & 0xffffffff

            s32_result = self.convert_to_s32int(result)

            self.X[t] = s32_result

        a = self.H1
        b = self.H2
        c = self.H3
        d = self.H4
        e = self.H5
        f = self.H6
        g = self.H7
        h = self.H8

        t = 0
        for i in range(8):

            h0 = self.convert_to_s32int((self.sum_1(e) + self.ch(e, f, g) + self.K[t] + self.X[t]) & 0xffffffff)
            h = self.convert_to_s32int((h + h0) & 0xffffffff)
            d = self.convert_to_s32int((d + h) & 0xffffffff)
            h0 = self.convert_to_s32int((self.sum_0(a) + self.maj(a, b, c)) & 0xffffffff)
            h = self.convert_to_s32int((h + h0) & 0xffffffff)
            t += 1

            g0 = self.convert_to_s32int((self.sum_1(d) + self.ch(d, e, f) + self.K[t] + self.X[t]) & 0xffffffff)
            g = self.convert_to_s32int((g + g0) & 0xffffffff)
            c = self.convert_to_s32int((c + g) & 0xffffffff)
            g0 = self.convert_to_s32int((self.sum_0(h) + self.maj(h, a, b)) & 0xffffffff)
            g = self.convert_to_s32int((g + g0) & 0xffffffff)
            t += 1

            f0 = self.convert_to_s32int((self.sum_1(c) + self.ch(c, d, e) + self.K[t] + self.X[t]) & 0xffffffff)
            f = self.convert_to_s32int((f + f0) & 0xffffffff)
            b = self.convert_to_s32int((b + f) & 0xffffffff)
            f0 = self.convert_to_s32int((self.sum_0(g) + self.maj(g, h, a)) & 0xffffffff)
            f = self.convert_to_s32int((f + f0) & 0xffffffff)
            t += 1

            e0 = self.convert_to_s32int((self.sum_1(b) + self.ch(b, c, d) + self.K[t] + self.X[t]) & 0xffffffff)
            e = self.convert_to_s32int((e + e0) & 0xffffffff)
            a = self.convert_to_s32int((a + e) & 0xffffffff)
            e0 = self.convert_to_s32int((self.sum_0(f) + self.maj(f, g, h)) & 0xffffffff)
            e = self.convert_to_s32int((e + e0) & 0xffffffff)
            t += 1

            d0 = self.convert_to_s32int((self.sum_1(a) + self.ch(a, b, c) + self.K[t] + self.X[t]) & 0xffffffff)
            d = self.convert_to_s32int((d + d0) & 0xffffffff)
            h = self.convert_to_s32int((h + d) & 0xffffffff)
            d0 = self.convert_to_s32int((self.sum_0(e) + self.maj(e, f, g)) & 0xffffffff)
            d = self.convert_to_s32int((d + d0) & 0xffffffff)
            t += 1

            c0 = self.convert_to_s32int((self.sum_1(h) + self.ch(h, a, b) + self.K[t] + self.X[t]) & 0xffffffff)
            c = self.convert_to_s32int((c + c0) & 0xffffffff)
            g = self.convert_to_s32int((g + c) & 0xffffffff)
            c0 = self.convert_to_s32int((self.sum_0(d) + self.maj(d, e, f)) & 0xffffffff)
            c = self.convert_to_s32int((c + c0) & 0xffffffff)
            t += 1

            b0 = self.convert_to_s32int((self.sum_1(g) + self.ch(g, h, a) + self.K[t] + self.X[t]) & 0xffffffff)
            b = self.convert_to_s32int((b + b0) & 0xffffffff)
            f = self.convert_to_s32int((f + b) & 0xffffffff)
            b0 = self.convert_to_s32int((self.sum_0(c) + self.maj(c, d, e)) & 0xffffffff)
            b = self.convert_to_s32int((b + b0) & 0xffffffff)
            t += 1

            a0 = self.convert_to_s32int((self.sum_1(f) + self.ch(f, g, h) + self.K[t] + self.X[t]) & 0xffffffff)
            a = self.convert_to_s32int((a + a0) & 0xffffffff)
            e = self.convert_to_s32int((e + a) & 0xffffffff)
            a0 = self.convert_to_s32int((self.sum_0(b) + self.maj(b, c, d)) & 0xffffffff)
            a = self.convert_to_s32int((a + a0) & 0xffffffff)
            t += 1

        self.H1 = self.convert_to_s32int((self.H1 + a) & 0xffffffff)
        self.H2 = self.convert_to_s32int((self.H2 + b) & 0xffffffff)
        self.H3 = self.convert_to_s32int((self.H3 + c) & 0xffffffff)
        self.H4 = self.convert_to_s32int((self.H4 + d) & 0xffffffff)
        self.H5 = self.convert_to_s32int((self.H5 + e) & 0xffffffff)
        self.H6 = self.convert_to_s32int((self.H6 + f) & 0xffffffff)
        self.H7 = self.convert_to_s32int((self.H7 + g) & 0xffffffff)
        self.H8 = self.convert_to_s32int((self.H8 + h) & 0xffffffff)

        self.x_off = 0
        for i in range(16):
            self.X[i] = 0x00

    def reset(self):
        self.byte_count = 0
        self.x_buff_off = 0

        for i in range(len(self.x_buf)):
            self.x_buf[i] = 0x00

        self.H1 = self.convert_to_s32int(0x6a09e667)
        self.H2 = self.convert_to_s32int(0xbb67ae85)
        self.H3 = self.convert_to_s32int(0x3c6ef372)
        self.H4 = self.convert_to_s32int(0xa54ff53a)
        self.H5 = self.convert_to_s32int(0x510e527f)
        self.H6 = self.convert_to_s32int(0x9b05688c)
        self.H7 = self.convert_to_s32int(0x1f83d9ab)
        self.H8 = self.convert_to_s32int(0x5be0cd19)

        self.x_off = 0

        for i in range(len(self.X)):
            self.X[i] = int(0x00)

    def do_final(self, out, out_off):
        """
        :param out: byte[]
        :param out_off: int
        :return:
        """
        self.finish()

        out = self.int_to_big_endian(self.H1, out, out_off)
        out = self.int_to_big_endian(self.H2, out, out_off + 4)
        out = self.int_to_big_endian(self.H3, out, out_off + 8)
        out = self.int_to_big_endian(self.H4, out, out_off + 12)
        out = self.int_to_big_endian(self.H5, out, out_off + 16)
        out = self.int_to_big_endian(self.H6, out, out_off + 20)
        out = self.int_to_big_endian(self.H7, out, out_off + 24)
        out = self.int_to_big_endian(self.H8, out, out_off + 28)

        self.reset()

        return out

    def int_to_big_endian(self, n, bs, off):
        """
        Convert int to big endian
        :param n: int
        :param bs: byte[]
        :param off: offset
        :return:
        """
        bs[off] = self.convert_to_s8int(self.r_shift(n, 24))
        off += 1
        bs[off] = self.convert_to_s8int(self.r_shift(n, 16))
        off += 1
        bs[off] = self.convert_to_s8int(self.r_shift(n, 8))
        off += 1
        bs[off] = self.convert_to_s8int(self.convert_to_s32int(n))

        return bs

    def finish(self):
        bit_length = self.byte_count << 3
        self.update(-128)

        while self.x_buff_off != 0:
            self.update(0x00)

        self.process_length(bit_length)
        self.process_block()

    def process_length(self, bit_length):

        if self.x_off > 14:
            self.process_block()

        self.X[14] = int(self.r_shift(bit_length, 32))
        self.X[15] = int(bit_length & 0xffffffff)

    def update_bytes(self, in_bytes, in_off, length):
        """

        :param in_bytes: byte[] -> input bytes
        :param in_off: int -> input offset
        :param length: int -> length of input bytes
        :return:
        """

        # Fill the current word
        while self.x_buff_off != 0 and length > 0:
            self.update(in_bytes[in_off])
            in_off += 1
            length -= 1

        # Process whole words (4 bytes)
        while length > len(self.x_buf):
            self.process_word(in_bytes, in_off)
            in_off += len(self.x_buf)
            length -= len(self.x_buf)
            self.byte_count += len(self.x_buf)

        # Load in the remainder
        while length > 0:
            self.update(in_bytes[in_off])
            in_off += 1
            length -= 1

    def update(self, byte_in):
        """
        Update a single byte, and add it to the hash digest

        :param byte_in: a single byte (8-bit char?)
        :return:
        """

        self.x_buf[self.x_buff_off] = byte_in
        self.x_buff_off += 1

        if self.x_buff_off == len(self.x_buf):
            self.process_word(self.x_buf, 0)
            self.x_buff_off = 0

        self.byte_count += 1

    def theta_0(self, x):

        a = self.r_shift(x, 7)
        b = self.convert_to_s32int((x << 25) & 0xffffffff)
        c = self.r_shift(x, 18)
        d = self.convert_to_s32int((x << 14) & 0xffffffff)
        e = self.r_shift(x, 3)

        result = self.convert_to_s32int((a | b) ^ (c | d) ^ e)
        return result

    def theta_1(self, x):

        a = self.r_shift(x, 17)
        b = self.convert_to_s32int((x << 15) & 0xffffffff)
        c = self.r_shift(x, 19)
        d = self.convert_to_s32int((x << 13) & 0xffffffff)
        e = self.r_shift(x, 10)

        result = self.convert_to_s32int((a | b) ^ (c | d) ^ e)
        return result

    def sum_0(self, x):

        a = self.r_shift(x, 2)
        b = self.convert_to_s32int((x << 30) & 0xffffffff)
        c = self.r_shift(x, 13)
        d = self.convert_to_s32int((x << 19) & 0xffffffff)
        e = self.r_shift(x, 22)
        f = self.convert_to_s32int((x << 10) & 0xffffffff)

        result = (a | b) ^ (c | d) ^ (e | f)
        return result

    def sum_1(self, x):

        a = self.r_shift(x, 6)
        b = self.convert_to_s32int((x << 26) & 0xffffffff)
        c = self.r_shift(x, 11)
        d = self.convert_to_s32int((x << 21) & 0xffffffff)
        e = self.r_shift(x, 25)
        f = self.convert_to_s32int((x << 7) & 0xffffffff)

        result = self.convert_to_s32int((a | b) ^ (c | d) ^ (e | f))
        return result

    def maj(self, x, y, z):

        x = self.convert_to_s32int(x)
        y = self.convert_to_s32int(y)
        z = self.convert_to_s32int(z)

        result = self.convert_to_s32int((x & y) ^ (x & z) ^ (y & z))
        return result

    def ch(self, x, y, z):

        x = self.convert_to_s32int(x)
        y = self.convert_to_s32int(y)
        z = self.convert_to_s32int(z)

        result = self.convert_to_s32int((x & y) ^ ((~x) & z))
        return result

    def r_shift(self, val, n):
        return ((val % 0x100000000) >> n) & 0xffffffff

    def convert_to_s32int(self, val):
        masked = val & 0x80000000
        if masked:
            val = (-0x100000000 + val)
        return val

    def convert_to_s8int(self, val):
        unsigned = val & 0xff
        s_8_bit = unsigned - 256 if unsigned > 127 else unsigned
        return s_8_bit

    def convert_to_us8int(self, val):
        signed = val & 0xff
        us_8_bit = signed + 256 if signed < 0 else signed
        return us_8_bit
