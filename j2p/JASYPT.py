
import array
import base64

from Crypto.Cipher import AES

from JASYPT_SHA256 import SHA256HASH


class J2PEngine(object):
    """

        Engine for the J2P library.
        When initialized, needs the password used to encrypt the plaintext.

        NOTES:
            This engine assumes that the encryption method used was PBEWITHSHA256AND256BITAES-CBC-BC

            It is the result from reverse-engineering the Jasypt grails plugin and includes some reverse engineering
            of the bouncy castle AES encryption libraries.

            This library is entirely written in Python and, as such, is extremely slow. It should only be used if
            there is no alternative.

        Author: Caleb Shortt
                November 2014

    """

    # Salt and password in bytes
    b_salt = []
    b_pword = []

    password = ""

    # Algorithm specifics
    ITERATIONS = 1000
    KEY_SIZE = 256
    IV_SIZE = 128
    SALT_SIZE = 16
    BLOCK_SIZE = 16

    digest = None

    def __init__(self, password, b_salt=None):

        if not b_salt:
            self.b_salt = [0x00]*self.SALT_SIZE

        self.password = password
        self.digest = SHA256HASH()

    def decrypt(self, b64_ciphertext):
        """
        Decrypts the ciphertext and returns the plaintext string.

        :param b64_ciphertext: The ciphertext in base 64 encoding
        :return: plaintext string
        """

        # Copy the first 16 BYTES of the given ciphertext (currently encoded in base64). IT IS THE SALT!
        s_arr = self.basic_array_copy(list(base64.b64decode(b64_ciphertext)), self.b_salt, 0, self.SALT_SIZE)

        self.b_salt = [self.digest.convert_to_s8int(ord(item)) for item in s_arr]
        self.b_pword = self.PKCS12_password_to_bytes(list(self.password))

        # Sizes are in bits. Need them to be in bytes (hence the / 8)
        key = self.generate_key(1, self.KEY_SIZE / 8)
        iv = self.generate_key(2, self.IV_SIZE / 8)

        # Key and IV are both byte[] arrays
        key_bytes = array.array('b', key).tostring()
        iv_bytes = array.array('b', iv).tostring()

        decoded_raw = base64.b64decode(b64_ciphertext)
        raw_arr = [self.digest.convert_to_s8int(ord(item)) for item in list(decoded_raw[self.SALT_SIZE:])]

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        decoded = cipher.decrypt(array.array('b', raw_arr).tostring())

        unpad = lambda s: s[0:-ord(s[-1])]

        return unpad(decoded)

    # def encrypt(self, plaintext):
    #     """
    #     Encrypts the plaintext and returns the ciphertext string (base64 encoded)
    #
    #     :param plaintext: message to be encrypted
    #     :return: base 64 encoded ciphertext string
    #     """
    #
    #     self.b_salt = [self.digest.convert_to_s8int(ord(item)) for item in plaintext]
    #     self.b_pword = self.PKCS12_password_to_bytes(list(self.password))
    #
    #     key = self.generate_key(1, self.KEY_SIZE / 8)
    #     iv = self.generate_key(2, self.IV_SIZE / 8)
    #
    #     key_bytes = array.array('b', key).tostring()
    #     iv_bytes = array.array('b', iv).tostring()
    #
    #     cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    #
    #     pad = lambda s: s + (self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE) * chr(self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE)
    #
    #     padded = str(pad(plaintext))
    #
    #     encoded = cipher.encrypt(str(iv) + padded)
    #
    #     return base64.b64encode(encoded)

    def generate_key(self, id_byte, n):
        """
        Generate a key based in the id_byte and the length 'n' of the key.

        :param id_byte: identifier byte (int)
        :param n: size of key (eg: AES is 256/8 = 32, IV is 128/8 = 16)
        :return: key in byte array (byte[])
        """

        u = 32
        v = 64

        D = [int(id_byte)]*v
        d_key = [0x00]*n

        S = []
        if self.b_salt and len(self.b_salt) > 0:
            s_size = v * ((len(self.b_salt) + v - 1) / v)
            S = [0x00]*s_size

            for i in range(len(S)):
                S[i] = self.b_salt[i % len(self.b_salt)]

        P = []
        if self.b_pword and len(self.b_pword) > 0:
            p_size = v * ((len(self.b_pword) + v - 1) / v)
            P = [0x00]*p_size

            for i in range(len(P)):
                P[i] = self.b_pword[i % len(self.b_pword)]

        I = S + P

        B = [0x00]*v
        c = (n + u - 1) / u

        for i in range(1, c + 1):

            A = [0x00]*u

            self.digest.update_bytes(D, 0, len(D))
            self.digest.update_bytes(I, 0, len(I))
            A = self.digest.do_final(A, 0)

            for j in range(1, self.ITERATIONS):
                self.digest.update_bytes(A, 0, len(A))
                A = self.digest.do_final(A, 0)

            for j in range(len(B)):
                B[j] = A[j % len(A)]

            for j in range(len(I) / v):
                I = self.adjust(I, j * v, B)

            copy_offset = (i - 1) * u
            if i == c:
                d_key = self.basic_array_copy(A, d_key, copy_offset, len(d_key) - copy_offset)
            else:
                d_key = self.basic_array_copy(A, d_key, copy_offset, len(A))

        return d_key

    def adjust(self, a, a_off, b):
        """
        :param a: byte[]
        :param a_off: int
        :param b: byte[]
        :return:
        """

        len_b = len(b)
        x = (b[-1] & 0xff) + (a[a_off + len_b - 1] & 0xff) + 1

        a[a_off + len_b - 1] = x
        x >>= 8

        i = len_b - 2
        while i >= 0:

            x += (b[i] & 0xff) + (a[a_off + i] & 0xff)
            a[a_off + i] = x
            x >>= 8
            i -= 1

        return a

    def basic_array_copy(self, source, dest, dest_offset, length):
        """
        Copy 'length' elments from the source array to the destination starting at the given 'dest_offset'
        This is a helper method.

        :param source: list
        :param dest: list
        :param dest_offset: int -> where to start copying in the destination list
        :param length: int -> how many elements to copy
        :return:
        """

        for i in range(length):
            dest[dest_offset + i] = source[i]

        return dest

    def PKCS12_password_to_bytes(self, char_arr_password):
        """
        Padds the given char array.

        :param char_arr_password: phrase broken into a char array
        :return: an array oy padded bytes -> byte array
        """

        if not isinstance(char_arr_password, list):
            raise AttributeError("char_arr_password must be a list of characters")

        l_pword = char_arr_password

        if len(l_pword) > 0:
            bts_length = (len(l_pword) + 1) * 2
            bts = [int(0)]*bts_length

            for i in range(len(l_pword)):

                digit = ord(l_pword[i])

                bts[i * 2] = int(digit >> 8)
                bts[i * 2 + 1] = int(digit)

            return bts

        return []

