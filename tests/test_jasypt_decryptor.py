
import unittest
import base64

from j2p.JASYPT import Decryptor

"""

    Tests the decryption capability of the Jasypt2Python Library.

    Author: Caleb Shortt
            November 2014

"""


class DecryptorTester(unittest.TestCase):

    def setUp(self):

        self.password = "<zHkUd435\WrAB7Z@ebIo=zIdR!EN1b\\1Q6:_5P=#F.]=m!uN4z]Al4xOYh="

        self.encryptions = {
            "asdf": "M/6UDLoCxk26sWW952hIqM94KVP0/JgSejSgV6OCUE8=",
            "I dare you!": "PBKPktGenuLqbTHEcyAuE3mUMCKvp2UFdCOjeTBMLWM=",
            "This is an sms": "XS4g9FrpyoFLxlClteQKYYdsEPZFEpO5xbJqVsQvPMA=",
            "test": "HTvSyhfJlQjRtKP2oufrITtQxClfBZHmf9igfHgg7VU=",
        }

        self.decryptor = Decryptor(self.password)

    def test_basic_decryption(self):

        for plaintext, ciphertext in self.encryptions.items():
            given_plaintext = self.decryptor.decrypt(ciphertext)
            self.assertEqual(plaintext, given_plaintext)

    def test_wrong_long_ciphertext(self):

        try:
            wrong_ciphertext = base64.b64encode("this is a test 123")
            given_plaintext = self.decryptor.decrypt(wrong_ciphertext)
            given_plaintext = str(given_plaintext).decode('utf-8', 'ignore')

        except ValueError as e:
            pass
        else:
            raise AssertionError("Giving the wrong unpadded ciphertext should throw a ValueError")

    def test_wrong_short_ciphertext(self):

        try:
            too_small_ciphertext = base64.b64encode("this is a test")
            given_plaintext = self.decryptor.decrypt(too_small_ciphertext)

        except IndexError as e:
            pass
        else:
            # This is because the first 16 bytes are taken to be the IV of the cipher
            # If there are less than 16 bytes, something is clearly wrong.
            raise AssertionError("Passing in a ciphertext that is too small (less than 16 bytes) should fail")

