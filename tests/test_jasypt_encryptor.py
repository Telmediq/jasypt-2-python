
import unittest
import base64

from j2p.JASYPT import J2PEngine


class EncryptorTester(unittest.TestCase):

    def setUp(self):

        self.password = "<zHkUd435\WrAB7Z@ebIo=zIdR!EN1b\\1Q6:_5P=#F.]=m!uN4z]Al4xOYh="

        self.encryptions = {
            "asdf": "M/6UDLoCxk26sWW952hIqM94KVP0/JgSejSgV6OCUE8=",
            "I dare you!": "PBKPktGenuLqbTHEcyAuE3mUMCKvp2UFdCOjeTBMLWM=",
            "This is an sms": "XS4g9FrpyoFLxlClteQKYYdsEPZFEpO5xbJqVsQvPMA=",
            "test": "HTvSyhfJlQjRtKP2oufrITtQxClfBZHmf9igfHgg7VU=",
        }

        self.j2p = J2PEngine(self.password)

    def test_basic_encryption(self):

        # for plaintext, ciphertext in self.encryptions.items():
        #     given_ciphertext = self.j2p.encrypt(plaintext)
        #     self.assertEqual(ciphertext, given_ciphertext)

        pass


