
===============
Jasypt 2 Python
===============


Description
-----------

    This project allows for python to decrypt ciphertext that has been encrypted with the JASYPT Java library.
    It assumes that the encryption has been done in the format:

        PBEWITHSHA256AND256BITAES-CBC-BC

    The purpose of this library is to provide the ability for Python applications (such as Django and its custom
    fields) to access information from a database that has been encrypted using the JASYPT field-level method.


Usage
-----

.. code-block:: python

    from j2p.JASYPT import Decryptor


    my_password = "password used for encryption"
    some_ciphertext = "..."

    decryptor = Decryptor(my_password)
    plaintext = decryptor.decrypt(some_ciphertext)

    print plaintext


Requires
--------

* All requirements are listed in requirements.txt
* J2P decryption uses the pycrypto library (from https://pypi.python.org/pypi/pycrypto)