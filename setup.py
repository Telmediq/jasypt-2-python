
from setuptools import setup, find_packages


__version__ = '1.0.0'

setup(
    name='jasypt2python' + __version__,
    version=__version__,
    description='Jasypt decryption library in Python',
    author='Caleb Shortt',
    packages=find_packages(),
    keywords=[
        'jasypt',
        'python',
        'decryption',
    ],
    install_requires=[
        'pycrypto==2.6.1',
    ],
)
