
from setuptools import setup, find_packages


__version__ = '1.0.1'

setup(
    name='Jasypt2Python',
    version=__version__,
    description='Jasypt decryption library in Python',
    author='Caleb Shortt',
    author_email='caleb.shortt@telmediq.com',
    url='https://github.com/TelmedIQ/jasypt-2-python',
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
