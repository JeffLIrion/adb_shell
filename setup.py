from setuptools import setup

with open('README.rst') as f:
    readme = f.read()

setup(
    name='adb_shell',
    version='0.4.3',
    description='A Python implementation of ADB with shell and FileSync functionality.',
    long_description=readme,
    keywords=['adb', 'android'],
    url='https://github.com/JeffLIrion/adb_shell',
    author='Jeff Irion',
    author_email='jefflirion@users.noreply.github.com',
    packages=['adb_shell', 'adb_shell.auth', 'adb_shell.transport'],
    install_requires=['cryptography', 'pyasn1', 'rsa'],
    tests_require=['pycryptodome', 'libusb1>=1.0.16'],
    extras_require = {'usb': ['libusb1>=1.0.16'], 'async': ['aiofiles>=0.4.0']},
    classifiers=['Operating System :: OS Independent',
                 'License :: OSI Approved :: Apache Software License',
                 'Programming Language :: Python :: 3',
                 'Programming Language :: Python :: 2'],
    test_suite='tests'
)
