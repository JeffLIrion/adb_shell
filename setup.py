from setuptools import setup

with open('README.rst') as f:
    readme = f.read()

setup(
    name='adb_shell_dev',
    version='0.2.1',
    description='A Python implementation of ADB with shell and FileSync functionality.',
    long_description=readme,
    keywords=['adb', 'android'],
    url='https://github.com/JeffLIrion/adb_shell_dev',
    author='Jeff Irion',
    author_email='jefflirion@users.noreply.github.com',
    packages=['adb_shell_dev', 'adb_shell_dev.auth', 'adb_shell_dev.transport'],
    install_requires=['cryptography', 'pyasn1', 'rsa'],
    tests_require=['pycryptodome', 'libusb1>=1.0.16'],
    extras_require = {'usb': ['libusb1>=1.0.16'], 'async': ['aiofiles>=0.4.0']},
    classifiers=['Operating System :: OS Independent',
                 'License :: OSI Approved :: Apache Software License',
                 'Programming Language :: Python :: 3',
                 'Programming Language :: Python :: 2'],
    test_suite='tests'
)
