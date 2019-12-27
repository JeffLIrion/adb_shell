from setuptools import setup

with open('README.rst') as f:
    readme = f.read()

setup(
    name='adb_shell',
    version='0.1.0',
    description='A Python implementation of ADB with shell and FileSync functionality.',
    long_description=readme,
    url='https://github.com/JeffLIrion/adb_shell',
    author='Jeff Irion',
    author_email='jefflirion@users.noreply.github.com',
    packages=['adb_shell', 'adb_shell.auth', 'adb_shell.handle'],
    install_requires=['cryptography', 'pyasn1', 'rsa'],
    tests_require=['pycryptodome'],
    classifiers=['Operating System :: OS Independent',
                 'Programming Language :: Python :: 3',
                 'Programming Language :: Python :: 2'],
    test_suite='tests'
)
