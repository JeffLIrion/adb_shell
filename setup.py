from setuptools import setup

with open('README.rst') as f:
    readme = f.read()

setup(
    name='aio_adb_shell',
    version='0.1.4',
    description='A Python implementation of ADB with shell and FileSync functionality.',
    long_description=readme,
    keywords=['adb', 'android'],
    url='https://github.com/JeffLIrion/aio_adb_shell',
    author='Jeff Irion',
    author_email='jefflirion@users.noreply.github.com',
    packages=['aio_adb_shell', 'aio_adb_shell.auth', 'aio_adb_shell.handle'],
    install_requires=['cryptography', 'pyasn1', 'rsa'],
    tests_require=['pycryptodome'],
    python_requires='>=3.6',
    classifiers=['Operating System :: OS Independent',
                 'License :: OSI Approved :: Apache Software License',
                 'Programming Language :: Python :: 3'],
    test_suite='tests'
)
