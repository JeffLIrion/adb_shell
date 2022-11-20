adb\_shell
==========

.. image:: https://travis-ci.com/JeffLIrion/adb_shell.svg?branch=master
   :target: https://travis-ci.com/JeffLIrion/adb_shell

.. image:: https://coveralls.io/repos/github/JeffLIrion/adb_shell/badge.svg?branch=master
   :target: https://coveralls.io/github/JeffLIrion/adb_shell?branch=master

.. image:: https://pepy.tech/badge/adb-shell
   :target: https://pepy.tech/project/adb-shell


Documentation for this package can be found at https://adb-shell.readthedocs.io/.

Prebuilt wheel can be downloaded from `nightly.link <https://nightly.link/JeffLIrion/adb_shell/workflows/python-package/master/wheel.zip>`_.

This Python package implements ADB shell and FileSync functionality.  It originated from `python-adb <https://github.com/google/python-adb>`_.

Installation
------------

.. code-block::

   pip install adb-shell


Async
*****

To utilize the async version of this code, you must install into a Python 3.7+ environment via:

.. code-block::

   pip install adb-shell[async]


USB Support (Experimental)
**************************

To connect to a device via USB, install this package via:

.. code-block::

   pip install adb-shell[usb]


Example Usage
-------------

(Based on `androidtv/adb_manager.py <https://github.com/JeffLIrion/python-androidtv/blob/133063c8d6793a88259af405d6a69ceb301a0ca0/androidtv/adb_manager.py#L67>`_)

.. code-block:: python

   from adb_shell.adb_device import AdbDeviceTcp, AdbDeviceUsb
   from adb_shell.auth.sign_pythonrsa import PythonRSASigner

   # Load the public and private keys
   adbkey = 'path/to/adbkey'
   with open(adbkey) as f:
       priv = f.read()
   with open(adbkey + '.pub') as f:
        pub = f.read()
   signer = PythonRSASigner(pub, priv)

   # Connect
   device1 = AdbDeviceTcp('192.168.0.222', 5555, default_transport_timeout_s=9.)
   device1.connect(rsa_keys=[signer], auth_timeout_s=0.1)

   # Connect via USB (package must be installed via `pip install adb-shell[usb])`
   device2 = AdbDeviceUsb()
   device2.connect(rsa_keys=[signer], auth_timeout_s=0.1)

   # Send a shell command
   response1 = device1.shell('echo TEST1')
   response2 = device2.shell('echo TEST2')


Generate ADB Key Files
**********************

If you need to generate a key, you can do so as follows.

.. code-block:: python

  from adb_shell.auth.keygen import keygen

  keygen('path/to/adbkey')
