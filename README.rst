adb\_shell
==========

.. image:: https://travis-ci.com/JeffLIrion/aio_adb_shell.svg?branch=master
   :target: https://travis-ci.com/JeffLIrion/aio_adb_shell

.. image:: https://coveralls.io/repos/github/JeffLIrion/aio_adb_shell/badge.svg?branch=master
   :target: https://coveralls.io/github/JeffLIrion/aio_adb_shell?branch=master


Documentation for this package can be found at https://adb-shell.readthedocs.io/.

This Python package implements ADB shell and FileSync functionality.  It originated from `python-adb <https://github.com/google/python-adb>`_.

Installation
------------

.. code-block::

   pip install adb-shell


Example Usage
-------------

(Based on `androidtv/adb_manager.py <https://github.com/JeffLIrion/python-androidtv/blob/133063c8d6793a88259af405d6a69ceb301a0ca0/androidtv/adb_manager.py#L67>`_)

.. code-block:: python

   from aio_adb_shell.adb_device import AdbDeviceTcp
   from aio_adb_shell.auth.sign_pythonrsa import PythonRSASigner

   # Connect (no authentication necessary)
   device1 = AdbDeviceTcp('192.168.0.111', 5555, default_timeout_s=9.)
   await device1.connect(auth_timeout_s=0.1)

   # Connect (authentication required)
   with open('path/to/adbkey') as f:
       priv = f.read()
   signer = PythonRSASigner('', priv)
   device2 = AdbDeviceTcp('192.168.0.222', 5555, default_timeout_s=9.)
   await device2.connect(rsa_keys=[signer], auth_timeout_s=0.1)

   # Send a shell command
   response1 = await device1.shell('echo TEST1')
   response2 = await device2.shell('echo TEST2')
