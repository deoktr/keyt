====
keyt
====


.. image:: https://img.shields.io/pypi/v/keyt.svg
        :target: https://pypi.python.org/pypi/keyt


keyt is a stateless password manager/generator.

The intent of this program is to have a password manager and generator without storing any data anywhere in any form. No database, no storage, no encryption.


Install
-------

.. code-block::

   pip install keyt


Usage
-----

.. code-block::

    $ keyt -h
    usage: keyt [domain] [username] [master_password] [options]

    keyt stateless password manager/generator.

    positional arguments:
      domain                Domain name/IP/service.
      username              Username/Email/ID.
      master_password       Master password used during the password generation.

    optional arguments:
      -h, --help            show this help message and exit
      --version
      -c [DOMAIN_COUNTER], --domain-counter [DOMAIN_COUNTER]
                            An integer representing the number of times you
                            changed your password, increment to change password.
      -s, --short-simple    Short and simple password, generate a 15 char password
                            variant instead of the 40 default, and without special
                            characters.
      -o, --output          Output the password, by default the password is added
                            to the clipboard.
      -t [TIMER], --timer [TIMER]
                            Time before flushing the clipboard, default=20 (s),
                            use 0 to disable the timer.


Examples
--------

.. code-block::

    $ keyt
    domain: example.com
    username: admin
    master password:
    Password copied to the clipboard for 20s.

    $ keyt example.com admin admin
    Password copied to the clipboard for 20s.

    $ keyt example.com admin admin -o
    F=jSlI5}cDVK*=^H#uZwWI1JHVlp{2WMVQgG-hTo

    $ keyt example.com admin admin -o -s
    Rj1qU2xJNX1jRFZ


License
-------

Free software: MIT license
