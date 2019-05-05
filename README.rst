========
ssh_util
========

ssh command utility

TODO for 0.9.0
==============

* change command name


Usages
=======

First use
----------

::

    (.venv) $ ssh_util init
    Enter password for your registry: xxxxx
    The registry file ~/.ssh.secret is created.

Change password
----------------

::

    (.venv) $ ssh_util chpw
    Enter CURRENT password for your registry: xxxxx
    Enter NEW password for your registry: yyyyy
    Enter NEW password again for verification: yyyyy
    Password has been changed.

Register key
-------------

::

    (.venv) $ ssh_util add -g prod ~/id_rsa_server1
    Enter password for your registry: xxxxx
    Enter passphrase for the keyfile: yyyyy
    The keyfile is registered.

List keys
----------

::

    (.venv) $ ssh_util list
    Enter password for your registry: xxxxx
    [prod]
    /home/user/.ssh/id_rsa_server1
    /home/user/.ssh/id_rsa_server2

    [stg]
    /home/user/.ssh/id_rsa_server7
    /home/user/.ssh/id_rsa_server8

Invoke ssh-agent
-----------------

::

    (venv) $ ssh_util agent -g prod
    Enter password for your registry: xxxxx
    Enter password for your registry:
    Registering keys for session "prod"
    ssh-agent PID=67779 session "prod" has been started. To close this session, exit shell.
    [prod] (venv) $
    [prod] (venv) $ exit
    exit
    ssh-agent PID=67779 session "prod" has been closed.
    (venv) $

