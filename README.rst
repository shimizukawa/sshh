====
sshh
====

``sshh`` is an ssh helper tool for batch registration of ssh private keys in ssh-agent.

The main purpose of sshh is to avoid ``ssh: Too many authentication failures`` that occurs when
the number of keys registered in ssh-agent exceeds a certain number. This error occurs when the
upper limit of key attempts is exceeded when the server is setting the upper limit of private key
attempts strictly.

This problem can be avoided by clearing all the keys registered in ssh-agent and registering
as many as necessary, or entering the passphrase each time. However, in situations where there
are multiple keys and servers, ssh connections can be very cumbersome. sshh uses Python's
subprocess package to start a new ssh-agent, and further calls ssh-add to collectively register
as many private keys as necessary. This relieves you from the hassle.

Usages
=======

Init
-----

::

    (.venv) $ sshh-config init
    Enter password for your registry: xxxxx
    The registry file ~/.sshh.registry is created.

Change password
----------------

::

    (.venv) $ sshh-config chpw
    Enter CURRENT password for your registry: xxxxx
    Enter NEW password for your registry: yyyyy
    Enter NEW password again for verification: yyyyy
    Password has been changed.

Register key
-------------

::

    (.venv) $ sshh-add -g prod ~/id_rsa_server1
    Enter password for your registry: xxxxx
    Enter passphrase for the keyfile: yyyyy
    The keyfile is registered.

List keys
----------

::

    (.venv) $ sshh-add -l
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

    (venv) $ sshh-agent -g prod
    Enter password for your registry: xxxxx
    Enter password for your registry:
    Registering keys for session "prod"
    ssh-agent PID=67779 session "prod" has been started. To close this session, exit shell.
    [prod] (venv) $
    [prod] (venv) $ exit
    exit
    ssh-agent PID=67779 session "prod" has been closed.
    (venv) $

