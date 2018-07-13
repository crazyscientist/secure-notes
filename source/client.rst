CLI Client
==========

.. code::

    usage: securenotes.py [-h] [-u USERNAME] [-p PASSWORD] [-P PASSPHRASE]
                          [-H HOST] [--debug] [-s]
                          {ListNote,GetNote,AddNote,ChangeNote,DeleteNote,ShareNote,UnshareNote,ListShares}
                          ...

    Secure Notes

    positional arguments:
      {ListNote,GetNote,AddNote,ChangeNote,DeleteNote,ShareNote,UnshareNote,ListShares}
                            Commands. For detailed help on command <command> use:
                            securenotes.py <command> -h

    optional arguments:
      -h, --help            show this help message and exit

    Authentication/Server:
      -u USERNAME, --username USERNAME
                            Username
      -p PASSWORD, --password PASSWORD
                            Password
      -P PASSPHRASE, --passphrase PASSPHRASE
                            Phassphrase for encryption; if omitted, password is
                            used
      -H HOST, --host HOST  URL of server

    More options:
      --debug               Activate debug output
      -s, --save-as-defaults
                            Save generic options to config file


.. automodule:: clients.cli_client.securenotes
    :members:
    :undoc-members: