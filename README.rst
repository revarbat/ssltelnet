SslTelnet
=========

A wrapper for telnetlib.Telnet() that handles SSL/TLS, with optional             
TELNET negotiated TLS.  This can be used to connect to TELNETS and
SSLTELNET servers, as well as various MUD/MUCK/MUSH chat servers.  


API
---

The API for SslTelnet is just like that for the standard python library
telnetlib, with the addition of a few arguments to the Telnet() initializer.

ssltelnet.SslTelnet()
    Called just like telnetlib.Telnet(), with these extra optional arguments:

    force_ssl
        If True, force SSL negotiation as soon as connected.  Defaults to True.

    telnet_tls
        If true, allow TELNET TLS negotiation after non-ssl connection.  Defaults to True.

    You can also pass args that ssl.wrap_socket() would expect.

    If force_ssl is True, plaintext connections aren't allowed.
    If force_ssl is False, and telnet_tls is True, the connection
    will be plaintext until the server negotiates TLS, at which
    time the connection will be secured.
    If both are False, the connection will be plaintext.


Example
-------
::

    import ssltelnet
    s = ssltelnet.SslTelnet(force_ssl=False, host='foobar.com', port=23)
    print(s.read_until(b'\n', 10))
    s.close()


