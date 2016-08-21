"""
A wrapper for telnetlib.Telnet() that handles SSL/TLS, with optional
TELNET negotiated TLS support.  Can be used to connect to TELNETS and
SSLTELNET servers, as well as various MUD/MUCK/MUSH chat servers.
"""

import ssl
from telnetlib import (  # noqa
    Telnet, IAC, DO, DONT, WILL, WONT, SB, SE,
    theNULL, NOP, DM, BRK, IP, AO, AYT, EC, EL, GA,
    BINARY, ECHO, RCP, SGA, NAMS, STATUS, TM, RCTE,
    NAOL, NAOP, NAOCRD, NAOHTS, NAOHTD, NAOFFD,
    NAOVTS, NAOVTD, NAOLFD, XASCII, LOGOUT, BM,
    DET, SUPDUP, SUPDUPOUTPUT, SNDLOC, TTYPE, EOR,
    TUID, OUTMRK, TTYLOC, VT3270REGIME, X3PAD, NAWS,
    TSPEED, LFLOW, LINEMODE, XDISPLOC, OLD_ENVIRON,
    AUTHENTICATION, ENCRYPT, NEW_ENVIRON, TN3270E, XAUTH,
    CHARSET, RSP, COM_PORT_OPTION, SUPPRESS_LOCAL_ECHO, TLS,
    KERMIT, SEND_URL, FORWARD_X, PRAGMA_LOGON, SSPI_LOGON,
    PRAGMA_HEARTBEAT, EXOPL, NOOPT,
)


FOLLOWS = bytes([1])


class SslTelnet(Telnet):
    def __init__(self, force_ssl=True, telnet_tls=True, **kwargs):
        """
        Called just like telnetlib.Telnet(), with these extra options:

        force_ssl  - If True, force SSL negotiation as soon as connected.
                     Defaults to True.
        telnet_tls - If true, allow TELNET TLS negotiation after non-ssl
                     connection.  Defaults to True.

        Also accepts args to ssl.wrap_socket()

        If force_ssl is True, plaintext connections aren't allowed.
        If force_ssl is False, and telnet_tls is True, the connection
        will be plaintext until the server negotiates TLS, at which
        time the connection will be secured.
        If both are False, the connection will be plaintext.
        """
        self.in_tls_wait = False
        self.tls_write_buffer = b''
        self.secure = False
        self.force_ssl = force_ssl
        self.allow_telnet_tls = telnet_tls
        self.ssltelnet_callback = None
        ssl_argnames = {
            'keyfile', 'certfile', 'cert_reqs', 'ssl_version',
            'ca_certs', 'suppress_ragged_eofs', 'ciphers',
        }
        self.ssl_args = {k: v for k, v in kwargs.items() if k in ssl_argnames}
        telnet_args = {k: v for k, v in kwargs.items() if k not in ssl_argnames}
        super(SslTelnet, self).__init__(**telnet_args)
        super(SslTelnet, self).set_option_negotiation_callback(
            self._ssltelnet_opt_cb)

    def open(self, *args, **kwargs):
        """
        Works exactly like the Telnet.open() call from the telnetlib
        module, except SSL/TLS may be transparently negotiated.
        """
        super(SslTelnet, self).open(*args, **kwargs)
        if self.force_ssl:
            self._start_tls()

    def set_option_negotiation_callback(self, callback):
        """
        Works exactly like the call from the telnetlib module,
        except that TLS negotiations will be elided.
        """
        self.ssltelnet_callback = callback

    def write(self, data):
        if self.in_tls_wait:
            self.tls_write_buffer += data
            return
        super(SslTelnet, self).write(data)

    def _start_tls(self):
        if self.secure:
            return
        # Dodgy, but only way I can see to install SSL under telnetlib.
        self.sock = ssl.wrap_socket(self.sock, **self.ssl_args)
        self.secure = True

    def _ssltelnet_opt_cb(self, sock, cmd, opt):
        if cmd == DO and opt == TLS:
            sock.sendall(IAC + (WILL if self.allow_telnet_tls else WONT) + TLS)
            sock.sendall(IAC + SB + TLS + FOLLOWS + IAC + SE)
            self.in_tls_wait = True
            self.tls_write_buffer = b''
            return
        elif cmd in (DO, DONT):
            if self.ssltelnet_callback:
                self.ssltelnet_callback(sock, cmd, opt)
            else:
                sock.sendall(IAC + WONT + opt)
        elif cmd == WILL or cmd == WONT:
            if self.ssltelnet_callback:
                self.ssltelnet_callback(sock, cmd, opt)
            else:
                sock.sendall(IAC + DONT + opt)
        elif cmd == SB:
            if self.ssltelnet_callback:
                self.ssltelnet_callback(sock, cmd, opt)
            else:
                self.msg('IAC %d not recognized' % ord(cmd))
        elif cmd == SE:
            data = self.read_sb_data()
            if self.allow_telnet_tls and data.startswith(TLS):
                if data[1:2] == b'\x01':
                    self._start_tls()
                    self.in_tls_wait = False
                    self.write(self.tls_write_buffer)
            self.tls_write_buffer = b''
                return
            # Dodgy, but restores ability to read_db_data()
            self.sbdataq = data
            if self.ssltelnet_callback:
                self.ssltelnet_callback(sock, cmd, opt)
            else:
                self.msg('IAC %d not recognized' % ord(cmd))


if __name__ == '__main__':
    s = SslTelnet(host='belfry.com', port=443)
    s.write(
        b"GET / HTTP/1.0\r\n"
        b"Host: www.belfry.com\n"
        b"\n\n"
    )
    print(s.read_all())
    s.close


# vim: expandtab tabstop=4 shiftwidth=4 softtabstop=4 nowrap
