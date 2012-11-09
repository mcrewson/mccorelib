# vim:set ts=4 sw=4 et nowrap syntax=python ff=unix:
#
# Copyright 2011-2012 Mark Crewson <mark@crewson.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno, socket, struct, sys

from myapp import async

##############################################################################

class SocketReactable (async.Reactable):

    socket_family = None,
    socket_type   = None

    def __init__ (self, socket=None, **kw):
        super(SocketReactable, self).__init__(**kw)
        if socket is not None:
            self.set_socket(socket)

    def set_socket (self, sock):
        self.socket = sock
        self.socket.setblocking(0)
        self.add_to_reactor()

    def create_socket (self, sfamily=None, stype=None):
        if sfamily is None: sfamily = self.socket_family
        if stype is None:   stype   = self.socket_type
        self.set_socket(socket.socket(sfamily, stype))

    def fileno (self):
        return self.socket.fileno()

    def handle_close (self):
        try:
            self.socket.close()
        except socket.error, err:
            if err.args[0] not in (errno.ENOTCONN, errno.EBADF):
                raise

    ##############################################

    # Socket object methods

    def bind (self, addr):
        self.socket.bind(addr)

    def set_reuse_addr (self):
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                   self.socket.getsockopt(socket.SOL_SOCKET, 
                                                          socket.SO_REUSEADDR) | 1)
        except socket.error:
            pass

##############################################################################

class TCPReactable (SocketReactable):

    socket_family = socket.AF_INET
    socket_type   = socket.SOCK_STREAM

    connected = False

    def on_connect (self):
        pass

    ########################################################################## 

    def __init__ (self, address=None, **kw):
        super(TCPReactable, self).__init__(**kw)
        self.address = address

    def writable (self):
        if not self.connected: return True
        return super(TCPReactable, self).writable()

    def handle_read_event (self):
        if not self.connected:
            self.handle_connect()
        super(TCPReactable, self).handle_read_event()

    def handle_write_event (self):
        if not self.connected:
            self.handle_connect()
        super(TCPReactable, self).handle_write_event()

    def handle_connect (self):
        assert self.address is not None, "no address specified for connect"
        self.connected = False
        err = self.socket.connect_ex(self.address)
        if err in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
            return
        if err in (errno.EISCONN, 0):
            self.connected = True
            self.on_connect()
        else:
            raise socket.error(err, errno.errorcode.get(err))

    def handle_close (self):
        self.connected = False
        super(TCPReactable, self).handle_close()

    def handle_read (self):
        try:
            return self.socket.recv(self.in_buffer_size)
        except socket.error, err:
            if err.args[0] in (errno.ECONNRESET, errno.ENOTCONN, errno.ESHUTDOWN):
                return ''
            else:
                raise

    def handle_write (self, data):
        try:
            return self.socket.send(data)
        except socket.error, err:
            if err.args[0] != errno.EWOULDBLOCK:
                raise
            return 0


class TCPListener (TCPReactable):

    accepting = False

    def __init__ (self, **kw):
        super(TCPListener, self).__init__(**kw)
        if not hasattr(self, 'socket'):
            self.create_socket()
            self.set_reuse_addr()

    def activate (self):
        assert self.address is not None, "no address specified for bind"
        self.bind(self.address)
        self.listen(5)

    def on_accept (self, sock, addr):
        pass

    ##########################################################################

    def writable (self):
        return False

    def handle_read_event (self):
        if self.accepting:
            self.handle_accept()
        else:
            super(TCPListener, self).handle_read_event()

    def handle_accept (self):
        try:
            sock, addr = self.socket.accept()
            self.connected = True
            self.on_accept(sock, addr)
        except socket.error, err:
            if err.args[0] != errno.EWOULDBLOCK:
                raise

    def listen (self, num):
        self.accepting = True
        return self.socket.listen(num)

##############################################################################

try:
    from OpenSSL import SSL
    ssl_supported = True
except ImportError:
    ssl_supported = False

if ssl_supported == True:

    class SSLReactable (TCPReactable):

        def __init__ (self, cert, pkey, cacert=None, **kw):
            self.ssl_ctx = None
            self.set_ssl_certificate(cert, pkey, cacert)
            super(SSLReactable, self).__init__(**kw)

        def set_ssl_certificae (self, cert, pkey, cacert=None):
            self.set_ssl_context(self._create_ssl_context(cert, pkey, cacert))

        def set_ssl_context (self, ctx):
            self.ssl_ctx = ctx

        def create_socket (self, family, type):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.ssl_ctx is not None:
                sock = SSL.Connection(self.ssl_ctx, sock)
            self.set_socket(sock)

        def handle_read (self):
            while True:
                try:
                    return super(SSLReactable, self).handle_read()
                except SSL.ZeroReturnError:
                    return ''
                except SSL.WantReadError:
                    time.sleep(0.2)
                    continue
                except SSL.Error, e:
                    if self._can_ignore_ssl_error(e):
                        return ''
                    raise

        def handle_write (self, data):
            while True:
                try:
                    return super(SSLReactable, self).handle_write(data)
                except SSL.SysCallError, e:
                    if e.args[0] == errno.EPIPE:
                        self.close()
                        return 0
                    elif e.args[0] == errno.EWOULDBLOCK:
                        return 0
                    else:
                        raise socket.error(e)
                except (SSL.WantWriteError, SSL.WantReadError):
                    time.sleep(0.2)
                    continue

        def _create_ssl_context (self, cert, pkey, cacert=None):
            ctx = SSL.Context(SSL.SSLv3_METHOD)
            ctx.use_certificate_file(cert)
            ctx.use_privatekey_file(pkey)
            if cacert is not None:
                ctx.load_client_ca(cacert)
                ctx.load_verify_locations(cacert)
                verify = SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
                def our_verify (connection, x509, errNum, errDepth, preverifyOK):
                    return preverifyOK
                ctx.set_verify(verify, our_verify)
                ctx.set_verify_depth(10)
            ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_TLSv1)
            return ctx

        def _can_ignore_ssl_error (e):
            if e.args[0] in (errno.ECONNRESET, ECONNREFUSED):
                return True
            s = "%s" % e
            if s == "no certificate returned":
                return True
            elif s == "wrong version number":
                return True
            elif s == "unexpected eof":
                return True
            return False


    class SSLServer (SSLReactable, TCPListener):

        def __init__ (self, **kw):
            SSLReactable.__init__(self, **kw)
            TCPListener.__init__(self, **kw)

##############################################################################

class UDPReactable (SocketReactable):

    socket_family = socket.AF_INET
    socket_type   = socket.SOCK_DGRAM

    def __init__ (self, address=None, **kw):
        super(UDPReactable, self).__init__(**kw)
        self.address = address

    def handle_read (self):
        try:
            data,addr = self.socket.recvfrom(self.in_buffer_size)
            return data
        except socket.error, err:
            if err.args[0] in (errno.EAGAIN, errno.EINTR, errno.EWOULDBLOCK):
                return ''
            else:
                raise

    def handle_write (self, data):
        assert self.address is not None, "no address specified for write"
        try:
            sent = self.socket.sendto(data, self.address)
            return sent
        except socket.error, err:
            if err.args[0] != errno.EWOULDBLOCK:
                raise
            return 0


class UDPListener (UDPReactable):

    def __init__ (self, **kw):
        super(UDPListener, self).__init__(**kw)
        if not hasattr(self, 'socket'):
            self.create_socket()
            self.set_reuse_addr()

    def activate (self):
        assert self.address is not None, "no address specified for bind"
        self.bind(self.address)

##############################################################################

class MulticastReactable (UDPReactable):
    joined_group = False

    def on_join_group (self):
        pass

    def on_leave_group (self):
        pass

    def set_loopback_mode (self, mode):
        mode = struct.pack('b', mode)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, mode)

    def set_ttl (self, ttl):
        ttl = struct.pack('B', ttl)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    ##########################################################################

    def __init__ (self, interface='', **kw):
        super(MulticastReactable, self).__init__(**kw)
        self.interface = interface

    def handle_read_event (self):
        if not self.joined_group:
            self.handle_join_group()
        super(MulticastReactable, self).handle_read_event()

    def handle_write_event (self):
        if not self.joined_group:
            self.handle_join_group()
        super(MulticastReactable, self).handle_write_event()

    def handle_close (self):
        if self.joined_group:
            self.handle_leave_group()
        super(MulticastReactable, self).handle_close()

    def handle_join_group (self):
        self._multicast_join_group(self.address[0], self.interface, True)
        self.joined_group = True
        self.on_join_group()

    def handle_leave_group (self):
        self._multicast_join_group(self.address[0], self.interface, False)
        self.joined_group = False
        self.on_leave_group()

    def _multicast_join_group (self, address, interface, join):
        addr = socket.inet_aton(socket.gethostbyname(address))
        intf = socket.inet_aton(socket.gethostbyname(interface))
        if join:
            cmd = socket.IP_ADD_MEMBERSHIP
        else:
            cmd = socket.IP_DROP_MEMBERSHIP
        self.socket.setsockopt(socket.IPPROTO_IP, cmd, addr + intf)


class MulticastListener (MulticastReactable):

    def __init__ (self, **kw):
        super(MulticastListener, self).__init__(**kw)
        if not hasattr(self, 'socket'):
            self.create_socket()
            self.set_reuse_addr()

    def activate (self):
        assert self.address is not None, "no address specified for bind"
        self.bind(self.address)
        self.handle_join_group()

##############################################################################
## THE END
