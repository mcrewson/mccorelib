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

from myapp import baseobject, asyncnet

##############################################################################

class Protocol (baseobject.BaseObject):

    def on_connection_made (self):
        pass

    def on_connection_lost (self):
        pass

    def on_message_received (self, message):
        pass

    def on_message_size_exceeded (self):
        pass

    def on_timeout (self):
        pass

    def write (self, data):
        assert self.channel is not None, "No channel to write to"
        self.channel.write_data(data)

    def close (self):
        assert self.channel is not None, "No channel to close"
        self.channel.close_when_done()

    ##########################################################################

    options = { 'message_delimiter': None,
                'message_max_size' : 16384
              }

    _buffer = ''

    def __init__ (self, **kw):
        super(Protocol, self).__init__()
        self._parse_options(Protocol.options, kw)
        self.channel = None

    def make_connection (self, channel):
        self.channel = channel
        self.on_connection_made()

    def lose_connection (self):
        if self._buffer:
            if len(self._buffer) > self.message_max_size:
                self._buffer = ''
                return self.on_message_size_exceeded()
            else:
                self.on_message_received(self._buffer)
                self._buffer = ''

        self.on_connection_lost()

    def timeout_connection (self):
        self.on_timeout()

    def data_in (self, data):
        assert self.message_delimiter is not None, "message_delimiter not specified"
        self._buffer += data
        while self._buffer:
            try:
                message, self._buffer = self._buffer.split(self.message_delimiter, 1)
            except ValueError:
                if len(self._buffer) > self.message_max_size:
                    self._buffer = ''
                    return self.on_message_size_exceeded()
                return

            if len(message) > self.message_max_size:
                self._buffer = ''
                return self.on_message_size_exceeded()

            self.on_message_received(message)

##############################################################################

class LineProtocol (Protocol):

    def on_raw_data_received (self, data):
        pass

    def on_line_received (self, line):
        pass

    def on_line_length_exceeded (self, line):
        self.on_message_size_exceeded()
        self.channel.close_when_done()

    #########################################################################

    options = { 'message_delimiter' : '\r\n' }

    _line_mode = 1

    def __init__ (self, **kw):
        super(LineProtocol, self).__init__()
        self._parse_options(LineProtocol.options, kw)

    def data_in (self, data):
        self._buffer += data
        while self._line_mode:
            try:
                line, self._buffer = self._buffer.split(self.message_delimiter, 1)
            except ValueError:
                if len(self._buffer) > self.message_max_size:
                    line, self._buffer = self._buffer, ''
                    return self.on_line_length_exceeded(line)
                break
            else:
                if len(self._buffer) > self.message_max_size:
                    line, self._buffer = self._buffer, ''
                    return self.on_line_length_exceeded(line)
                self.on_line_received(line)
        else:
            data, self._buffer = self._buffer, ''
            if data:
                self.on_raw_data_received(data)

    def set_line_mode (self, extra=''):
        self._line_mode = 1
        if extra:
            return self.data_in(extra)

    def set_raw_mode (self, extra=''):
        self._line_mode = 0
        if extra:
            return self.data_in(extra)

##############################################################################

class TCPChannel (asyncnet.TCPReactable):

    def __init__ (self, protocol, **kw):
        super(TCPChannel, self).__init__(**kw)
        self.protocol = protocol(**kw)
        self.protocol.make_connection(self)

    def on_data_read (self, data):
        self.protocol.data_in(data)

    def on_timeout (self):
        self.protocol.timeout_connection()
        super(TCPChannel, self).on_timeout()

    def on_closed (self):
        self.protocol.lose_connection()
        super(TCPChannel, self).on_closed()

class TCPServer (asyncnet.TCPListener):

    def __init__ (self, protocol, **kw):
        assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
        super(TCPServer, self).__init__(**kw)
        self.protocol = protocol
        self.protocol_kw = dict([i for i in kw.items() if i[0] not in ('address','socket')])

    def on_accept (self, sock, addr):
        TCPChannel(self.protocol, address=addr, socket=sock, **self.protocol_kw)

##############################################################################

if asyncnet.ssl_supported == True:

    class SSLServer (asyncnet.SSLListener):

        def __init__ (self, protocol, **kw):
            assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
            super(SSLServer, self).__init__(**kw)
            self.protocol = protocol

        def on_accept (self, sock, addr):
            TCPChannel(self.protocol, address=addr, socket=sock)

##############################################################################

class UDPServer (asyncnet.UDPListener):

    def __init__ (self, protocol, **kw):
        assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
        super(UDPServer, self).__init__(**kw)
        self.protocol = protocol(**kw)

    def on_data_read (self, data):
        self.protocol.make_connection(self)
        self.protocol.data_in(data)

##############################################################################

class MulticastServer (asyncnet.MulticastListener):

    def __init__ (self, protocol, **kw):
        assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
        super(MulticastServer, self).__init__(**kw)
        self.protocol = protocol(**kw)

    def on_data_read (self, data):
        self.protocol.make_connection(self)
        self.protocol.data_in(data)

##############################################################################

def __test ():

    from myapp.async import get_reactor

    class ChatProtocol (Protocol):

        channels = dict()
        idletime = 10

        def write_line (self, line):
            self.write(line + self.message_delimiter)

        def on_connection_made (self):
            ChatProtocol.channels[self] = 1
            self.nick = None
            self.write('nickname: ')
            self.channel.set_timeout(self.idletime)

        def on_connection_lost (self):
            del ChatProtocol.channels[self]

        def on_timeout (self):
            self.write_line('Connection timed out. Goodbye.')
            self.handle_talk('[quit - timed out]')
            self.close()

        def on_message_received (self, line):
            self.channel.reset_timeout()
            if self.nick is None:
                try:
                    self.nick = line.split()[0]
                except IndexError:
                    self.nick = None
                if not self.nick:
                    self.write_line("Huh?")
                    self.write('nickname: ')
                else:
                    # Greet
                    self.write_line("Hello, %s" % self.nick)
                    self.handle_talk("[joined]")
                    self.cmd_callers(None)
            else:
                if not line: pass
                elif line[0] != '/':
                    self.handle_talk(line)
                else:
                    self.handle_command(line)

        def handle_talk (self, line):
            for channel in ChatProtocol.channels.keys():
                if channel is not self:
                    channel.write_line("%s: %s" % (self.nick, line))

        def handle_command (self, line):
            command = line.split()
            name = 'cmd_%s' % command[0][1:]
            if hasattr(self, name):
                method = getattr(self, name)
                if callable(method):
                    method(command[1:])
                    return
            self.write_line('unknown command: %s' % command[0])

        def cmd_quit (self, args):
            if args:
                self.handle_talk('[quit] (%s)' % ' '.join(args))
            else:
                self.handle_talk('[quit]')
            self.write_line('goodbye.')
            self.close()

        cmd_q = cmd_quit

        def cmd_callers (self, args):
            num_channels = len(ChatProtocol.channels)
            if num_channels == 1:
                self.write_line("[You're the only caller]")
            else:
                self.write_line("[There are %d callers]" % (num_channels))
                nicks = [ x.nick or '<unknown>' for x in ChatProtocol.channels.keys() ]
                self.write(' ' + '\r\n '.join(nicks) + '\r\n')

    TCPServer(ChatProtocol, address=('', 8518), message_delimiter='\n').activate()
    get_reactor().start()

if __name__ == "__main__":
    __test()

##############################################################################
## THE END
