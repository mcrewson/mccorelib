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

    __buffer = ''

    options = { 'message_delimiter': None,
                'message_max_size' : 16384
              }

    def on_connection_made (self):
        pass

    def on_connection_lost (self):
        pass

    def on_message_received (self, message):
        pass

    def on_message_size_exceeded (self):
        pass

    def write (self, data):
        self.transport.write_data(data)

    def close (self):
        self.transport.close_when_done()

    ##########################################################################

    def __init__ (self, transport, **kw):
        super(Protocol, self).__init__()
        self._parse_options(Protocol.options, kw)

    def make_connection (self, transport):
        self.transport = transport
        self.on_connection_made()

    def data_in (self, data):
        assert self.message_delimiter is not None, "message_delimiter not specified"
        print "data_in"
        self.__buffer += data
        while self.__buffer:
            try:
                message, self.__buffer = self.__buffer.split(self.message_delimiter, 1)
            except ValueError:
                if len(self.__buffer) > self.message_max_size:
                    self.__buffer = ''
                    return self.on_message_size_exceeded()
                return

            if len(message) > self.message_max_size:
                return self.on_message_size_exceeded()

            self.on_message_received(message)

##############################################################################

class TCPChannel (asyncnet.TCPReactable):

    def __init__ (self, protocol, **kw):
        super(TCPChannel, self).__init__(**kw)
        self.protocol = protocol
        self.protocol.make_connection(self)

    def on_data_read (self, data):
        self.protocol.data_in(data)

    def on_closed (self):
        self.protocol.on_connection_lost()
        super(TCPChannel, self).on_closed()

class TCPServer (asyncnet.TCPListener):

    def __init__ (self, protocol, **kw):
        assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
        super(TCPServer, self).__init__(**kw)
        self.protocol = protocol(self, **kw)

    def on_accept (self, sock, addr):
        TCPChannel(self.protocol, address=addr, socket=sock)

##############################################################################

if asyncnet.ssl_supported == True:

    class SSLServer (asyncnet.SSLListener):

        def __init__ (self, protocol, **kw):
            assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
            super(SSLServer, self).__init__(**kw)
            self.protocol = protocol(self, **kw)

        def on_accept (self, sock, addr):
            TCPChannel(self.protocol, address=addr, socket=sock)

##############################################################################

class UDPServer (asyncnet.UDPListener):

    def __init__ (self, protocol, **kw):
        assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
        super(UDPServer, self).__init__(**kw)
        self.protocol = protocol(self, **kw)

    def on_data_read (self, data):
        self.protocol.make_connection(self)
        self.protocol.data_in(data)

##############################################################################

class MulticastServer (asyncnet.MulticastListener):

    def __init__ (self, protocol, **kw):
        assert issubclass(protocol, Protocol), 'protocol must be a class, not an instance'
        super(MulticastServer, self).__init__(**kw)
        self.protocol = protocol(self, **kw)

    def on_data_read (self, data):
        self.protocol.make_connection(self)
        self.protocol.data_in(data)

##############################################################################

def __test ():

    from myapp.async import get_reactor

    class ChatProtocol (Protocol):

        message_delimiter = '\n'

        channels = dict()

        def write_line (self, line):
            self.write_data(line + self.message_delimiter)

        def on_connection_made (self):
            ChatProtocol.channels[self] = 1
            self.nick = None
            self.write_data('nickname: ')

        def on_connection_lost (self):
            del ChatProtocol.channels[self]

        def on_message_received (self, line):
            if self.nick is None:
                try:
                    self.nick = line.split()[0]
                except IndexError:
                    self.nick = None
                if not self.nick:
                    self.write_line("Huh?")
                    self.write_data('nickname: ')
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
                self.write_data(' ' + '\r\n '.join(nicks) + '\r\n')

    TCPServer(ChatProtocol, address=('', 8518)).activate()
    get_reactor().start()

if __name__ == "__main__":
    __test()

##############################################################################
## THE END
