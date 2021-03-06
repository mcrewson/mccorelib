# vim:set ts=4 sw=4 et nowrap syntax=python ff=unix:
#
# Copyright 2011-2018 Mark Crewson <mark@crewson.net>
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


__all__ = [ 'Application', 'get_app', ]

import signal, sys, traceback

from mccorelib.async             import get_reactor, free_reactor
from mccorelib.baseobject        import BaseObject, NonStdlibError
from mccorelib.config            import Config, ConfigError
from mccorelib.log               import configure as configurelog, getlog
from mccorelib.string_conversion import convert_to_floating

#############################################################################

class ApplicationError (NonStdlibError):
    """Base exception for application errors"""
    pass

class OperationError (ApplicationError):
    """Raised when a runtime application operation fails"""
    pass

#############################################################################

_app_inst = None
_app_name = "UnamedApp"
_app_version = "0"

def get_app ():
    global _app_inst
    return _app_inst

def _except_hook (exc_type, value, tb):
    global _app_name, _app_version

    try:
        log = getlog()
        log.critical('Exception: please include the following information '
                     'in any bug report:')
        log.critical('  %s version %s' % (_app_name, _app_version))
        log.critical('  Python version %s' % sys.version.split('\n',1)[0])
        log.critical('')
        log.critical('Unhandled exception follows:')
        tblist = (traceback.format_tb(tb, None) +
                  traceback.format_exception_only(exc_type, value))
        if type(tblist) != list: tblist = [tblist, ]
        for line in tblist:
            for l in line.split('\n'):
                if not l: continue
                log.critical('%s' % l.rstrip())
        log.critical('')
        log.critical('Please also include configuration information from '
                     'running %s' % _app_name)
        log.critical('with your normal options plus \'--dump\'')
    except:
        traceback.print_exception(exc_type, value, tb)

class Application (BaseObject):

    app_name = "UnnamedApp"
    app_version = "0"

    short_cmdline_args = None
    long_cmdline_args = None

    options = { 'exception_hook' : _except_hook,
              }

    def __init__ (self, **kw):
        """constructor"""
        super(Application, self).__init__()
        self._parse_options(Application.options, kw)

        if hasattr(self, 'config_files'):
            self.app_config = self.config_files
        elif hasattr(self, 'config_file'):
            self.app_config = str(self.config_file)
        else:
            self.app_config = "%s.conf" % self.app_name

        global _app_inst, _app_name, _app_version
        _app_inst = self
        _app_name = self.app_name
        _app_version = self.app_version

        if self.exception_hook is not None:
            sys.excepthook = self.exception_hook

    def start (self):
        try:
            self.config = Config(self.app_config, sys.argv,
                                 short_arguments=self.short_cmdline_args,
                                 long_arguments=self.long_cmdline_args,
                                 command_line_handler=self.cmdline_handler)

            # Default logging setup, if there is a 'logging' section in
            # the configuration file. Otherwise you are on your own to
            # setup the logging subsystem
            if 'logging' in self.config.get_sections():
                configurelog(self.config)

            self.setup()
            self.run()
            self.cleanup()
            return

        except KeyboardInterrupt:
            self.abort('Aborted by user (keyboard interrupt)', errorcode=0)

        except ConfigError, o:
            self.abort('Configuration error: %s' % (o), errorcode=2)

        except OperationError, o:
            self.abort('Error: %s' % (o), errorcode=3)

        # otherwise, let the exception_hook handle the error (if defined)

    def cmdline_handler (self, argument, value):
        pass

    def setup (self):
        pass

    def cleanup (self):
        pass

    def run (self):
        raise NotImplementedError("Override this function to do something")

    def abort (self, message, errorcode=1):
        sys.stderr.write('%s\n' % message)
        sys.stderr.flush()
        try:
            self.cleanup()
        except Exception, why:
            sys.stderr.write('UNEXPECTED ERROR during cleanup: %s\n' & str(why))
            sys.stderr.flush()
        sys.exit(errorcode)

#############################################################################

class AsyncApplication (Application):

    def setup (self):
        super(AsyncApplication, self).setup()
        self.reactor = get_reactor()

    def cleanup (self):
        free_reactor()
        super(AsyncApplication, self).cleanup()

    def run (self):
        self.reactor.start()

#############################################################################
## THE END
