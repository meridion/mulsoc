# Network RPC layer
"""
    Simple cPickle based network asynchronous Remote Procedure Call

    This library provides a simple unencrypted, authenticated RPC
    system. Since it uses cPickle arguments can be any normal
    Python type.
"""

from mulsoc import ManagedSocket
from struct import pack, unpack, calcsize
from cPickle import dumps, loads

# Header and magic trailer
RPC_HEADER_FORMAT = '!H'
RPC_HEADER_SIZE = calcsize(RPC_HEADER_FORMAT)
RPC_MAGIC = '#42!'
RPC_MAGIC_LENGTH = len(RPC_MAGIC)

# Arg check regexes
from re import compile as regex
rx_arg = regex('[a-zA-Z_]+')

class RemoteProcedureCall(object):
    """
        This class represents a single remote method.
    """

    # RPC calls will be wrapped by pickle in the following format
    # (<call nr>, ((varargs), {keyargs}))

    def __init__(self, rpconn, id, args_r, args_def, args_var, args_key):
        """
            rpconn: is the RPC socket.
            id: is the RPC-ID that is used to identify the call
            on the other side of the connection.
            func: is the function that should be called.
            argd_dsc: is the argument description or None if no
            argument protection is available.
        """

        # Base settings
        self.rpconn = rpconn
        self.id = id

        self.args_r, self.args_def, self.args_var, self.args_key = \
            args_r, args_def, args_var, args_key

        # Build fastcall dictionary
        arg_lookup = {}

        # Walk arguments and validate
        reg_args = self.args_r + map(lambda x: x[0], self.args_def)
        for i in xrange(len(reg_args)):
            arg = reg_args[i]

            # Regular arguments
            arg_lookup[arg] = i

        self.arg_lookup = arg_lookup

    def __call__(self, *args, **keys):
        """
            Perform RPC call

            Arguments should be according to argument format
            provided.
        """

        for k in keys:
            if self.arg_lookup[k] < len(args):
                raise TypeError("RPC got multiple values for " + k)

        args = list(args)

        # Handle regular arguments from **keys
        for i in xrange(len(args), len(self.args_r)):
            if self.args_r[i] not in keys:
                raise TypeError("Expecting %i args, got %i" %
                    (len(self.args_r), len(args)))
            args.append(keys[self.args_r[i]])
            del keys[self.args_r[i]]

        # Handle default arguments from **keys
        for i in xrange(len(args) - len(self.args_r),len(self.args_def)):
            if self.args_def[i][0] not in keys:
                args.append(self.args_def[i][1])
            else:
                args.append(keys[self.args_def[i][0]])
                del keys[self.args_def[i][0]]

        # If we are not a variable args function and
        # got too many arguments, bail.
        if len(args) > len(self.args_r) + len(self.args_def) \
                and not self.args_var:
            raise TypeError("Expecting %i args, got %i" %
                (len(self.args_r), len(args)))

        # Verify we are a keyword arguments function befor accepting
        # extra keywords
        if len(keys) and not self.args_key:
            raise TypeError("Unexpected keyword arguments")

        return self.rpconn._sendRPC(dumps((self.id, tuple(args), keys)))

class NetRPCSocket(ManagedSocket):
    """
        Network RCP class

        Any class inheriting NetRPC should not override onAccept or
        onConnect. The onSetup method is provided to initilialize
        RPC's.
    """

    def __init__(self, *args, **keys):
        ManagedSocket.__init__(self, *args, **keys)

        # The master is the socket that accepted
        self.master = False

        # Authentication strings
        self.id = self.key = ''

        # Data stream buffer and unpack variables
        self.stream = ''
        self.next_rpc_size = 0

        # Remote procedure function list
        self.rpflist = [self._export_callback]

        # Exported symbols
        self.xsymbols = {None : self._export_callback}

        # Importable symbols
        self.isymbols = {None : None}

    def onAccept(self, sock):
        """
            Manage the accepted connection.
        """
        sock._rigAuthentication()

    def onRecv(self, data):
        """
            This is the initial onRecv method, which
            will override itself upon successful authentication with
            the _onRPCRecv method.
        """

        self.stream += data
        r = self.stream.find('\r\n')
        if r != -1:
            if self.master:
                if self.stream[:r] == self.key:
                    self.onRecv = self._onRecvRPC
                    self.stream = self.stream[r + 2:]
                    self._runSetup()

                    # Following the key there could've been RPCs
                    self.onRecv('')

                else:
                    self.onAuthFail()
                    self.close()
            else:
                if self.stream[:r] == 'RPC:%s' % self.id:
                    self.onRecv = self._onRecvRPC
                    self.stream = self.stream[r + 2:]
                    self.send('%s\r\n' % self.key)
                    self._runSetup()

                    # Following the ID there couldn't have been any RPCs
                else:
                    self.onAuthFail()
                    self.close()

    def _onRecvRPC(self, data):
        """
            Handle RPC stream from the other side.
        """
        self.stream += data

        while self.isConnected():
            # Fetch next RPC message size
            if self.next_rpc_size == 0 and len(self.stream) >= RPC_HEADER_SIZE:
                d = self.stream[:RPC_HEADER_SIZE]
                self.stream = self.stream[RPC_HEADER_SIZE:]
                self.next_rpc_size = unpack(RPC_HEADER_FORMAT, d)[0]

            # Scan for magic if we lost the normal signal
            elif self.next_rpc_size == -1:
                x = self.stream.find(RPC_MAGIC)
                if x == -1:
                    return True
                self.stream = self.stream[x + RPC_MAGIC_LENGTH:]
                self.next_rpc_size = 0
                continue

            if len(self.stream) >= self.next_rpc_size + RPC_MAGIC_LENGTH:

                # Validate RPC request
                if self.stream[self.next_rpc_size:self.next_rpc_size +
                        RPC_MAGIC_LENGTH] == RPC_MAGIC:
                    rpcstr = self.stream[:self.next_rpc_size]
                    self.stream = self.stream[self.next_rpc_size +
                        RPC_MAGIC_LENGTH:]
                    self.next_rpc_size = 0
                    id, args, keywords = loads(rpcstr)
                    self.rpflist[id](*args, **keywords)
                    continue
                else:
                    self.next_rpc_size = -1
                    continue
            return True

    def _runSetup(self):
        """
            Execute RPC setup routines.
            This method is called after authentication.
        """

        self.onExport()

        # Notify export completion.
        self._sendRPC(dumps((0, (None, None, None, None, None), {})))

    def _export_callback(self, name, args_r, args_def, args_var, args_key):
        """
            This is RPC0, a special call used to receive export information.
        """

        # If name is None it means onExport on the other side is complete
        # and so on this side, we can now call onImport
        if name is None:
            self.onImport()

        # Update old RPC
        elif name in self.isymbols:
            x = self.isymbols[name]
            x.args_r, x.args_def, x.args_var, x.args_key = \
                args_r, args_def, args_var, args_key

        # Register new RPC
        else:
            self.isymbols[name] = RemoteProcedureCall(self, len(self.isymbols),
                args_r, args_def, args_var, args_key)

    def setIdentification(self, id):
        """
            Set the identification of the listening socket.
        """
        self.id = id

    def setAuthentication(self, key):
        """
            Set the authentication of the connecting socket.
        """
        self.key = key

    def _rigAuthentication(self):
        """
            This function called by onAccept and its main purpose
            is to send the RPC identification to the connecting socket.
        """
        self.master = True
        self.send('RPC:%s\r\n' % self.id)

    def exportRPC(self, name, func, args_r = [], args_def = [],
            args_var = False, args_key = False):
        """
            Register a new RPC call.
            This function should only be called before connecting, or
            during accepting.
            On success this function returns a callable RPC object that
            causes a function call in the remote application upon being called.

            func: the function object to be made available.
            args_r: a list of strings naming regular arguments.
            args_def: a list of (name, defaul_value) tuples naming
            arguments with default values.
            args_var: A boolean switching on or off the variable arguments
            feature.
            args_key: A boolean toggling the keyword arguments feature.
        """

        # Walk arguments and validate
        reg_args = args_r + map(lambda x: x[0], args_def)
        for i in xrange(len(reg_args)):
            arg = reg_args[i]

            # Regular arguments
            if rx_arg.match(arg) is None:
                raise TypeError("Argument format invalid")

        if name in self.xsymbols:
            # Replace old RPC call
            self.rpflist[self.xsymbols[name]] = func
        else:

            # Add new RPC call
            self.xsymbols[name] = len(self.xsymbols)
            self.rpflist.append(func)
        self._sendRPC(dumps((0, (name, args_r, args_def, args_var, args_key), {})))

    def importRPC(self, symname):
        """
            Import symname from the RPC socket.
        """

        if symname in self.isymbols:
            return self.isymbols[symname]
        return None

    def _sendRPC(self, rpcstr):
        """
            Internal function for sending RPCs.
        """
        self.send(pack('!H', len(rpcstr)) + rpcstr + RPC_MAGIC)

    # Exported events
    def onAuthFail(self):
        """
            Called upon failure of authentication or disconnection
            during authentication.
        """

    def onExport(self):
        """
            This method is called upon connecting or accepting and is
            considered the place to be to export your RPC's
        """

    def onImport(self):
        """
            Called when both RPC sockets have finished exporting there symbols.
        """

