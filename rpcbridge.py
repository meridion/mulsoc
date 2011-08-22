# RPC Bridge for multi-process systems in Python
"""
    Forked Remote Procedure Call Bridge

    This library provides a tool for forking processes while maintaining
    easy communication between those processes. Every process partaking in
    an RPC Bridge will be able to call functions within the other process
    as easy as calling functions native to the process.
"""

from socket import socketpair, error as socket_error
from mulsoc import ManagedSocket
from os import fork, waitpid
from errno import EINTR
from struct import pack, unpack, calcsize

RPC_ARG_STR, RPC_ARG_INT = range(2)
RPC_HEADSIZE = calcsize('II')
RPC_ARGSIZE = calcsize('Ii')
del calcsize

class RemoteProcedureCall(object):
    """
        Class used by the RPC bridge, to call across processes.
    """

    def __init__(self, rpcbridge, code, args):
        """
            'code' represents the call's identifier.
            'args' represents the number of arguments the call expects.
            A value of None means the call has variable arguments.
        """

        self.rpcbridge = rpcbridge
        self.code = code
        self.args = args

    def __call__(self, *argv):
        """
            Execute an RPC call.
        """

        if self.args is not None:
            if len(argv) != self.args:
                raise TypeError("Expecting %i arguments, not %i" %
                    (self.args, len(argv)))

        for i in range(len(argv)):
            t = type(argv[i])
            if t is not int and t is not str:
                raise TypeError("Argument %i has type '%s'" % (i, repr(t)))

        # Prepare Call Request
        crq = pack('II', self.code, len(argv))
        for a in argv:
            if type(a) is str:
                crq += pack('Ii', RPC_ARG_STR, len(a))
                crq += a
            else:
                crq += pack('Ii', RPC_ARG_INT, a)

        # Send call to other process
        self.rpcbridge.send(crq)

class ForkedRPCBridge(ManagedSocket):
    """
        This class represents an RPC bridge between two forked processes.
        Instantiating this class will fork() your process and return to both
        the master and slave, after instantiating the 2 processes can
        communicate with eachother through calling functions registered in
        the RPC bridge, the only restriction given here is that the arguments
        should either be integers or strings. Furthermore it is not possible
        to return values, since all RPCs are asynchronous.
        Note: The process that creates the RPC bridge always becomes the
            master of the bridge.
    """

    def __init__(self, muxer, **args):
        """
            Any keyword arguments passed to __init__ will be forwarded to
            the master and slave process, in the onMaster and onSlave calls.
            The keyword arguments may contain any regular python object.
        """

        master, slave = socketpair()

        self.rpc = []
        self.curhead = None
        self.curarg = None
        self.curargv = []
        self.stream = ''

        self.onPreFork()
        try:
            self.mode = fork()
        except Exception, e:
            master.close()
            slave.close()
            raise e

        if self.mode == 0:
            master.close()
            del master
            ManagedSocket.__init__(self, muxer, (slave,), ('', 0))
            self.onSlave(**args)
        else:
            slave.close()
            del slave
            ManagedSocket.__init__(self, muxer, (master,), ('', 0))
            self.onMaster(**args)

    def onRecv(self, data):
        """
            Handle call requests coming from the other end of the bridge.
        """
        self.stream += data
        while self.handleStream(): pass

    def handleStream(self):
        """
            Handle pending RPC stream.
        """

        if self.curhead is None:
            if len(self.stream) < RPC_HEADSIZE:
                return False
            self.curhead = unpack('II', self.stream[:RPC_HEADSIZE])
            self.stream = self.stream[RPC_HEADSIZE:]

        code, args = self.curhead

        while True:

            # Perform actual call
            if len(self.curargv) == args:
                argv = tuple(self.curargv)
                self.rpc[code](*argv)
                self.curhead = None
                self.curargv = []
                return True

            # Process string component
            if self.curarg is not None:
                length, curstr = self.curarg
                addlen = min(length - len(curstr), len(self.stream))
                curstr += self.stream[:addlen]
                self.stream = self.stream[addlen:]

                if len(curstr) == length:
                    self.curarg = None
                    self.curargv.append(curstr)
                    continue
                else:
                    self.curarg = (length, curstr)
                    return False

            # Process argument headers / integer arguments
            if len(self.stream) >= RPC_ARGSIZE:
                type, value = unpack('Ii', self.stream[:RPC_ARGSIZE])
                self.stream = self.stream[RPC_ARGSIZE:]

                if type == RPC_ARG_INT:
                    self.curargv.append(value)
                    continue
                else:
                    self.curarg = (value, '')
                    continue

        return False

    def onDisconnect(self):
        """
            Handles calling on***Lost() functions.
        """
        if self.mode:
            self.onSlaveLost()
        else:
            self.onMasterLost()

    def waitSlave(self):
        """
            Wait for the slave to complete shutdown.
        """

        if not self.mode:
            return

        while True:
            try:
                waitpid(self.mode, 0)
                break
            except OSError, e:
                if e.errno != EINTR:
                    raise e
                continue

    def registerRPC(self, call, args = None):
        """
            This function registers a call in the RPC Bridge.

            It returns a function that should be used to call the function
            on the other side of the bridge.
        """

        rpc = RemoteProcedureCall(self, len(self.rpc), args)
        self.rpc.append(call)
        return rpc

    def onPreFork(self):
        """
            This function should be overidden and used to register any
            RPC calls, just before the fork() will occur, afterwards those
            calls can be used to communicate with eachother.
        """

    def onMaster(self):
        """
            Called in the process that has become the master of the bridge.
        """

    def onSlave(self):
        """
            Called in the process that has become the slave of the bridge.
        """

    def onMasterLost(self):
        """
            Called when the connection to the master process has been lost.
        """

    def onSlaveLost(self):
        """
            Called when the connection to the slave process has been lost.

            The master should call waitSlave() at the end of this function
            in order to clean up the zombie process that is likely to appear
            soon after this call.
        """

