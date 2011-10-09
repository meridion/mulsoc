# mulsoc - Non-blocking IO library
"""
    Non-blocking IO library

    For anyone who wants to do some simple non-blocking development
"""

from mulsoc import SocketMultiplexer, ManagedSocket
from os import name as os_name
if os_name == 'posix':
    from rpcbridge import ForkedRPCBridge
del os_name
from events import DeferredCall, PeriodicCall, PropagatingCall
from netrpc import NetRPCSocket

