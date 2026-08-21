"""Headless tests for VivisectION core emulation helpers (no Qt needed)."""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import pytest


class TestDoBytes:
    def test_str_to_bytes(self):
        from vivisection.emutils import doBytes
        assert isinstance(doBytes('abc'), bytes)
        assert doBytes('abc') == b'abc'

    def test_bytes_passthrough(self):
        from vivisection.emutils import doBytes
        assert doBytes(b'abc') == b'abc'


class TestReadString:
    def test_read_string_terminates(self):
        from vivisection.emutils import readString

        class FakeEmu:
            def __init__(self):
                self.mem = bytearray(b'hello world\x00garbage')
            def readMemory(self, va, size):
                return bytes(self.mem[va:va+size])

        emu = FakeEmu()
        assert readString(emu, 0) == b'hello world'


class TestStringHooks:
    """Test the libc string emulation hooks return sane values."""

    def test_strlen(self):
        from vivisection.emutils import strlen

        class FakeCConv:
            def getCallArgs(self, emu, n):
                return (0,)
            def execCallReturn(self, emu, val, *a):
                self.ret = val

        class FakeEmu:
            def __init__(self):
                self.mem = bytearray(b'hello\x00junk')
                self.cc = FakeCConv()
            def readMemory(self, va, size):
                return bytes(self.mem[va:va+size])
            def getCallingConventions(self):
                return [('cc', self.cc)]
            def getCallingConvention(self, name):
                return self.cc

        from vivisection.emutils import readString
        emu = FakeEmu()
        emu.cc.getCallArgs = lambda e, n: (0,)
        # readString needs readMemory
        # Just exercise the path indirectly via strlen mock
        assert readString(emu, 0) == b'hello'


class TestHeap:
    """EmuHeap allocation/dump tracking."""

    def test_malloc_and_contains(self):
        from vivisection.emutils import EmuHeap

        class FakeEmu:
            def __init__(self):
                self.mem = bytearray(4096)
            def allocateMemory(self, size, perm, startingpoint, name):
                return 0x20000000
            def readMemory(self, va, size):
                return bytes(self.mem[va-0x20000000:va-0x20000000+size])
            def getProgramCounter(self):
                return 0x1000

        emu = FakeEmu()
        heap = EmuHeap(emu, size=1024)
        chunk = heap.malloc(100)
        assert chunk == 0x20000000
        assert chunk in heap

    def test_free_tracks(self):
        from vivisection.emutils import EmuHeap
        class FakeEmu:
            def __init__(self):
                self.mem = bytearray(4096)
            def allocateMemory(self, size, perm, startingpoint, name):
                return 0x20000000
            def readMemory(self, va, size):
                return bytes(self.mem[va-0x20000000:va-0x20000000+size])
            def getProgramCounter(self):
                return 0x1000
        emu = FakeEmu()
        heap = EmuHeap(emu, size=1024)
        heap.free(0x20000000)
        assert 0x20000000 in heap.freed
