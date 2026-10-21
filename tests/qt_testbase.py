'''
qt_testbase.py - shared QApplication singleton helper for GUI tests.

VivisectION / vqt touch Qt widgets at import time, which requires a
``QApplication`` to exist.  This helper ensures exactly one ``QApplication``
is created for the lifetime of the test-process and hands it out to any
test that asks for it via :func:`getQApp`.
'''
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from unittest.mock import MagicMock

# conftest has already set the offscreen platform by the time this
# module is imported during test collection, but be defensive in case it
# is imported standalone.
try:
    from PyQt6.QtWidgets import QApplication
except Exception:  # pragma: no cover - exercised when Qt is missing
    QApplication = None

_QAPP = None


def getQApp():
    '''
    Return a process-wide ``QApplication`` singleton.

    If Qt is not available (``QApplication is None``) this returns ``None``
    so callers can short-circuit / skip GUI dependent code paths.
    '''
    global _QAPP
    if QApplication is None:
        return None
    if _QAPP is None:
        inst = QApplication.instance()
        if inst is None:
            _QAPP = QApplication([])
        else:
            _QAPP = inst
    return _QAPP


def ensureQApp():
    '''Like :func:`getQApp` but raises ``unittest.SkipTest`` if Qt is missing.'''
    import unittest
    qapp = getQApp()
    if qapp is None:
        raise unittest.SkipTest('Qt/QApplication unavailable')
    return qapp