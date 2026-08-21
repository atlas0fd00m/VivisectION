"""PyQt5/PyQt6 dual-version compatibility shim for VivisectION.

Provides a single import point that works regardless of whether the user has
installed PyQt5 or PyQt6.  The two bindings share most APIs but differ in a
few important places, which this module normalizes:

* Qt5 exposes a top-level ``PyQt5.Qt`` module holding the ``Qt`` enum;
  Qt6 does not (enums live in ``QtCore``).  We re-export ``Qt`` as a
  lazy, int-valued namespace that works for both.
* Qt5 uses the legacy ``exec_()`` name for menu/dialog loops; Qt6 renamed
  to ``exec()``.  We patch classes so both names work.
"""
import sys as _sys


# ---------------------------------------------------------------------------
# Binding detection (PyQt6 preferred, PyQt5 fallback)
# ---------------------------------------------------------------------------
_pyqt_ver = None
try:
    import PyQt6  # noqa: F401
    _pyqt_ver = '6'
except ImportError:
    pass

if _pyqt_ver is None:
    try:
        import PyQt5  # noqa: F401
        _pyqt_ver = '5'
    except ImportError:
        raise RuntimeError(
            "No Qt binding available.\n"
            "Install one: pip install PyQt6  OR  pip install PyQt5\n")

# Version flags used by other modules for explicit branching.
PyQt5_available = _pyqt_ver == '5'
PyQt6_available = _pyqt_ver == '6'

# Core modules (same names regardless of version).
_CORE_MOD = 'PyQt6.QtCore' if _pyqt_ver == '6' else 'PyQt5.QtCore'
_GUI_MOD = 'PyQt6.QtGui' if _pyqt_ver == '6' else 'PyQt5.QtGui'
_WID_MOD = 'PyQt6.QtWidgets' if _pyqt_ver == '6' else 'PyQt5.QtWidgets'

QTCORE = __import__(_CORE_MOD, fromlist=['*'])
QTGUI = __import__(_GUI_MOD, fromlist=['*'])
QTWIDGETS = __import__(_WID_MOD, fromlist=['*'])

# Public module aliases.
QtCore = QTCORE
QtGui = QTGUI
QtWidgets = QTWIDGETS

# pyqtSignal (identical API in both versions).
pyqtSignal = QTCORE.pyqtSignal


# ---------------------------------------------------------------------------
# Qt enum namespace wrapper (replaces the old ``from PyQt5 import Qt``)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Qt enum namespace wrapper (replaces the old ``from PyQt5 import Qt``)
# ---------------------------------------------------------------------------
class QtEnumNamespace:
    """Attribute-style ``Qt.Key_*`` / ``Qt.QEvent.*`` access that works for
    both PyQt5 and PyQt6.

    PyQt5 exposes enum members *directly* on the ``Qt`` class (e.g.
    ``Qt.Key_Escape``).  PyQt6 nests members under enum types
    (``Qt.Key.Key_Escape``, ``Qt.QEvent.Type.ChildAdded``).  This namespace
    flattens those differences: for PyQt6 it resolves nested enum members for
    the requested name directly (so ``Qt.Xxx`` yields the right value), and
    it maps ``Qt.QEvent`` to an object that also exposes the ``ChildAdded`` /
    ``Wheel`` etc. *type* members via ``.Type`` so legacy call sites work.
    """

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)

        enum_src = getattr(QTCORE, 'Qt', QTCORE)

        # 1) Direct attribute on the Qt enum class (PyQt5 style).
        if hasattr(enum_src, name):
            return getattr(enum_src, name)

        # 2) QtCore module class type (QEvent, QKeySequence, ...).
        if _pyqt_ver == '5':
            val = getattr(QTCORE, name, None)
            if val is not None:
                return val
        else:
            # PyQt6: return a small wrapper for known class types whose event
            # type enum is nested (see ``QEvent``).
            if name == 'QEvent':
                return _QEventProxy()

        # 3) PyQt6 nested enum members (Qt.Key.Key_Escape).
        for n in dir(enum_src):
            if n.startswith('_'):
                continue
            try:
                enum_type = getattr(enum_src, n)
            except AttributeError:
                continue
            members = getattr(enum_type, '__members__', None)
            if members and name in members:
                return members[name]

        # 4) General QtCore class types.
        val = getattr(QTCORE, name, None)
        if val is not None:
            return val

        raise AttributeError(f"Qt has no attribute {name!r}")


class _QEventProxy:
    """Proxy over PyQt6 ``QEvent`` that flattens ``QEvent.Type.*`` members so
    legacy ``Qt.QEvent.ChildAdded`` access works."""

    def __getattr__(self, name):
        ev = getattr(QTCORE, 'QEvent')
        # Prefer a direct member, else fall back to ``QEvent.Type``.
        if hasattr(ev, name):
            return getattr(ev, name)
        return getattr(ev.Type, name)


Qt = QtEnumNamespace()


# ---------------------------------------------------------------------------
# exec / exec_ compatibility (patched lazily via a function)
# ---------------------------------------------------------------------------
def apply_qt_exec_compat():
    """Patch Qt classes so both ``.exec()`` and ``.exec_()`` work identically.

    Qt5 kept the historical ``exec_`` name (since ``exec`` was a Python
    keyword) and Qt6 renamed it to ``exec``.  We alias whichever one a given
    binding lacks so VivisectION code can use either spelling.
    """
    for cls_name in ('QMenu', 'QDialog', 'QApplication'):
        klass = getattr(QTWIDGETS, cls_name, None)
        if klass is None:
            continue

        has_exec = hasattr(klass, 'exec')
        has_exec_ = hasattr(klass, 'exec_')

        if not has_exec and has_exec_:
            orig = klass.exec_
            klass.exec = lambda self, *a, **kw: orig(self, *a, **kw)
        elif has_exec and not has_exec_:
            orig = klass.exec
            klass.exec_ = lambda self, *a, **kw: orig(self, *a, **kw)


# ---------------------------------------------------------------------------
# QtWebEngine optional proxy (may not be installed)
# ---------------------------------------------------------------------------
class QtWebEngine:
    """Lazy proxy to QtWebEngineWidgets so imports don't fail if missing."""

    _mod = None

    @classmethod
    def _load(cls):
        if cls._mod is not None:
            return True
        try:
            pname = ('PyQt6.QtWebEngineWidgets' if _pyqt_ver == '6'
                     else 'PyQt5.QtWebEngineWidgets')
            cls._mod = __import__(pname, fromlist=['*'])
            return True
        except (ImportError, ModuleNotFoundError):
            return False

    @classmethod
    def __getattr__(cls, name):
        if not cls._load():
            raise ImportError("QtWebEngineWidgets not installed")
        return getattr(cls._mod, name)


QWebEngine = QtWebEngine


# ---------------------------------------------------------------------------
# QApplication (standalone export)
# ---------------------------------------------------------------------------
QApplication = QTWIDGETS.QApplication


# ---------------------------------------------------------------------------
# Re-export commonly-used widget classes so plugin.py's import block works.
# ---------------------------------------------------------------------------
QToolBar = QTWIDGETS.QToolBar
QLabel = QTWIDGETS.QLabel
QPushButton = QTWIDGETS.QPushButton
QTextEdit = QTWIDGETS.QTextEdit
QPlainTextEdit = QTWIDGETS.QPlainTextEdit
QWidget = QTWIDGETS.QWidget
QInputDialog = QTWIDGETS.QInputDialog
# QAction lives in QtGui (Qt6) / QtWidgets (Qt5).  Resolve per binding.
QAction = getattr(QTWIDGETS, 'QAction', None) or getattr(QTGUI, 'QAction')


# ---------------------------------------------------------------------------
# Diagnostics / docs
# ---------------------------------------------------------------------------
_QVT = getattr(QTCORE, 'QT_VERSION_STR',
               str(getattr(QTCORE, 'QT_VERSION', '?')))

__doc__ = "PyQt compat shim (Qt {} / binding {})".format(_QVT, _pyqt_ver)
