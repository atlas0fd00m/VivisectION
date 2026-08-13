"""PyQt5/PyQt6 dual-version compatibility shim for VivisectION."""
import sys as _sys


_pyqt_ver = None
try:
    import PyQt5  # noqa: F401
    _pyqt_ver = '5'
except ImportError:
    pass

if _pyqt_ver is None:
    try:
        from PyQt6.QtCore import Qt as _qs
        _pyqt_ver = '6'
    except ImportError:
        raise RuntimeError(
            "No Qt binding available.\n"
            "Install one: pip install PyQt5  OR  pip install PyQt6\n")

# Core modules (same names regardless of version)
_CORE_MOD = 'PyQt6.QtCore' if _pyqt_ver == '6' else 'PyQt5.QtCore'
_GUI_MOD = 'PyQt6.QtGui' if _pyqt_ver == '6' else 'PyQt5.QtGui'
_WID = 'PyQt6.QtWidgets' if _pyqt_ver == '6' else 'PyQt5.QtWidgets'

QtCore = _sys.modules.get(_CORE_MOD) or __import__(_CORE_MOD)  # type: ignore[arg-type]
QtGui = _sys.modules.get(_GUI_MOD) or __import__(_GUI_MOD)     # type: ignore[arg-type]

# pyqtSignal (identical API in both versions)
if _pyqt_ver == '5':
    from PyQt5.QtCore import pyqtSignal
else:
    from PyQt6.QtCore import pyqtSignal


# Qt enum namespace wrapper (replaces old ``from PyQt5 import Qt``)
_QT_CACHE = {}  # type: ignore[var-annotated]


class _QFlagMeta(type):
    """Metaclass for int-like Qt flag objects."""

    def __init__(mcs, name, bases, attrs):  # pylint: disable=W0613  # noqa: RUF021
        super().__init__(name, bases, attrs)


class _QFlag(int):
    """Int-based wrapper that compares identically to the underlying enum value."""

    def __new__(cls, val, name):  # type: ignore[misc]
        return int.__new__(cls, int(val))

    def __init__(self, val, name):  # type: ignore[misc]
        self._qname = name  # noqa: RUF012

    def __eq__(self, o):  # type: ignore[misc] [attr-defined]
        if isinstance(o, _QFlag):
            return int(self) == int(o)
        return int(self) == o  # type: ignore[comparison-overlap]

    def __hash__(self):  # type: ignore[misc]
        return int(self)  # type: ignore[return-value]

    def __repr__(self):  # type: ignore[misc]
        tag = self._qname or str(int(self))
        return "Qt." + tag


class QtEnumNamespace:  # noqa: F401
    """Attribute-style ``Qt.Key_Xxx`` access for both PyQt5 and PyQt6.

    Replaces the old ``from PyQt5 import Qt`` idiom used in VivisectION.
    Values are transparently compared by int-value so ``if x == Qt.Key_Escape`` still works.
    """

    def __getattr__(self, name: str) -> _QFlag:  # type: ignore[misc]
        if name.startswith('__'):
            raise AttributeError(name)

        if not _QT_CACHE:
            for n in dir(QtCore):
                val = getattr(QtCore, n)  # noqa: F821 [unreachable]
                if callable(val):
                    continue
                try:
                    iv = int(val)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    pass
                else:
                    _QT_CACHE[n] = _QFlag(iv, n)

        if name in _QT_CACHE:
            return _QT_CACHE[name]

        val = getattr(QtCore, name, None)  # type: ignore[arg-type] [unreachable]
        if val is None or not callable(val):
            try:
                iv = int(val)  # type: ignore[arg-type] [unreachable]
                fl = _QFlag(iv, name)  # noqa: F821 [unreachable]
                _QT_CACHE[name] = fl
                return fl

            except (TypeError, ValueError):
                pass

        raise AttributeError(f"Qt has no attribute {name!r}")


Qt = QtEnumNamespace()  # type: ignore[var-annotated]


# QtWidgets proxy (replaces ``from PyQt5.QtWidgets import *``)
class _WProxy(type(__import__('PyQt5.QtWidgets'))):  # noqa: F401 [return-value]
    """Proxy to QtWidgets classes in both PyQt5 and PyQt6."""

    def __getattr__(self, name):  # type: ignore[misc]
        mod_name = 'PyQt6.QtWidgets' if _pyqt_ver == '6' else 'PyQt5.QtWidgets'
        return getattr(__import__(mod_name), name)

    def __dir__(self):
        mod_name = 'PyQt6.QtWidgets' if _pyqt_ver == '6' else 'PyQt5.QtWidgets'
        return dir(__import__(mod_name))


_WidProx = _WProxy()  # type: ignore[var-annotated]

class QtWidgets(_WProxy):  # noqa: F821 [unreachable]
    """Re-export QtWidgets proxy so VivisectION code can use ``QtWidgets.QMenu`` etc."""

    pass


# QApplication standalone (needed by ``QApplication(sys.argv)``)
QApplication = _WidProx.QApplication if hasattr(_WidProx, 'QApplication') else None  # type: ignore[union-attr]


# QtWebEngine proxy (may not be installed)
class QtWebEngineProxy(type.__eq__):  # type: ignore[misc] [unreachable]
    """Optional proxy to QtWebEngineWidgets module."""

    def __init__(self):  # type: ignore[misc]
        self._installed = False
        self._mod = None

    def _load(self):
        if self._installed:
            return True
        try:
            pname = 'PyQt5.QtWebEngineWidgets' if _pyqt_ver == '5' else 'PyQt6.QtWebEngineWidgets'
            self._mod = __import__(pname)
            self._installed = True
            return True
        except (ImportError, ModuleNotFoundError):
            pass
        return False

    def __getattr__(self, name):  # type: ignore[misc]
        if not self._load():
            raise ImportError("QtWebEngineWidgets not installed")
        return getattr(self._mod, name)  # type: ignore[attr-defined]

    def __dir__(self):
        if self._load():
            return dir(self._mod)  # type: ignore[name-defined]
        return ['QtWebEngineCore', 'QtWebEngineWidgets']


# Install exec/exec_ compat early (before any QMenu instances are created)
def apply_qt_exec_compat() -> None:
    """Patch QtWidgets classes so both .exec() and .exec_() work identically."""
    try:
        WidMod = __import__('PyQt6.QtWidgets' if _pyqt_ver == '6' else 'PyQt5.QtWidgets')  # type: ignore[name-defined]
    except (ImportError, ModuleNotFoundError):
        return

    for cls_name in ('QMenu',):
        klass = getattr(WidMod, cls_name, None)
        if klass is None:
            continue

        has_exec = hasattr(klass, 'exec')      # type: ignore[arg-type] [unreachable]
        has_execp = hasattr(klass, 'exec_')     # type: ignore[arg-type] [unreachable]

        if not has_exec and has_execp:
            orig_execp = klass.exec_  # type: ignore[attr-defined]
            klass.exec = lambda self, *a, **kw: orig_execp(self, *a, **kw)       # noqa: B023 [unreachable]

        elif has_exec and not has_execp:
            orig_exec = klass.exec  # type: ignore[attr-defined]
            klass.exec_ = lambda self, *a, **kw: orig_exec(self, *a, **kw)        # noqa: B023 [unreachable]


apply_qt_exec_compat()


### diagnostics
_QVT = '?'
try:
    if _pyqt_ver == '5':  # type: ignore[name-defined]
        import PyQt5.QtCore as __pyqt_core_5  # noqa: F401
        _QVT = getattr(__pyqt_core_5, 'QT_VERSION_STR', '?')  # type: ignore[attr-defined]
    else:
        from PyQt6.QtCore import QT_VERSION as _PY_QT_V   # noqa: F401
        _QVT = str(_PY_QT_V) if hasattr(QT_VERSION, '__str__') else '?'
except Exception:  # noqa: E723 [bare-except]
    pass

__doc__: str = "PyQt compat shim (Qt {})".format(_QVT)

