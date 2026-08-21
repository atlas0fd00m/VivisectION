"""Tests for the PyQt5/PyQt6 dual-version compatibility shim.

Run headlessly (no display required).  These tests validate the
``vivisection.qt._qt_compat`` module against whichever Qt binding is
installed.  Per project guidance the GUI path is PyQt6; PyQt5 remains a
fallback and is tested only where both are installed.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest

import vivisection.qt._qt_compat as compat


class TestBindingDetection:
    """The shim must detect exactly one Qt binding."""

    def test_pyqt_ver_is_valid(self):
        assert compat._pyqt_ver in ('5', '6')

    def test_version_flags_are_bool(self):
        assert isinstance(compat.PyQt5_available, bool)
        assert isinstance(compat.PyQt6_available, bool)
        assert compat.PyQt5_available or compat.PyQt6_available


class TestModuleExports:
    """All names the consumers (graph.py / plugin.py) import must exist."""

    REQUIRE = [
        'QtCore', 'QtGui', 'QtWidgets', 'Qt', 'pyqtSignal',
        'QApplication', 'QToolBar', 'QLabel', 'QPushButton',
        'QTextEdit', 'QWidget', 'QInputDialog', 'QPlainTextEdit',
        'QAction', 'apply_qt_exec_compat', 'QWebEngine',
    ]

    def test_all_required_exports_exist(self):
        for name in self.REQUIRE:
            assert hasattr(compat, name), f"compat missing required export {name!r}"


class TestQtCoreModule:
    def test_qtcore_has_qt_enum(self):
        assert hasattr(compat.QtCore, 'Qt')

    def test_qtcore_has_qobject(self):
        assert hasattr(compat.QtCore, 'QObject')


class TestQtGuiModule:
    def test_qtgui_has_qcursor(self):
        assert hasattr(compat.QtGui, 'QCursor')


class TestQtWidgetsModule:
    def test_qtwidgets_has_widgets(self):
        for name in ('QWidget', 'QPushButton', 'QMenu', 'QToolBar'):
            assert hasattr(compat.QtWidgets, name)


class TestQtEnumNamespace:
    """Legacy ``Qt.Xxx`` accesses used by graph.py / plugin.py must resolve."""

    def test_key_escape(self):
        assert int(compat.Qt.Key_Escape) == 16777216

    def test_shift_modifier(self):
        val = compat.Qt.ShiftModifier
        # PyQt6 flag uses .value; normalize for cross-version comparison.
        result = getattr(val, 'value', val)
        assert int(result) == 0x02000000

    def test_toolbar_area(self):
        val = compat.Qt.TopToolBarArea
        result = getattr(val, 'value', val)
        assert int(result) == 4  # TopToolBarArea = 0x4

    def test_qevent_child_added(self):
        # graph.py: evt.type() == Qt.QEvent.ChildAdded
        assert int(compat.Qt.QEvent.ChildAdded) == 68

    def test_qevent_wheel(self):
        assert int(compat.Qt.QEvent.Wheel) == 31

    def test_qevent_mouse_move(self):
        assert int(compat.Qt.QEvent.MouseMove) == 5

    def test_unknown_attr_raises(self):
        with pytest.raises(AttributeError):
            compat.Qt.DoesNotExist_XYZ_123


class TestWidgetsInstantiate:
    """Widgets must instantiate headlessly via the compat proxy."""

    def test_qpushbutton(self, qapp):
        btn = compat.QPushButton('hi')
        assert btn.text() == 'hi'

    def test_qlabel(self, qapp):
        lbl = compat.QLabel('label')
        assert lbl.text() == 'label'

    def test_qtextedit(self, qapp):
        te = compat.QTextEdit()
        te.setPlainText('hello')
        assert te.toPlainText() == 'hello'

    def test_qplaintextedit(self, qapp):
        pte = compat.QPlainTextEdit()
        pte.setPlainText('x')
        assert pte.toPlainText() == 'x'

    def test_toolbar(self, qapp):
        tb = compat.QToolBar()
        assert tb is not None


class TestExecCompat:
    """QMenu must have both .exec() and .exec_() aliases."""

    def test_qmenu_has_both(self, qapp):
        compat.apply_qt_exec_compat()
        m = compat.QtWidgets.QMenu
        assert hasattr(m, 'exec')
        assert hasattr(m, 'exec_')


class TestSignals:
    def test_pyqt_signal_decorates(self):
        from PyQt6.QtCore import QObject
        from PyQt6.QtCore import pyqtSignal as P6S

        class Emitter(QObject):
            emitted = P6S(int)

        e = Emitter()
        assert hasattr(e, 'emitted')
