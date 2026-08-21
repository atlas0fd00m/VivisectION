"""Headless tests for the VivisectION viv_plugin package under PyQt6.

The ``viv_plugin`` module wires Qt widgets into Vivisect's extension system.
These tests exercise the *importable* surface and Qt widget classes headlessly,
plus the pure helper functions that don't require a live workspace.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest


@pytest.fixture(scope='module')
def plugin_qapp():
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(['-platform', 'offscreen'])
    return app


class TestPluginImport:
    """viv_plugin.plugin must import cleanly under PyQt6."""

    def test_plugin_imports(self):
        import vivisection.viv_plugin.plugin as plug
        assert plug is not None

    def test_required_functions_exist(self):
        import vivisection.viv_plugin.plugin as plug
        for name in ('demangleNameAtVa', 'renameFullString', 'reanalyzeFunction',
                     'ctxMenuHook', 'vivExtension', 'runInteractive'):
            assert hasattr(plug, name), f"plugin missing {name!r}"


class TestIonManager:
    """IonManager config/session handling (no GUI needed)."""

    def test_ionmanager_session_add_get(self, tmp_path, monkeypatch):
        import vivisection.viv_plugin.plugin as plug

        # Point ionhome at a temp dir to avoid touching real config.
        tmp_ion = tmp_path / '.ion'
        monkeypatch.setattr(plug.e_config, 'gethomedir', lambda *a, **k: str(tmp_ion))

        class FakeVw:
            pass

        mgr = plug.IonManager(FakeVw(), autosave=False)
        mgr.addSession('abc', {'x': 1})
        assert mgr.getSession('abc') == {'x': 1}

    def test_ionmanager_get_missing_returns_none(self, tmp_path, monkeypatch):
        import vivisection.viv_plugin.plugin as plug
        tmp_ion = tmp_path / '.ion'
        monkeypatch.setattr(plug.e_config, 'gethomedir', lambda *a, **k: str(tmp_ion))
        mgr = plug.IonManager(object(), autosave=False)
        assert mgr.getSession('nope') is None

    def test_console_in_use(self, tmp_path, monkeypatch):
        import vivisection.viv_plugin.plugin as plug
        tmp_ion = tmp_path / '.ion'
        monkeypatch.setattr(plug.e_config, 'gethomedir', lambda *a, **k: str(tmp_ion))
        mgr = plug.IonManager(object(), autosave=False)
        assert mgr.isConsoleInUse() is False
        mgr.setUsingConsole(True)
        assert mgr.isConsoleInUse() is True
        mgr.resetConsoleInUse()
        assert mgr.isConsoleInUse() is False


class TestIonToolbarWidget:
    """IonToolbar must instantiate headlessly under PyQt6."""

    def test_toolbar_instantiates(self, plugin_qapp):
        import vivisection.viv_plugin.plugin as plug

        class FakeVwgui:
            def addWidget(self, w):
                pass

        class FakeVw:
            pass

        # Use the compat QToolBar subclass — instantiate with a dummy parent.
        tb = plug.IonToolbar(FakeVw(), None)
        assert tb is not None


class TestDemangleHelpers:
    """demangleNameAtVa should be guarded for missing names."""

    def test_demangle_no_name_returns(self, capsys):
        import vivisection.viv_plugin.plugin as plug

        class FakeVw:
            def getName(self, va):
                return None
            def vprint(self, *a):
                pass

        # Should not raise and should print "No name found"
        plug.demangleNameAtVa(FakeVw(), 0x1234)
        out = capsys.readouterr().out
        assert 'No name found' in out
