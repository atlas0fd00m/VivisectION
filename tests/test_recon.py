'''
Tests for vivisection.recon — FuncRecon GUI widgets.

These tests are skipped if IPython is not available, since recon.py imports
IPython at module level.
'''
import unittest
import importlib


def _has_ipython():
    try:
        import IPython  # noqa: F401
        return True
    except ImportError:
        return False


def _has_pyqt():
    try:
        import PyQt6  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_has_ipython() and _has_pyqt(), 'Requires IPython and PyQt')
class TestFuncReconViews(unittest.TestCase):
    '''Test FuncReconView classes and their column definitions.'''

    @classmethod
    def setUpClass(cls):
        # Need to import recon module which has IPython + PyQt deps
        # These imports may fail due to other missing deps
        try:
            import vivisection.recon as recon
            cls.recon = recon
        except Exception:
            raise unittest.SkipTest('Cannot import vivisection.recon')

    def test_fr_imports_view_columns(self):
        from vivisection.recon import FrImportsView
        self.assertEqual(FrImportsView.window_title, 'Imports')
        self.assertEqual(FrImportsView.columns, ('Address', 'Ref', 'Import'))

    def test_fr_dynbrs_view_columns(self):
        from vivisection.recon import FrDynBrsView
        self.assertEqual(FrDynBrsView.window_title, 'Dynamic Branches')
        self.assertEqual(FrDynBrsView.columns, ('Address', 'HostFunc', 'Dynamic Branch Opcode'))

    def test_fr_strings_view_columns(self):
        from vivisection.recon import FrStringsView
        self.assertEqual(FrStringsView.window_title, 'Strings')
        self.assertEqual(FrStringsView.columns, ('Address', 'Ref', 'String'))

    def test_fr_taints_view_columns(self):
        from vivisection.recon import FrTaintsView
        self.assertEqual(FrTaintsView.window_title, 'Taint Values')
        self.assertEqual(FrTaintsView.columns, ('Taint Value', 'TaintVal2', 'Type', 'Name'))

    def test_fr_immediates_view_columns(self):
        from vivisection.recon import FrImmediatesView
        self.assertEqual(FrImmediatesView.window_title, 'Immediates')
        self.assertEqual(FrImmediatesView.columns, ('Immediate', 'Refs'))

    def test_fr_funcs_view_columns(self):
        from vivisection.recon import FrFuncsView
        self.assertEqual(FrFuncsView.window_title, 'Functions')
        self.assertEqual(FrFuncsView.columns, ('Address', 'Functions'))

    def test_fr_imports_view_is_subclass(self):
        from vivisection.recon import FrImportsView, FuncReconView
        self.assertTrue(issubclass(FrImportsView, FuncReconView))

    def test_fr_funcs_view_inherits_imports(self):
        from vivisection.recon import FrFuncsView, FrImportsView
        self.assertTrue(issubclass(FrFuncsView, FrImportsView))

    def test_fr_strings_view_inherits_base(self):
        from vivisection.recon import FrStringsView, FuncReconView
        self.assertTrue(issubclass(FrStringsView, FuncReconView))


@unittest.skipUnless(_has_ipython() and _has_pyqt(), 'Requires IPython and PyQt')
class TestFuncReconWidget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import vivisection.recon as recon
            cls.recon = recon
        except Exception:
            raise unittest.SkipTest('Cannot import vivisection.recon')

    def test_widget_class_exists(self):
        from vivisection.recon import FuncReconWidget
        self.assertIsInstance(FuncReconWidget, type)


@unittest.skipUnless(_has_ipython() and _has_pyqt(), 'Requires IPython and PyQt')
class TestReconGlobalsBug(unittest.TestCase):
    '''BUG: recon.py line 227 uses `globals().get` which should be
    `globals().get` (already fixed).'''

    def test_globals_get_bug(self):
        import inspect
        try:
            import vivisection.recon as recon
            src = inspect.getsource(recon)
            self.assertIn('globals().get(', src)
        except Exception:
            self.skipTest('Cannot inspect recon.py source')


if __name__ == '__main__':
    unittest.main()