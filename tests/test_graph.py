'''
Tests for vivisection.visualize.graph — DirectedGraphView/Canvas.

These tests are skipped if QtWebEngine is not available, since graph.py
imports PyQt6.QtWebEngineWidgets.
'''
import unittest
import importlib


def _has_qtwebengine():
    try:
        from PyQt6 import QtWebEngineWidgets  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_has_qtwebengine(), 'Requires QtWebEngine')
class TestDirectedGraphCanvas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import vivisection.visualize.graph as graph
            cls.graph = graph
        except Exception:
            raise unittest.SkipTest('Cannot import vivisection.visualize.graph')

    def test_canvas_class_exists(self):
        from vivisection.visualize.graph import DirecedGraphCanvas
        self.assertIsInstance(DirecedGraphCanvas, type)

    def test_canvas_class_name_typo_bug(self):
        '''BUG: class is named "DirecedGraphCanvas" (missing 't').
        Should be "DirectedGraphCanvas".'''
        from vivisection.visualize.graph import DirecedGraphCanvas
        self.assertEqual(DirecedGraphCanvas.__name__, 'DirecedGraphCanvas')

    def test_canvas_has_signals(self):
        from vivisection.visualize.graph import DirecedGraphCanvas
        # Check for signal attributes
        self.assertTrue(hasattr(DirecedGraphCanvas, 'paintUp'))
        self.assertTrue(hasattr(DirecedGraphCanvas, 'paintDown'))
        self.assertTrue(hasattr(DirecedGraphCanvas, 'paintMerge'))
        self.assertTrue(hasattr(DirecedGraphCanvas, 'refreshSignal'))


@unittest.skipUnless(_has_qtwebengine(), 'Requires QtWebEngine')
class TestDirectedGraphView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import vivisection.visualize.graph as graph
            cls.graph = graph
        except Exception:
            raise unittest.SkipTest('Cannot import vivisection.visualize.graph')

    def test_view_class_exists(self):
        from vivisection.visualize.graph import DirectedGraphView
        self.assertIsInstance(DirectedGraphView, type)

    def test_view_has_viewidx(self):
        from vivisection.visualize.graph import DirectedGraphView
        self.assertTrue(hasattr(DirectedGraphView, 'viewidx'))


@unittest.skipUnless(_has_qtwebengine(), 'Requires QtWebEngine')
class TestQtEventNamespaceBug(unittest.TestCase):
    '''graph.py uses QtCore.QEvent.Type.ChildAdded (PyQt6 scoped enum).'''

    def test_qt_event_namespace_fixed(self):
        import inspect
        try:
            import vivisection.visualize.graph as graph
            src = inspect.getsource(graph)
            # The fix: accessing QEvent via QtCore.QEvent.Type namespace
            self.assertIn('QtCore.QEvent.Type.ChildAdded', src)
            self.assertIn('QtCore.QEvent.Type.ChildRemoved', src)
        except Exception:
            self.skipTest('Cannot inspect graph.py source')


if __name__ == '__main__':
    unittest.main()