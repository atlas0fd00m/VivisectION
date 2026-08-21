"""Shared fixtures for VivisectION tests."""
import os
import sys

# Ensure the repo root is importable so ``vivisection`` resolves.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)

# Force headless Qt for any GUI tests.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest


@pytest.fixture(scope='session')
def qapp():
    """Session-scoped QApplication singleton for headless Qt testing."""
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication(['-platform', 'offscreen'])
    return app


@pytest.fixture(autouse=True)
def _qt_cleanup(qapp):
    """Process pending Qt events between tests."""
    yield
    qapp.processEvents()
