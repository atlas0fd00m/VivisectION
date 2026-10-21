'''
conftest.py for the VivisectION test suite.

Sets the Qt platform to ``offscreen`` so that GUI dependent imports do
not try to talk to a real display server.
'''
import os
import sys

# Force the offscreen Qt platform *before* any Qt/QPA code runs.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')