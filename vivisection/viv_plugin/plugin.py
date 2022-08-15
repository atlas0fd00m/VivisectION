'''
This is the Vivisect Extension component of VivisectION.

a Symnlink to this directory should be placed somewhere in your Vivisect Extensions path,
defined by the environment variable VIV_EXT_PATH and following typical pathing standards

eg.
$ export VIV_EXT_PATH=~/hacking/viv_extensions:~/work/viv_ext
$ ln -s <path_to_this_dir> ~/hacking/viv_extensions/
'''
import os
import sys
import uuid
import threading
import traceback

import envi.interactive as ei
import envi.config as e_config
import envi.threads as e_thread

import vivisection.viv_plugin.share as ion_share


from PyQt5.QtWidgets import QToolBar, QLabel, QPushButton, QTextEdit, QWidget, QInputDialog
from PyQt5 import QtCore

from vqt.main import idlethread
from vqt.basics import VBox
from vqt.common import ACT



### standard UI stuff
def vprint(vw, s, *args, **kwargs):
    vw.vprint(s % args)
    print(s % args)

def ctxMenuHook(vw, va, expr, menu, parent, nav):
    '''
    Context Menu handler (adds options as we wish)
    '''
    try:
        if va == vw.getFunction(va):
            # FIXME: make shared workspace mode work correctly, then uncomment:
            #menu.addAction('SmartEmu', ACT(launchEmuShared, vw, "0x%x"%va))
            menu.addAction('SmartEmu - console', ACT(launchEmuLocal, vw, "0x%x"%va))

    except Exception as e:
        traceback.print_exc()

class IonToolbar(QToolBar):
    def __init__(self, vw, vwgui):
        self.vw = vw
        self.vwgui = vwgui

        QToolBar.__init__(self, parent=vwgui)
        self.addWidget( QLabel('Ion tools:', parent=self) )
        self.addAction('CLI', self.cli)

    def cli(self):
        # TODO: make this and FuncEmulator 1-shot/mutex, since there can be only one (console)
        vw = self.vw
        vwgui = self.vwgui

        self.vw.clithread = threading.Thread(target=ei.dbg_interact, args=(locals(), globals()), daemon=True)
        self.vw.clithread.start()

### emulation support tools
DEFAULT_SETUPCODE = '''fva = vw.parseExpression('%s')
import vivisection.emutils as vemu
emu = vw.getEmulator(va=fva, logread=True, logwrite=True, safemem=False)
nemu = vemu.NinjaEmulator(emu, fakePEB=True, guiFuncGraphName="FuncGraph0")

args = []
nemu.setupCall(fva, args)
nemu.runStep()
'''

defconfig = {
        'termcmd': 'konsole -e <vwcmd>',
        'setup_code': DEFAULT_SETUPCODE,
        'cache': {},

        }
class IonManager:
    def __init__(self, vw, autosave=True):
        self.vw = vw
        self.sessions = {}
        self.console_in_use = False

        self.ionhome = e_config.gethomedir('.ion')

        # Load up the config
        cfgfile = os.path.join(self.ionhome, 'vivisection.json')
        self.config = e_config.EnviConfig(filename=cfgfile, defaults=defconfig, autosave=autosave)

        # share out the workspace
        # FIXME: check if connected to a VivServer and support that instead
        self.daemon = ion_share.shareWorkspace(vw)

    def addSession(self, sessid, sesstup):
        if sessid in self.sessions:
            logger.warning("IonManager:addSession refusing to add an existing session (%r).", sessid)
            return

        self.sessions[sessid] = sesstup

    def getSession(self, sessid):
        if sessid not in self.sessions:
            logger.warning("IonManager:getSession %r session does not exist.", sessid)
            return

        return self.sessions[sessid]

    def isConsoleInUse(self):
        return self.console_in_use

    def setUsingConsole(self, state=True):
        self.console_in_use = state

def getSetupCode(vw, fvaexpr):
    '''
    Caches results in Ion config
    '''
    defcode = vw._ionmgr.config.setup_code
    defcode = defcode % fvaexpr
    fva = vw.parseExpression(fvaexpr)
    initialcode = vw._ionmgr.config.cache.get(fva, defcode)

    setup_code, ok = QInputDialog.getMultiLineText(None, 'Enter Setup Code', 'Code:', text=initialcode)
    if ok:
        vw._ionmgr.config.cache.fva = setup_code
        vw._ionmgr.config.saveConfigFile()
        return setup_code
  
def launchEmuShared(vw, fvaexpr):
    # TODO: fix up Vivisect's Shared Workspace.  there are a few bugs remaining.
    #### THIS DOESN'T WORK CORRECTLY YET....
    sessid = uuid.uuid1().hex
    ctx = {}
    setup_code = getSetupCode(vw, fvaexpr)
    if setup_code is None:
        return

    ctx['setup_code'] = setup_code
    
    vw._ionmgr.addSession(sessid, ctx)
    port = vw._ionmgr.daemon.port

    termcmd = vw._ionmgr.config.termcmd #'konsole -e <vwcmd>'

    cmdsyntax = '%s -s %s %s %s' % (sys.argv[0], 'localhost', port, sessid)
    termcmd = termcmd.replace('<vwcmd>', cmdsyntax)
    os.system(termcmd)

def launchEmuLocal(vw, fvaexpr):
    # setup and popup
    setup_code = getSetupCode(vw, fvaexpr)
    if setup_code is None:
        return

    # FIXME: track and check if any other thing is using the console and pop up 
    # an error message if it is busy.

    # execute setup
    if vw._ionmgr.isConsoleInUse():
        # pop up message
        print("\n\n=== Can't use console, already in use!")
        return

    vw._ionmgr.setUsingConsole(True)
    t = threading.Thread(target=runInteractive, \
            args=(vw, fvaexpr, setup_code, globals(), locals()), daemon=True)
    t.start()

    # we can also do the external gui widget, but not until we can replace the gui mainloop with ipython

def runInteractive(vw, fvaexpr, setup_code, gbls, lcls):
    '''
    Do the interactive emulation and end with an IPython shell.
    This function is specifically to group the emulation and ipython so they
    can be run in a separate thread.
    '''
    exec(setup_code, gbls, lcls)
    ei.dbg_interact(lcls, gbls, "VivisectION Emulation.  nemu.runStep() to start.")

    # very important: Free up Console for reuse
    vw._ionmgr.setUsingConsole(False)


@idlethread
def vivExtension(vw, vwgui):
    # Add IonManager into the workspace:
    vw._ionmgr = IonManager(vw)

    # Create a toolbar and add it to the GUI
    toolbar = IonToolbar(vw, vwgui)
    vwgui.addToolBar(QtCore.Qt.TopToolBarArea, toolbar)

    # Add a menu item
    vwgui.vqAddMenuField('&Plugins.&Ion.&PrintDiscoveredStats', vw.printDiscoveredStats, ())

    # hook context menu
    vw.addCtxMenuHook('ion', ctxMenuHook)

