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

import envi
import envi.interactive as ei
import envi.config as e_config
import envi.threads as e_thread

import vivisect

import vivisection.demangle as ion_demangle
import vivisection.viv_plugin.share as ion_share


from PyQt5.QtWidgets import QToolBar, QLabel, QPushButton, QTextEdit, QWidget, QInputDialog
from PyQt5 import QtCore

from vqt.main import idlethread
from vqt.basics import VBox
from vqt.common import ACT


def demangleNameAtVa(vw, va):
    '''
    Demangle string at a given address.
    ion_demangle requires Internet access (Access to demangler.com)
    '''
    curnm = vw.getName(va)
    if curnm is None:
        vprint(vw, "demangleNameAtVa(0x%x) -> No name found" % va)
        return

    newnm = ion_demangle.demangle(curnm)
    if newnm != curnm:
        if curnm.endswith("_%.8x" % va) and not newnm.endswith("_%.8x" % va):
            newnm += ("_%.8x" % va)

        vprint(vw, "%r  !=  %r   -> Updating" % (curnm, newnm))
        vw.makeName(va, newnm)
    else:
        vprint(vw, "response from demangle.com: %r" % (newnm))

def readMemString(self, va, maxlen=0xfffffff, wide=False):
    '''
    Returns a C-style string from memory.  Stops at Memory Map boundaries, or the first NULL (\x00) byte.
    '''

    terminator = (b'\0', b'\0\0')[wide]
    for mva, mmaxva, mmap, mbytes in self._map_defs:
        if mva <= va < mmaxva:
            mva, msize, mperms, mfname = mmap
            if not mperms & envi.MM_READ:
                raise envi.SegmentationViolation(va)
            offset = va - mva

            # now find the end of the string based on either \x00, maxlen, or end of map
            end = mbytes.find(terminator, offset)

            left = end - offset
            if end == -1:
                # couldn't find the NULL byte
                mend = offset + maxlen
                cstr = mbytes[offset:mend]
            else:
                # couldn't find the NULL byte go to the end of the map or maxlen
                mend = offset + (maxlen, left)[left < maxlen]
                cstr = mbytes[offset:mend]
            return cstr

    raise envi.SegmentationViolation(va)

def renameFullString(vw, va, maxsz=200):
    '''
    Rename a string to include more of the string (up to maxsz, default=200)
    '''
    loc = vw.getLocation(va)
    if not loc:
        vprint(vw, "renameFullString(0x%x) -> No string location found" % va)
        return

    lva, lsz, ltype, ltinfo = loc
    if ltype not in (vivisect.LOC_STRING, vivisect.LOC_UNI):
        vprint(vw, "renameFullString(0x%x) -> Location *isn't* String or Unicode" % va)
        return

    curnm = vw.getName(va)
    string = readMemString(vw, va, maxsz, bool(ltype==vivisect.LOC_UNI))
    if curnm is None or not string:
        vprint(vw, "renameFullString(0x%x) -> No string/name found" % va)
        return

    string = string.decode('utf8')
    if ltype == vivisect.LOC_STRING:
        newnm = "str_%s_%.8x" % (string, va)
    else:
        newnm = "wstr_%s_%.8x" % (string, va)

    if newnm != curnm:
        vw.makeName(va, newnm)
        vprint(vw, "%r  !=  %r   -> Updating" % (repr(curnm), repr(newnm)))


### standard UI stuff
def vprint(vw, s, *args, **kwargs):
    vw.vprint(s % args)
    print(s % args)

def reanalyzeFunction(vw, va):
    vw.analyzeFunction(va)

def ctxMenuHook(vw, va, expr, menu, parent, nav, tags=None):
    '''
    Context Menu handler (adds options as we wish)
    '''
    try:
        if va == vw.getFunction(va):
            # FIXME: make shared workspace mode work correctly, then uncomment:
            #menu.addAction('SmartEmu', ACT(launchEmuShared, vw, "0x%x"%va))
            menu.addAction('SmartEmu - console', ACT(launchEmuLocal, vw, "0x%x"%va))
            menu.addAction('Reanalyze Function', ACT(reanalyzeFunction, vw, va))

        if vw.getName(va):
            # if it has a name, let's offer the option of demangling
            menu.addAction('Demangle Name', ACT(demangleNameAtVa, vw, va))
            menu.addAction('Rename String Bigger', ACT(renameFullString, vw, va))

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
        # FIXME: setting this as the server causes saving to stop working.  need to work around another method of enabling the "Follow/Lead" in the gui.  probably an upstream problem to solve.  for now, we have the console.
        #self.daemon = ion_share.shareWorkspace(vw)

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

    def resetConsoleInUse(self):
        self.console_in_use = False

    def setUsingConsole(self, state=True):
        self.console_in_use = state

def getSetupCode(vw, fvaexpr):
    '''
    Caches results in Ion config
    '''
    defcode = vw._ionmgr.config.setup_code
    defcode = defcode % fvaexpr
    fva = vw.parseExpression(fvaexpr)

    # grab cache/saved-config
    faotup = vw.getFileAndOffset(fva)
    if faotup:
        fname, fbase, foff = faotup
    else:
        fname, fbase, foff = "___LOST___", 0, fva

    # DEBUG: This is to resolve bad translation from VSnapshot to VivWorkspace and may cause problems!
    fname = vw.normFileName(fname)

    filecfg = vw._ionmgr.config.cache.getSubConfig(fname)

    # see if there's existing config for this function:
    initialcode = filecfg.get(foff, defcode)

    setup_code, ok = QInputDialog.getMultiLineText(None, 'Enter Setup Code', 'Code:', text=initialcode)
    if ok:
        print("caching code:\n%r + 0x%x:\n%r" % (fname, foff, setup_code))
        filecfg[foff] = setup_code
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
    vwgui.vqAddMenuField('&Plugins.&Ion.&Reset Console In Use', vw._ionmgr.resetConsoleInUse, ())

    # hook context menu
    vw.addCtxMenuHook('ion', ctxMenuHook)

