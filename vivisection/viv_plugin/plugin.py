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

import vivisection.recon as ionRecon
import vivisection.analyze as ionAnal
import vivisection.demangle as ionDemangle
import vivisection.viv_plugin.share as ionShare

import vqt.common as vcmn

#from PyQt5.QtWidgets import QToolBar, QLabel, QPushButton, QTextEdit, QWidget, QInputDialog, QPlainTextEdit
from PyQt5 import QtCore
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from vqt.main import idlethread
from vqt.basics import VBox
from vqt.common import ACT

import logging

logger = logging.getLogger(__name__)


# uncomment to tell IPython to display ints as hex:
#import IPython.core as IPc
#df = IPc.formatters.DisplayFormatter()
#ptf = df.formatters['text/plain']
#ptf.for_type(int, lambda n, p, cycle: p.text("0x%x" % n))



def demangleNameAtVa(vw, va):
    '''
    Demangle string at a given address.
    ionDemangle requires Internet access (Access to demangler.com)
    '''
    curnm = vw.getName(va)
    if curnm is None:
        vprint(vw, "demangleNameAtVa(0x%x) -> No name found" % va)
        return

    newnm = ionDemangle.demangle(curnm)
    if newnm != curnm:
        if curnm.endswith("_%.8x" % va) and not newnm.endswith("_%.8x" % va):
            newnm += ("_%.8x" % va)

        vprint(vw, "%r  !=  %r   -> Updating" % (curnm, newnm))
        vw.makeName(va, newnm)
    else:
        vprint(vw, "response from demangle.com: %r" % (newnm))

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
    string = vw.readMemString(va, maxsz, bool(ltype==vivisect.LOC_UNI))
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
            menu.addAction('Function Recon',   ACT(ionRecon.ionRecon, vw, vw.getVivGui(), va))
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

def selectFindStringsParms(vw):
    
    dynd = vcmn.DynamicDialog('Find Pointers Dialog', parent=vw.getVivGui())

    try:
        dynd.addIntHexField("minlen", dflt=5, title="Min String Length")
        dynd.addComboBox("full", ["No", "Yes"], dfltidx=0, title="ALL Memory (ignore other fields)")
        mmaps = vw.getMemoryMaps()
        options = [(mmva, "0x%x: %s" % (mmva, mmnm)) for mmva, mmsz, _, mmnm in mmaps]
        mmaprev = {s:mmva for mmva, s in options}

        dynd.addComboBox("startmap", [mnm for mmva, mnm in options], title="Starting Map")
        dynd.addComboBox("stopmap", [mnm for mmva, mnm in options], title="Ending Map")

        dynd.addIntHexField('startva', dflt=hex(0), title='Start Address')
        dynd.addIntHexField('stopva', dflt=hex(0), title='Stop Address ')
        dynd.addComboBox("apply", ["No", "Yes"], dfltidx=0, title="Apply Strings")
        dynd.addComboBox("unistrs", ["ASCII", "UTF16LE"], dfltidx=0, title="String Type")

    except Exception as e:
        logger.warning("ERROR BUILDING DIALOG!", exc_info=1)

    results = dynd.prompt()

    ok =  len(results) != 0
    if ok:
        mapstart = mmaprev[results.get('startmap')]
        mapstop = mmaprev[results.get('stopmap')]
        stopmap = vw.getMemoryMap(mapstop)
        mapstopva = stopmap[0] + stopmap[1]

        startva = results.get('startva')
        stopva = results.get('stopva')
        minlen = results.get('minlen')
        full = (results.get('full') == "Yes")
        apply = (results.get('apply') == "Yes")
        unistrs = (results.get('unistrs') == "UTF16LE")
        return ok, (minlen, mapstart, mapstopva, startva, stopva, full, apply, unistrs)
    return False, None


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
        #self.daemon = ionShare.shareWorkspace(vw)

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

    def findStrings(self, vw):
        '''
        ION GUI portions of findStrings
        TODO:  Add "Dictionary" option which only selects strings that show up in some dictionary
            probably including only words of size >= 3?
        '''
        vwgui = vw.getVivGui()
        # GUI SETUP
        ok, data = selectFindStringsParms(vw)
        if not ok:
            return
        
        minlen, mapstart, mapstop, memstart, memstop, full, apply, unistrs = data
        
        if full:
            memranges = ()
            print("memranges1: %r" % repr(memranges))
        elif 0 in (memstart, memstop):
            memstart = mapstart
            memstop = mapstop
            memranges = ((memstart, memstop),)
            print("memranges2: %r" % repr(memranges))
        else:
            memranges = ((memstart, memstop),)
            print("memranges3: %r" % repr(memranges))

        strvas, ustrvas = ionAnal.findStrings(vw, minlen, memranges=memranges, apply=apply, unistrs=unistrs)

        if apply:
            print("apply: yes")
            for strva in strvas:
                vw.makeString(strva)
            for ustrva in ustrvas:
                vw.makeUnicode(ustrva)
                
        else:
            print("not applying")
            # pop up a window and share the strings there
            #qpte = QPlainTextEdit()

            # TODO: make this based on VivCli, or Model after VQCli/Console
            qpte = QTextEdit()
            title = "Discovered Strings:"
            qpte.setWindowTitle(title)
            
            qpte.insertPlainText("Memory Ranges:\n\t")
            if memranges:
                qpte.insertPlainText("\n\t".join(["0x%x:0x%x" % mr for mr in memranges]))

            qpte.insertPlainText("\n\nStrings:\n")
            strs = ["0x%x: %r" % (va, vw.readMemString(va).decode('utf-8')) for va in strvas]
            qpte.insertPlainText('\n'.join(strs))

            qpte.insertPlainText("\n\nUnicode:\n")
            ustrs = ["0x%x: %r" % (va, vw.readMemString(va, wide=True).decode('utf-16le')) for va in ustrvas]
            qpte.insertPlainText('\n'.join(ustrs))    # probably need to '\n'.join() here instead of ptf

            qpte.move(10,10)
            qpte.resize(400,200)
            vwgui.vqDockWidget(qpte)
        print("DONE")

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
    vwgui.vqAddMenuField('&Plugins.&Ion.&Scan for Strings', vw._ionmgr.findStrings, (vw,))

    # hook context menu
    vw.addCtxMenuHook('ion', ctxMenuHook)

