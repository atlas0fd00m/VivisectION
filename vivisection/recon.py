'''
try to emulate starting from the current function and grab all strings referenced and imports and named functions called.
'''
import itertools

import IPython.core as IPc
df = IPc.formatters.DisplayFormatter()
ptf = df.formatters['text/plain']
ptf.for_type(int, lambda n, p, cycle: p.text("0x%x" % n))

from vivisection.emulation import *

# TODO: add Dynamic Branches

import vqt.saveable as vq_save
import vivisect.qt.views as vq_views
import envi.qt.memory as e_q_memory

from PyQt5.QtWidgets import QPlainTextEdit, QWidget, QLabel, QLineEdit
from vqt.basics import HBox, VBox


def ionRecon(vw, vwgui, fva, graphonly=False, textout=False):
    emu, emumon = getFuncRecon(vw, fva)


    if not graphonly:
        # do the quick and dirty way
        if textout:
            qpte = QPlainTextEdit()
            qpte.insertPlainText("Strings:\n")
            qpte.insertPlainText(ptf(emumon.strings))
            qpte.insertPlainText("\n\nImports:\n")
            qpte.insertPlainText(ptf(emumon.imports))
            qpte.insertPlainText("\n\nFunctions:\n")
            funcs = [(va, vw.getName(va)) for va in emumon.functions if va is not None and vw.getName(va) != "sub_%.8x" % va]
            qpte.insertPlainText(ptf(funcs))
            qpte.move(10,10)
            qpte.resize(400,200)
            title = "FuncRecon(txt): 0x%x" % fva
            fname = vw.getName(fva)
            if fname not in (None, "sub_%.8x"%fva):
                title += " (%s)" % fname
            qpte.setWindowTitle(title)
            vwgui.vqDockWidget(qpte)

        else:
            # do the new widget
            frw = FuncReconWidget(vw, fva, parent=vwgui)
            frw.renderReconData()
            vwgui.vqDockWidget(frw, floating=False)

    vw.vprint('DONE')
    return emu, emumon

class FuncReconView(vq_views.VQVivTreeView): # TODO: make Saveable?
    def __init__(self, vw, vwqgui, widget=None):
        self.widget = widget
        vq_views.VQVivTreeView.__init__(self, vw, vwqgui)
        model = vq_views.VivNavModel(self._viv_navcol, parent=self, columns=self.columns)
        self.setModel(model)
        self.vqSizeColumns()

    def load(self, data):
        for stuff in data:
            self.addEntry(*stuff)

    def clear(self):
        for va in list(self._viv_va_nodes):
            self.vivDelRow(va)

    
class FrImportsView(FuncReconView):
    window_title = "Imports"
    columns = ('Address', 'Ref','Import')

    def addEntry(self, lva, ref, impstr):
        vaname = self.vw.getName(lva)
        if vaname is None:
            vaname = hex(lva)
        self.vivAddRow(lva, vaname, hex(ref), impstr)

class FrDynBrsView(FuncReconView):
    window_title = "Dynamic Branches"
    columns = ('Address', 'HostFunc', 'Dynamic Branch Opcode')

    def addEntry(self, va, opcode):
        funcva = self.vw.getFunction(va)
        hostfuncnm = self.vw.getName(funcva)
        if hostfuncnm is None:
            hostfuncnm = 'sub_%.8x' % funcva
        self.vivAddRow(va, hex(va), hostfuncnm, repr(opcode))

class FrStringsView(FuncReconView):

    window_title = 'Strings'
    columns = ('Address', 'Ref', 'String')

    def addEntry(self, lva, ref, string):
        vaname = self.vw.getName(lva)
        if vaname is None:
            vaname = hex(lva)
        self.vivAddRow(lva, vaname, hex(ref), string)
        #self.vivAddRow(va, '0x%.8x' % va, ref, string)

class FrTaintsView(FuncReconView):

    window_title = 'Taint Values'
    columns = ('Taint Value', 'TaintVal2', 'Type', 'Name')

    def addEntry(self, taintva, t2, ttype, name):
        self.vivAddRow(taintva, hex(taintva), hex(t2), ttype, name)

class FrImmediatesView(FuncReconView):

    window_title = 'Immediates'
    columns = ('Immediate', 'Refs')

    def addEntry(self, immediate, refs):
        emu = self.widget.emu
        taint = emu.getVivTaint(immediate)
        if taint:
            immrepr = emu.reprVivTaint(taint)
        else:
            immrepr = hex(immediate)

        self.vivAddRow(refs[0], immrepr, "%d:  %r" % (len(refs), [hex(ref) for ref in refs]))

class FrFuncsView(FrImportsView):
    window_title = "Functions"
    columns = ('Address', 'Functions')

    def addEntry(self, lva, string):
        self.vivAddRow(lva, hex(lva), string)

class FuncReconWidget(e_q_memory.EnviNavMixin, vq_save.SaveableWidget, QWidget):
    
    viewidx = itertools.count()

    def __init__(self, vw, funcva, parent=None):
        self.vw = vw
        self.funcva = funcva

        QWidget.__init__(self, parent=parent)
        e_q_memory.EnviNavMixin.__init__(self)
        #vq_save.SaveableWidget.__init__(self)
        self.setEnviNavName('FuncRecon%d' % next(self.viewidx))

        self.exprtext = QLineEdit(parent=self)
        self.exprtext.returnPressed.connect(self.renderReconData)

        reprFuncName = vw.getName(funcva)
        if reprFuncName is None:
            reprFuncName = hex(funcva)
        self.fvalabel = QLabel("Function VA: %r" % reprFuncName, parent=self)
        self.navbox = HBox(self.fvalabel, self.exprtext)

        self.stringlist = FrStringsView(self.vw, self.vw.getVivGui())
        self.immediateslist = FrImmediatesView(self.vw, self.vw.getVivGui(), self)
        self.importslist = FrImportsView(self.vw, self.vw.getVivGui())
        self.funcslist = FrFuncsView(self.vw, self.vw.getVivGui())
        self.dynbranchlist = FrDynBrsView(self.vw, self.vw.getVivGui())
        self.taintlist = FrTaintsView(self.vw, self.vw.getVivGui())
        self.exprtext.setText(hex(funcva))

        self.mainbox = VBox()
        self.mainbox.addLayout(self.navbox)
        self.mainbox.addWidget(self.stringlist)
        self.mainbox.addWidget(self.importslist)
        self.mainbox.addWidget(self.funcslist)
        self.mainbox.addWidget(self.immediateslist)
        self.mainbox.addWidget(self.dynbranchlist)
        self.mainbox.addWidget(self.taintlist)
        self.setLayout(self.mainbox)

    def clear(self):
        self.stringlist.clear()
        self.importslist.clear()
        self.funcslist.clear()
        self.immediateslist.clear()

    def renderReconData(self, emu=None, emumon=None):
        self.clear()
        self.funcva = self.vw.parseExpression(self.exprtext.text())

        if None in (emu, emumon):
            emu, emumon = getFuncRecon(self.vw, self.funcva)

        # make these available to the FuncReconViews
        self.emu = emu
        self.emumon = emumon

        self.setWindowTitle("%s (%d instrs)" % (self.getEnviNavName(), len(emumon.valist)))

        print("\n\nstrings:\n%r" % emumon.strings)
        print("\n\nimports:\n%r" % emumon.imports)
        print("\n\nfuncslist:\n%r" % emumon.functions)
        print("\n\nimmediates:\n%r" % emumon.immediates)
        print("\n\ndynbranches:\n%r" % emumon.dynbranches)
        self.stringlist.clear()
        self.stringlist.load(emumon.strings)
        
        self.importslist.clear()
        self.importslist.load(emumon.imports)

        self.funcslist.clear()
        funcs = [(va, self.vw.getName(va)) for va in emumon.functions if va is not None and self.vw.getName(va) != "sub_%.8x" % va]
        self.funcslist.load(funcs)
        
        self.immediateslist.clear()
        self.immediateslist.load(tuple(emumon.immediates.items()))

        dynbrs = list(emumon.dynbranches.items())
        dynbrs.sort()
        self.dynbranchlist.clear()
        self.dynbranchlist.load(dynbrs)

        #taints = [(tva, tva2, ttype, emu.reprVivTaint(tva2,ttype,idx)) for tva, (tva2, ttype, idx)  in emu.taints.items()]
        taints = []
        for tva, (tva2, ttype, idx) in emu.taints.items():
            taints.append((tva, tva2, ttype, emu.reprVivTaint((tva2,ttype,idx))))
        taints.sort()
        self.taintlist.clear()
        self.taintlist.load(taints)


if globals().get('vw') and globals.get('args'):
    fva = vw.parseExpression(args[-1])
    ionRecon(vw, vwgui, fva)


