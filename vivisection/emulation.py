import envi
import time
import logging
import vivisect
import collections
import envi.exc as e_exc
import vivisect.exc as v_exc
import visgraph.pathcore as vg_path
import visgraph.graphcore as vg_graph
import vivisect.impemu.monitor as viv_monitor

logger = logging.getLogger(__name__)


class DaybreakMonitor(viv_monitor.AnalysisMonitor):
    def __init__(self, vw, fva, trackPointers=False, stopAtModuleBreak=True):
        viv_monitor.AnalysisMonitor.__init__(self, vw, fva)
        self.trackPointers = trackPointers
        self.valist = []
        self.strings = []
        self.imports = []
        self.functions = []
        self.dynbranches = {}
        self.immediates = collections.defaultdict(list)
        self.stack = [(fva, fva)]
        self.byfunc = collections.defaultdict(collections.defaultdict)
        self.stopAtModuleBreak = stopAtModuleBreak

        self.graph = vg_graph.HierGraph()
       
    def checkIfInteresting(self, emu, op, vals):
        out = {}

        if vals is None:
            return False

        if type(vals) == int:
            vals = [vals]
        #print("checkIfInteresting: %r" % vals)

        for val in vals:
            if not self.vw.isValidPointer(val):
                out[val] = False
                continue

            loc = self.vw.getLocation(val)
            if loc is None:
                #return False

                if self.vw.isValidPointer(val) and self.vw.isProbablyString(val):
                    self.addString(op.va)
                    return True
                    out[val] = True

                if self.vw.isValidPointer(val) and self.vw.isProbablyUnicode(val):
                    item = (op.va, val, self.vw.readMemory(val, 30))
                    self.addUnicode(item)
                    return True
                    out[val] = True
                out[val] = False
                continue

            lva, lsz, ltype, ltinfo = loc
            if ltype == vivisect.LOC_IMPORT:
                item = (op.va, val, ltinfo)
                out[val] = self.addImport(item)
                continue

            if ltype == vivisect.LOC_STRING:
                self.addString(op.va, val)
                out[val] = True
                continue

            elif ltype == vivisect.LOC_UNI:
                self.addUnicode(op.va, val)
                out[val] = True
                continue


            out[val] = False

        return out

    def addImport(self, item):
        print("Adding Import: %r" % item)
        va = item[0]
        if item not in self.imports:
            self.imports.append(item)
            curf = self.byfunc[self.getCurFunc()]
            imps = curf.get('imports')
            if imps is None:
                imps = {}
                curf['imports'] = imps
            imps[va] = item
            return True

    def addString(self, va, val):
        string = self.vw.readMemString(val)
        string = string.decode('utf-8')
        item = (va, val, string)
        print("Adding String: 0x%x->0x%x (%r)" % item)
        if item not in self.strings:
            self.strings.append(item)
            curf = self.byfunc[self.getCurFunc()]
            strs = curf.get('strings')
            if strs is None:
                strs = {}
                curf['strings'] = strs
            strs[va] = item
            return True
        return False

    def addUnicode(self, va, val):
        string = self.vw.readMemString(val, wide=True)
        string = string.decode('utf-16le')
        item = (va, val, string)
        print("Adding Unicode: 0x%x->0x%x (%r)" % item)
        if item not in self.strings:
            self.strings.append(item)
            curf = self.byfunc[self.getCurFunc()]
            strs = curf.get('strings')
            if strs is None:
                strs = {}
                curf['strings'] = strs
            strs[va] = item
            return True
        return False

    def addDynBranch(self, starteip, op):
        self.dynbranches[starteip] = op
        print("Adding Dynamic Branch: 0x%x (%r)" % (starteip, op))
        curf = self.byfunc[self.getCurFunc()]
        dynbrs = curf.get('dynbranches')
        if dynbrs is None:
            dynbrs = {}
            curf['dynbranches'] = dynbrs
        dynbrs[starteip] = op

    def addImmediate(self, immediate, starteip):
        self.immediates[immediate].append(starteip)
        curf = self.byfunc[self.getCurFunc()]
        imms = curf.get('immediates')
        if imms is None:
            imms = collections.defaultdict(list)
            curf['immediates'] = imms
        imms[immediate].append(starteip)

    def addFunction(self, funcva):
        self.functions.append(funcva)
        curf = self.byfunc[self.getCurFunc()]
        funcs = curf.get('functions')
        if funcs is None:
            funcs = []
            curf['functions'] = funcs
        funcs.append(funcva)

    def prehook(self, emu, op, starteip):
        self.valist.append(starteip)
        self.starteip = starteip

        funcva = self.vw.getFunction(starteip)
        if funcva not in self.functions:
            self.addFunction(funcva)

        #print('0x%x: (%r #%d)\t\t%r' % (starteip, funcva, len(self.functions), op))
        if op.iflags & (envi.IF_CALL | envi.IF_BRANCH):
            # check for dynamic branches
            branches = op.getBranches() # no emu usage, kinda defeats the purpose
            print("checking branches: %r" % repr([hex(x) for x,y in branches]))
            if op.iflags & envi.IF_CALL and len(branches) == 1  or\
                op.iflags & envi.IF_BRANCH and not len(branches):
                    self.addDynBranch(starteip, op)

        try:
            for oidx, oper in enumerate(op.opers):
                tva = emu.getOperAddr(op, oidx)
                tgtval = emu.getOperValue(op, oidx)
                self.checkIfInteresting(emu, op, tva)
                self.checkIfInteresting(emu, op, tgtval)

                if tgtval is None:
                    continue

                if type(tgtval) == int:
                    tgtval = [tgtval]

                for val in tgtval:
                    if not self.vw.isValidPointer(val) or self.trackPointers:
                        self.addImmediate(val, starteip)
        except:
            logger.warning("exception at 0x%x", starteip, exc_info=1)

    
    def posthook(self, emu, op, endeip):
        if self.vw.getFunction(self.starteip) != self.vw.getFunction(endeip):
            # something happened
            pass
        if op.isCall():
            self.stack.append((self.starteip, endeip))
            print("  " * len(self.stack) + "Call:->  %x\t"%(endeip) )#+ (('\n    %%%ds'%(2*len(self.stack)))%'').join(["%x->%x" % (x,y) for x,y, in self.stack]))

        if op.isReturn():
            print("  " * len(self.stack) + "RET: ->  %x\t"%(endeip) )#+ (('\n    %%%ds'%(2*len(self.stack)))%'').join(["%x->%x" % (x,y) for x,y, in self.stack]))
            self.stack.pop()

    def getCurFunc(self):
        return self.vw.getFunction(self.starteip)

class DaybreakEmulator:
    '''
    Like a Vivisect WorkspaceEmulator that traverses beyond function boundaries
    for depth analysis.  

    Like a WorkspaceEmulator: 
    * Emulator
    '''
    def __init__(self, emu, maxdepth=10, lockModule=False, notOtherNamed=True):
        self.emu = emu
        emu._func_only = False
        self.maxdepth = maxdepth
        self.lockModule = lockModule
        self.notOtherNamed = notOtherNamed

    def runFunction(self, funcva, stopva=None, maxhit=None, maxloop=None):
        realself = self
        self = self.emu
        self.funcva = funcva
        vw = self.vw  # Save a dereference many many times
        self.startmm = self.getMemoryMap(funcva)
        '''
        This is a utility function specific to WorkspaceEmulation (and impemu) that
        will emulate, but only inside the given function.  You may specify a stopva
        to return once that location is hit.
        '''

        # Let the current (should be base also) path know where we are starting
        vg_path.setNodeProp(self.curpath, 'bva', funcva)
        hits = {}
        todo = [(funcva, self.getEmuSnap(), self.path)]

        while len(todo):
            #print("TODO: %r" % [(hex(va)) for va, esnap, cp in todo])

            va, esnap, self.curpath = todo.pop()

            self.setEmuSnap(esnap)

            self.setProgramCounter(va)

            # Check if we are beyond our loop max...
            if maxloop is not None:
                lcount = vg_path.getPathLoopCount(self.curpath, 'bva', va)
                if lcount > maxloop:
                    continue

            while True:

                starteip = self.getProgramCounter()

                if not vw.isValidPointer(starteip):
                    break

                if starteip == stopva:
                    return

                # Check straight hit count...
                if maxhit is not None:
                    h = hits.get(starteip, 0)
                    h += 1
                    if h > maxhit:
                        break
                    hits[starteip] = h

                # If we ran out of path (branches that went
                # somewhere that we couldn't follow)?
                if self.curpath is None:
                    break

                try:
                    # FIXME unify with stepi code...
                    op = self.parseOpcode(starteip)
                    self.op = op
                    if self.emumon:
                        try:
                            self.emumon.prehook(self, op, starteip)
                        except v_exc.BadOpBytes as e:
                            logger.debug(str(e))
                            break
                        except v_exc.BadOutInstruction as e:
                            logger.debug(str(e))
                            pass
                        except Exception as e:
                            logger.warning("Emulator prehook failed on fva: 0x%x, opva: 0x%x, op: %s, err: %s", funcva, starteip, str(op), str(e))

                        if self.emustop:
                            return

                    # if we are going to follow the call, we need an anchor to
                    # continue this codepath.
                    if op.iflags & envi.IF_CALL and not self._func_only:
                        fallthruva = starteip + len(op)
                        tgtva = None
                        for bva, bflags in op.getBranches(self):
                            if bva == fallthruva or bflags & envi.BR_DEREF:
                                continue
                            tgtva = bva

                        # FIX: if we call a thunk, the current path is done... add anyway.
                        # we are going to take the call. add fallthruva to todo.
                        #if tgtva is not None:
                        esnap = self.getEmuSnap()
                        bpath = self.getBranchNode(self.curpath, fallthruva)
                        #print("0x%x:  %r.  appending todo." % (op.va, op))
                        todo.append((fallthruva, esnap, bpath))

                    # Execute the opcode
                    self.executeOpcode(op)
                    vg_path.getNodeProp(self.curpath, 'valist').append(starteip)

                    endeip = self.getProgramCounter()

                    if self.emumon:
                        try:
                            self.emumon.posthook(self, op, endeip)
                        except v_exc.BadOpBytes as e:
                            logger.debug(str(e))
                            break
                        except v_exc.BadOutInstruction as e:
                            logger.debug(str(e))
                            pass
                        except Exception as e:
                            logger.warning("funcva: 0x%x opva: 0x%x:  %r   (%r) (in emumon posthook)", funcva, starteip, op, e)

                        if self.emustop:
                            return

                    iscall = bool(op.iflags & envi.IF_CALL)
                    if iscall:
                        # is endeip in a different module?  If so, set _func_only
                        orig_func_only = self._func_only 
                        tgtva, tgtsz, tgtprm, tgtfn = self.getMemoryMap(endeip)

                        # if lockModule, keep all emulation within this named file
                        # if notOtherNamed, don't emulate into another named file 
                        #   (ie. emulation into anonymous modules is fine).
                        if (realself.lockModule and tgtfn != self.startmm[vivisect.MAP_FNAME])\
                                or (realself.notOtherNamed and tgtfn not in ('', self.startmm[vivisect.MAP_FNAME])):
                            # if we are at the edge of our depth... set _func_only to stop descent.
                            self._func_only = True
                            logger.info("Skipping call to 0x%x (out of bounds)", endeip)

                        self.checkCall(starteip, endeip, op)
                        self._func_only = orig_func_only

                    if self.emustop:
                        return

                    # If it wasn't a call, check for branches, if so, add them to
                    # the todo list and go around again...
                    if not iscall:
                        blist = self.checkBranches(starteip, endeip, op)
                        if len(blist):
                            # pc in the snap will be wrong, but over-ridden at restore
                            esnap = self.getEmuSnap()
                            for bva, bpath in blist:
                                # TODO: hook things like error(...) when they have a param that indicates to
                                # exit. Might be a bit hairy since we'll possibly have to fix up codeblocks
                                if self.vw.isNoReturnVa(op.va):
                                    vg_path.setNodeProp(self.curpath, 'cleanret', False)
                                    logger.debug("no ret va on branch!")
                                    continue

                                #print("not iscall and branch, adding todo: %x" % bva)
                                todo.append((bva, esnap, bpath))
                            break

                    # If we enounter a procedure exit, it doesn't
                    # matter what EIP is, we're done here.
                    if op.iflags & envi.IF_RET:
                        vg_path.setNodeProp(self.curpath, 'cleanret', True)
                        logger.debug("returning!")
                        break

                    if self.vw.isNoReturnVa(op.va):
                        vg_path.setNodeProp(self.curpath, 'cleanret', False)
                        break

                except envi.BadOpcode:
                    logger.debug("BadOpcode!")
                    break
                except envi.UnsupportedInstruction as e:
                    if self.strictops:
                        logger.debug('runFunction failed: unsupported instruction: 0x%08x %s', e.op.va, e.op.mnem)
                        break
                    else:
                        logger.debug('runFunction continuing after unsupported instruction: 0x%08x %s', e.op.va, e.op.mnem)
                        self.setProgramCounter(e.op.va + e.op.size)
                except v_exc.BadOutInstruction as e:
                    logger.debug(str(e))
                    break
                except Exception as e:
                    if self.emumon is not None and not isinstance(e, e_exc.BreakpointHit):
                        self.emumon.logAnomaly(self, starteip, str(e))

                    break  # If we exc during execution, this branch is dead.


def getFuncRecon(vw, funcva, maxhit=1):
    '''
    Emulate through function and subfunction(s) to gather context info
    '''
    starttime = time.time()
    if type(funcva) in (str, bytes):
        funcva = vw.parseExpression(funcva)

    arch = envi.ARCH_DEFAULT
    loc = vw.getLocation(funcva)
    if loc:
        arch = loc[vivisect.L_TINFO] & 0xffff0000

    emu = vw.getEmulator(va=funcva, arch=arch)

    emumon = DaybreakMonitor(vw, funcva)
    emu.setEmulationMonitor(emumon)
    demu = DaybreakEmulator(emu)
    demu.runFunction(funcva, maxhit=maxhit)
    stoptime = time.time()
    vw.vprint("DONE: %.3f secs" % (stoptime-starttime))

    return emu, emumon


