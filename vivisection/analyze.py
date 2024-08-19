import string
import logging
from envi.exc import *


logger = logging.getLogger(__name__)


def findStrings(vw, minlen=5, memranges=(), unistrs=False):
    '''
    Search for Strings and Unicode Strings

    For granular control, we either do ASCII or Unicode strings
    '''
    strs = []
    unis = []
    printables = string.printable.encode('utf-8')
    
    for mmva, mmsz, mmperm, mmname in vw.getMemoryMaps():
        # first decide if and what of this map we're analyzing...
        skip = True
        startva = mmva
        stopva = mmva + mmsz
        if memranges:
            for rstartva, rstopva in memranges:
                #if not rstartva <= mmva < rstopva:
                if rstopva < mmva:
                    pass

                elif rstartva > mmva+mmsz:
                    pass
                
                else:
                    # this memrange applies to this memory map
                    skip = False
                    if rstartva > startva:
                        startva = rstartva 

                    if rstopva < stopva:
                        stopva = rstopva

        if skip:
            continue

        # Now we get to work
        logger.warning("findStrings: %x->%x", startva, stopva)
        tva = startva
        while tva < stopva:
            # Go String Hunting

            # first look for ASCII strings
            count = 0
            ucount = 0
            if not unistrs:

                bad = False
                tstr = vw.readMemString(tva)

                for b in tstr:
                    if b not in printables:
                        bad = True
                        break

                    count += 1

                if not bad and count == len(tstr) and count >= minlen:
                    strs.append(tva) # we got a good one
                    logger.warning("found string: %x: %r", tva, tstr)                


            else:
                # next check for unicode strings
                ubad = False
                tustr = vw.readMemString(tva, wide=True)

                if len(tustr) < 2*minlen:
                    ubad = True
                elif len(tustr) % 2:
                    # WORKAROUND for Viv's Wide String Terminator bug. should just be ubad=True
                    try:
                        if vw.readMemory(tva+len(tustr), 3) != b'\0\0\0':
                            ubad = True
                    except envi.SegmentationViolation:
                        ubad = True
                else:
                    # analyze the string

                    codepage = None
                    for uidx in range(0, len(tustr), 2):
                        b = tustr[uidx]
                        p = tustr[uidx+1]
                        if b not in printables:
                            ubad = True
                            break

                        # do we care about the codepage byte?
                        # should we hard-code it to \0??  or make it an option?
                        if codepage is None:
                            codepage = p
                        if codepage != p:
                            ubad = True
                            break

                        ucount += 1

                if not ubad and ucount == len(tustr)/2 and ucount >= minlen:
                    unis.append(tva) # we got a good one
                    logger.warning("found unicode: %x: %r", tva, tustr)                


                # add larger of the two counts.  most often, ucount will be smaller.

            tva += max(ucount, count)
            
            tva += 1
    
    return strs, unis

def findPointers(vw, memranges=(), lclfile=False, aligned=True, anongroup=True):
    '''
    Search for Pointers, withing a set of memory ranges, potentially limiting to pointers to the same file
    '''
    ptrsize = vw.getPointerSize()
    ptrs = []
    
    for mmva, mmsz, mmperm, mmname in vw.getMemoryMaps():
        # first decide if and what of this map we're analyzing...
        skip = True
        startva = mmva
        stopva = mmva + mmsz
        if memranges:
            for rstartva, rstopva in memranges:
                #if not rstartva <= mmva < rstopva:
                if rstopva < mmva:
                    pass

                elif rstartva > mmva+mmsz:
                    pass
                
                else:
                    # this memrange applies to this memory map
                    skip = False
                    if rstartva > startva:
                        startva = rstartva 

                    if rstopva < stopva:
                        stopva = rstopva

        if skip:
            continue

        # Now we get to work
        logger.warning("findPointers: %x->%x", startva, stopva)
        tva = startva
        while tva < stopva:
            # Go Pointer Hunting
            bad = False
            tptr = vw.readMemoryPtr(tva)

            if not vw.isValidPointer(tptr):
                bad = True

            else:
                tmmva, tmmsz, tmmperm, tmmname = vw.getMemoryMap(tptr)
                if mmname or anongroup:
                    if tmmname != mmname:
                        bad = True
                elif tmmva != mmva:
                        bad = True


            if not bad:
                ptrs.append(tva) # we got a good one
                logger.warning("found ptr: 0x%x: 0x%x", tva, tptr)


            if aligned:
                tva += ptrsize
            else:
                tva += 1
    
    return ptrs



def findStackRets(vw, memranges, tgtranges):
    rets = []
    logger.info("memranges: %r", ["0x%x->0x%x" % (x,y) for x,y in memranges])
    logger.info("tgtranges: %r", ["0x%x->0x%x" % (x,y) for x,y in tgtranges])

    for mmva, mmsz, mmperm, mmname in vw.getMemoryMaps():
        # if we specify memranges, honor them. otherwise, look through all maps
        if memranges:
            skip = True
            for mrstart, mrend in memranges:
                if mrstart <=mmva < mrend:
                    skip = False

            if skip:
                continue

        # analyze this map
        logger.info("starting map: 0x%x", mmva)
        srets = analyzeStackMap(vw, mmva)
        rets.extend([(stackva, retva, op) for stackva, retva, op in srets if isGoodTarget(retva, tgtranges)])

    return rets

def isGoodTarget(retva, tgtranges):
    for tgtrstart, tgtrend in tgtranges:
        if tgtrstart <= retva <tgtrend:
            return True

    return False
        

def analyzeStackMap(vw, mapva):
    ptrsz = vw.getPointerSize()
    out = []

    mmap = vw.getMemoryMap(mapva)
    if mmap is None:
        raise Exception("0x%x isn't in a valid Memory Map!" % mapva)

    mmva, mmsz, mmperm, mmnm = mmap

    for va in range(mmva, mmva+mmsz, ptrsz):
        ptr = vw.readMemoryPtr(va)
        try:
            good = False

            try:
                # what do we point at?
                tgt1 = vw.parseOpcode(ptr)
            except:
                # we're doing too much "evil" to log every bad decode
                continue


            tgt1bytes = vw.readMemory(ptr, 8)
            if tgt1bytes == b'\0\0\0\0\0\0\0\0':
                continue

            #print("... 0x%x: %r" % (ptr, tgt1bytes.hex()))

            # back up and look for valid codes
            for x in range(ptr-2, ptr-8, -1):
                try:
                    op = vw.parseOpcode(x)
                    if not op.isCall():
                        continue

                    # we're a call.  if the call instruction ends at our target VA, WIN!
                    if len(op) + x == ptr:
                        good = True
                        break

                except:
                    # we're gonna run into so much cruft, just throw it away
                    pass

            if good:
                out.append((va, ptr, op))

        except SegmentationViolation:
            pass
        
        except InvalidInstruction:
            pass

        except IndexError:
            import traceback
            traceback.print_exc()

        except Exception as e:
            print("ERROR: %r (ptr: 0x%x)" % (e, ptr))


    return out


def analyze(vw):
    out = {}
    mapdata = {}
    for mmva, mmsz, mmperm, mmnm in vw.getMemoryMaps():
        #if 'Stack' not in mmnm:
        #    continue

        
        data = mapdata[mmnm+"_%x" % mmva] = analyzeStackMap(vw, mmva)
        for ptr, op in data:
            pmap = vw.getMemoryMap(ptr)
            pmapnm = "%s_%x" % (pmap[3], pmap[0])
            thing = out.get(pmapnm)
            if thing is None:
                thing = []
                out[pmapnm] = thing
            thing.append((hex(op.va), op))

    return mapdata, out
