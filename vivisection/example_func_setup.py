
def getPosixNinjaEmu(emu, fva=None, funcgraph='FuncGraph0'):
    '''
    Simple helper script to simplify and bring consistency to all functions
    '''
    vemu.getHeap(emu, 5024*1024)    # initialize heap to 1MB instead of 10k default
    nemu = vemu.NinjaEmulator(emu, fakePEB=True, guiFuncGraphName=funcgraph)

def getWinBaseEmu(emu, fva=None, funcgraph='FuncGraph0'):
    '''
    Simple helper script to simplify and bring consistency to all functions
    '''
    vemu.getHeap(emu, 5024*1024)    # initialize heap to 1MB instead of 10k default
    nemu = vemu.NinjaEmulator(emu, fakePEB=True, guiFuncGraphName=funcgraph)
    nemu.addEnvVar(b'INSTALL_DIR', br'C:\foo\bar')
    nemu.addEnvVar(b'OS', br'Windows_NT')

    # create a directory mapping for lots of files/directories
    nemu.addDirectoryMap(br'C:\foo\bar\bin', b'./work/bin/')

    # create a fake file (not on disk) with default attributes
    nemu.addFile(br'C:\foo\bar\bin\blahblah.dll', b'asdflkahsdflkjh')

    nemu.addFilePathMapping(emu.vw.parseExpression('dll_module_in_viv'), "Dll-Module-With-Case_and_hyphes.dll")

    # existing directories 
    nemu.addDirectory(b'C:\\')
    nemu.addDirectory(br'C:\foo')
    nemu.addDirectory(br'C:\foo\bar')
    nemu.addDirectory(br'C:\foo\bar\xml')
    nemu.addDirectory(br'C:\foo\baz')

    # call handlers manually added (a bunch are added by default for common libc/kernel32/etc. funcs)
    nemu.addCallHandler('dll_module_in_viv+0x2a50', LogThing)
        
    nemu.getKernel().registry.setConfigPrimitive(cfgdict)

    stackbase, stacksize = nemu.emu.getMeta('kernel').getStackInfo()
    nemu.emu.addMemoryMap(stackbase + stacksize, 4, 'unknown', b'\0'*4096)

    return nemu

cfgdict = {
        'HKLM': {
            'SYSTEM': {
                'RNG': {
                    "ExternalEntropyCount": 2,
                    #"type:ExternalEntropyCount": nemu.REG_DWORD,
                    "Seed": unhexlify(b'5365656446696c6570760500b62d05517e90cfebc9416c5047c402c6a8fc38c6de55838f8dcf0b244bf83f06aad170e1160c643c8634dc91338fae64b5682440f1b370b5c5ab3e89e6e8ee5b'),
                    "type:Seed": nemu.REG_BINARY,
                    }
                },
            'SOFTWARE': {
                'Microsoft': {
                    'Crypt': {
                        'foo': 4,
                        },
                    'Cryptography': {
                        'RNG': {
                            }
                        }
                    }
                }
            }
        }

def getEmu_<THISFUNCTION>(vw):
    fva = vw.parseExpression('<THISFUNCTION>')
    emu = vw.getEmulator(va=fva, logread=True, logwrite=True, safemem=False)
    nemu = getEmu(emu)

    args = []
    nemu.setupCall(fva, args)

    return nemu
    
