#!python3
import argparse
import vivisection

'''
This is called interally from the Vivisect GUI to launch an emulator at a particular address and connect it into a Shared Workspace/VivServer
This should work with both a Shared Workspace (ie. someone with a GUI "shares their workspace" and shares the host/port) as well as a Vivisect Server (which typically is a server listening on TCP 16500)
'''

def emuMain(server, port, wsname, environ, description):
    '''
    '''
    # connect to server/workspace
    # setup environment
    # launch iPython-based NinjaEmulator
    pass

if __name__ == '__main__':
    argp = argparse.ArgumentParser()
    argp.add_argument('-S', '--server', help="Vivisect Server Name or IP address")
    argp.add_argument('-P', '--port', default=16500, help="Vivisect Server/Shared Workspace port")
    argp.add_argument('-w', '--wsname', help="Vivisect Workspace name (only required for Server connections)")
    argp.add_argument('-e', '--environ', help="Emulation Environment (pre-setup, like function args, etc...)")
    argp.add_argument('description', help="How will this emulator broadcast itself to its potential followers?")


