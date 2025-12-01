#!/usr/bin/python3
import os
import sys
import envi.config as e_config

from vivisection import viv_plugin

def doActivation(args=[]):
    '''
    Activation
    If you provide 
    '''
    if len(args) > 1:
        gopath = args[-1]

    else:
        extpath = os.environ.get('VIV_EXT_PATH')
        if extpath:
            if ':' in extpath:
                # grab the last in the VIV_EXT_PATH
                extparts = extpath.split(':')
                gopath = extparts[-1]
            else:
                # there's only one here
                gopath = extpath

        else:
            # if no VIV_EXT_PATH, grab the default
            gopath = e_config.gethomedir('.viv', 'plugins')


    vivisection_plugin = os.sep.join([gopath, 'VivisectION'])
    if os.path.exists(vivisection_plugin):
        print("Cannot reinstall existing VivisectION plugin.  Uninstall first using vivisection_deactivate.")
        print("  '%s' already exists:" % vivisection_plugin)
        sys.exit(-1)

    os.symlink(viv_plugin.__path__[0], vivisection_plugin)
    print("VivisectION Activated")

if __name__ == '__main__':
    doActivation(sys.argv[1:])
