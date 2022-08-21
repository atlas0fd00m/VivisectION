import logging

import cobra.dcode
import cobra.remoteapp

logger = logging.getLogger(__name__)


class SharedVivWorkspace:
    ''' 
    We are basically wrapping a VivCli or VivWorkspace object but adding 
    some Server functionality to support FollowTheLeader
    ''' 
    def __init__(self, vw):
        self.vw = vw 
        
    def __getattr__(self, name):
        '''
        If not defined as SharedVivWorkspace, reach into the VivCli
        '''
        if name not in self.__dict__:
            return getattr(self.vw, name)

    def getLeaderLocations(self, wsname):
        wsinfo = self._req_wsinfo(wsname)
        lock, path, events, users, leaders, leaderloc = wsinfo
        return dict(leaderloc)
        
    def getLeaderSessions(self, wsname):
        wsinfo = self._req_wsinfo(wsname)
        lock, path, events, users, leaders, leaderloc = wsinfo
        return dict(leaders)
        
    #def _fireEvent(self, evt, evtdata):
    #    print("fake _fireEvent(%r, %r)" % (evt, evtdata))
        
        
def shareWorkspace(vw, doref=False):
    # TODO:
    if vw.server:
        logger.warning("Already have a server setup... not yet supported.  vw.server == %r")
        return

    daemon = cobra.CobraDaemon('', 0, msgpack=True)
    daemon.fireThread()
    cobra.dcode.enableDcodeServer(daemon=daemon)
    cobra.remoteapp.shareRemoteApp('vivisect.remote.client', appsrv=vw, daemon=daemon)
    vw.server = SharedVivWorkspace(vw)
    #updateGuiMenus(vw)
        
    print(vw.server)
    return daemon

def updateGuiMenus(vw):
    vwgui = vw.getVivGui()
    for fg in vwgui.getFuncGraphs():
        widg = fg.widget()
        widg.rend_tools.setMenu( widg.getRendToolsMenu() )
            
    for mw in vwgui.getMemoryWidgets():
        widg = mw.widget()
        widg.rend_tools.setMenu( widg.getRendToolsMenu() )

