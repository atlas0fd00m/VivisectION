'''
this is the external client called to setup an emulator
'''
import sys
import cobra
import vivisect.cli as v_cli
import vivisect.remote.server as v_server


def getRemoteWs(hostport):
    uri = 'cobra://%s/vivisect.remote.client?msgpack=1' % hostport
    server = cobra.CobraProxy(uri, msgpack=True)

    vw = v_cli.VivCli()
    initWorkspaceClient(vw, server)
    return vw

def initWorkspaceClient(vw, remotevw):
    """
    Initialize this workspace as a workspace
    client to the given (potentially cobra remote)
    workspace object.
    """
    uname = "ion-client"
    self.server = remotevw
    self.rchan = remotevw.createEventChannel()

    self.server.vprint('%s connecting...' % uname)

    print("server: %r" % self.server)
    if isinstance(self.server, v_server.VivServerClient):
        self.leaders.update(self.server.getLeaderSessions())
        self.leaderloc.update(self.server.getLeaderLocations())
    else:
        self.leaders.update(self.server.leaders)
        self.leaderloc.update(self.server.leaderloc)


    wsevents = self.server.exportWorkspace()
    self.importWorkspace(wsevents)
    self.server.vprint('%s connection complete!' % uname)

    thr = threading.Thread(target=self._clientThread)
    thr.setDaemon(True)
    thr.start()

    timeout = self.config.viv.remote.wait_for_plat_arch
    self._load_event.wait(timeout=timeout)
    self._snapInAnalysisModules()

def runClient(host, port, sessid):
    print("runClient(%r, %r, %r)" % (host, port sessid))

    # connect to remote workspace
    vw = getRemoteWs()

    # get session context
    ctx = vw._ionmgr.getSession(sessid)
    print("sessid: %r\t\tctx: %r" % (sessid, ctx))
    pass


if __name__ == '__main__':
    runClient(*sys.argv[1:4])
