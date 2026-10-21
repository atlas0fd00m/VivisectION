'''
this is the external client called to setup an emulator
'''
import sys
import threading
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
    vw.server = remotevw
    vw.rchan = remotevw.createEventChannel()

    vw.server.vprint('%s connecting...' % uname)

    print("server: %r" % vw.server)
    if isinstance(vw.server, v_server.VivServerClient):
        vw.leaders.update(vw.server.getLeaderSessions())
        vw.leaderloc.update(vw.server.getLeaderLocations())
    else:
        vw.leaders.update(vw.server.leaders)
        vw.leaderloc.update(vw.server.leaderloc)


    wsevents = vw.server.exportWorkspace()
    vw.importWorkspace(wsevents)
    vw.server.vprint('%s connection complete!' % uname)

    thr = threading.Thread(target=vw._clientThread)
    thr.daemon = True
    thr.start()

    timeout = vw.config.viv.remote.wait_for_plat_arch
    vw._load_event.wait(timeout=timeout)
    vw._snapInAnalysisModules()

def runClient(host, port, sessid):
    print("runClient(%r, %r, %r)" % (host, port, sessid))

    # connect to remote workspace
    vw = getRemoteWs('%s:%s' % (host, port))

    # get session context
    ctx = vw._ionmgr.getSession(sessid)
    print("sessid: %r\t\tctx: %r" % (sessid, ctx))
    pass


if __name__ == '__main__':
    runClient(*sys.argv[1:4])