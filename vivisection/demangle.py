import requests

class DemangleException(Exception):
    def __init__(self, resp):
        self.resp = resp

    def __repr__(self):
        return "Failed access to demangler.com: %r" % self.resp

def demangle(mangname):
    """
    Demangle C++ names for MSVS and GCC using demangler.com
    Checks for key markers (_Z and @) before bothering the web.  
    If they're missing, returns the original argument
    """
    if not '_Z' in mangname and \
        not '@' in mangname:
            return mangname

    hdr = {'Content-Type': 'application/x-www-form-urlencoded'}
    resp = requests.post('http://demangler.com/raw', data='input=%s'%mangname, headers=hdr)

    if resp.status_code != 200:
        raise DemangleException(resp)

    return resp.content.decode('utf8')

def dmangleVw(vw, apply=False):
    deltas = {}

    for nva, name in vw.getNames():
        dmname = demangle(name)
        if dmname != name:
            inp = input("Apply? 0x%x:   %r  ==>  %r" % (nva, name, dmname))
            if inp.upper().startswith("Y"):
                deltas[nva] = (name, dmname)

    # do something...
    if apply:
        for nva, (name, dmname) in deltas.items():
            vw.makeName(nva, dmname)

    return deltas
