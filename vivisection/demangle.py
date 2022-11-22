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

    return resp.content
