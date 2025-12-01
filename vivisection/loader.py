import os
import logging

logger = logging.getLogger(__name__)


FT_PE = 1
FT_ELF = 2


class RecursiveLoader:
    def __init__(self, vw, paths=['.']):
        # TODO: load config from file or vw.config
        self.vw = vw
        self.paths = paths
        logger.debug("Initialized RecursiveLoader with paths: %r" % self.paths)

    def getLibFileExt(self):
        for f in self.vw.getFiles():
            if self.vw.getFileMeta(f, 'GOT'):
                return '.so'

        return '.dll'


    def load(self):
        ext = self.getLibFileExt()

        # cycle through workspace loaded files - nope, we don't store deps by filemeta

        # TODO: look for .viv files and treat them with preference?

        # RECURSIVELY:
        go = True
        done = []
        while go:
            go = False
            # find dependencies in path locations
            for lib in self.vw.getLibraryDependancies():
                if lib in done:
                    continue
                if lib in self.vw.getFiles():
                    continue

                # load into workspace
                libname = ''.join([lib, ext])
                filepath = self.findLibDep(libname)

                if filepath is None:
                    print("Unable to find/load dependency: %r" % libname)
                    continue

                normname = self.vw.loadFromFile(filepath)
                done.append(normname)
                go = True

                # wash, rinse, repeat

    def findLibDep(self, libname, filetype=FT_ELF):
        # TODO: case-sensitivity for ELF, insensitive for PE

        # dig through library paths
        for path in self.paths:
            try:
                listing = os.listdir(path)
                for f in listing:
                    if f == libname:
                        return os.sep.join([path, libname])

                    if filetype == FT_ELF:
                        # try differences
                        for num in range(11):
                            tempname = '.'.join([libname, "%d"%num])
                            if f == tempname:
                                return os.sep.join([path, tempname])

            except Exception as e:
                print("Exception searching %r for %r:  %r" % (path, libname, e))

        return None
