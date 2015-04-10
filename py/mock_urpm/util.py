# vim:expandtab:autoindent:tabstop=4:shiftwidth=4:filetype=python:textwidth=0:
# License: GPL2 or later see COPYING
# Written by Michael Brown
# Sections by Seth Vidal
# Sections taken from Mach by Thomas Vander Stichele
# Copyright (C) 2007 Michael E Brown <mebrown@michaels-house.net>

# python library imports
import ctypes
import fcntl
import os
import os.path
import rpm
import select
import shutil
import subprocess
import time
import errno
import re
import sys
from signal import SIGTERM

# our imports
import mock_urpm.exception
from mock_urpm.trace_decorator import traceLog, decorate, getLog
import mock_urpm.uid as uid

_libc = ctypes.cdll.LoadLibrary(None)
_errno = ctypes.c_int.in_dll(_libc, "errno")
_libc.personality.argtypes = [ctypes.c_ulong]
_libc.personality.restype = ctypes.c_int
_libc.unshare.argtypes = [ctypes.c_int,]
_libc.unshare.restype = ctypes.c_int
CLONE_NEWNS = 0x00020000

# taken from sys/personality.h
PER_LINUX32=0x0008
PER_LINUX=0x0000
personality_defs = {
    'x86_64': PER_LINUX, 'ppc64': PER_LINUX, 'sparc64': PER_LINUX,
    'i386': PER_LINUX32, 'i586': PER_LINUX32, 'i686': PER_LINUX32,
    'ppc': PER_LINUX32, 'sparc': PER_LINUX32, 'sparcv9': PER_LINUX32,
    'ia64' : PER_LINUX, 'alpha' : PER_LINUX,
    's390' : PER_LINUX32, 's390x' : PER_LINUX,
}

# classes
class commandTimeoutExpired(mock_urpm.exception.Error):
    def __init__(self, msg):
        mock_urpm.exception.Error.__init__(self, msg)
        self.msg = msg
        self.resultcode = 10

# functions
decorate(traceLog())
def mkdirIfAbsent(*args):
    for dirName in args:
        getLog().debug("ensuring that dir exists: %s" % dirName)
        if not os.path.exists(dirName):
            try:
                getLog().debug("creating dir: %s" % dirName)
                os.makedirs(dirName)
            except OSError, e:
                getLog().exception("Could not create dir %s. Error: %s" % (dirName, e))
                raise mock_urpm.exception.Error, "Could not create dir %s. Error: %s" % (dirName, e)

decorate(traceLog())
def touch(fileName):
    getLog().debug("touching file: %s" % fileName)
    fo = open(fileName, 'w')
    fo.close()

decorate(traceLog())
def rmtree(path, *args, **kargs):
    """version os shutil.rmtree that ignores no-such-file-or-directory errors,
       and tries harder if it finds immutable files"""
    do_selinux_ops = False
    if kargs.has_key('selinux'):
        do_selinux_ops = kargs['selinux']
        del kargs['selinux']
    tryAgain = 1
    retries = 0
    failedFilename = None
    getLog().debug("remove tree: %s" % path)
    while tryAgain:
        tryAgain = 0
        try:
            shutil.rmtree(path, *args, **kargs)
        except OSError, e:
            if e.errno == errno.ENOENT: # no such file or directory
                pass
            elif do_selinux_ops and (e.errno==errno.EPERM or e.errno==errno.EACCES):
                tryAgain = 1
                if failedFilename == e.filename:
                    raise
                failedFilename = e.filename
                os.system("chattr -R -i %s" % path)
            elif e.errno == errno.EBUSY:
                retries += 1
                if retries > 1:
                    raise
                tryAgain = 1
                getLog().debug("retrying failed tree remove after sleeping a bit")
                time.sleep(2)
            else:
                raise


decorate(traceLog())
def orphansKill(rootToKill, killsig=SIGTERM):
    """kill off anything that is still chrooted."""
    getLog().debug("kill orphans")
    for fn in [ d for d in os.listdir("/proc") if d.isdigit() ]:
        try:
            root = os.readlink("/proc/%s/root" % fn)
            if os.path.realpath(root) == os.path.realpath(rootToKill):
                getLog().warning("Process ID %s still running in chroot. Killing..." % fn)
                pid = int(fn, 10)
                os.kill(pid, killsig)
                os.waitpid(pid, 0)
        except OSError, e:
            pass


decorate(traceLog())
def yieldSrpmHeaders(srpms, plainRpmOk=0):
    ts = rpm.TransactionSet()
    ts.setVSFlags(rpm.RPMVSF_NOHDRCHK|rpm.RPMVSF_NOSHA1HEADER|rpm.RPMVSF_NODSAHEADER|rpm.RPMVSF_NORSAHEADER|rpm.RPMVSF_NOMD5|rpm.RPMVSF_NODSA|rpm.RPMVSF_NORSA)
    for srpm in srpms:
        try:
            fd = os.open(srpm, os.O_RDONLY)
            hdr = ts.hdrFromFdno(fd)
            os.close(fd)
        except (rpm.error), e:
            raise mock_urpm.exception.Error, "Cannot find/open srpm: %s. Error: %s" % (srpm, ''.join(e))

        if not plainRpmOk and hdr[rpm.RPMTAG_SOURCERPM] != []:
            raise mock_urpm.exception.Error("File is not an srpm: %s." % srpm )
        yield hdr

decorate(traceLog())
def getNEVRA(hdr):
    name = hdr[rpm.RPMTAG_NAME]
    ver  = hdr[rpm.RPMTAG_VERSION]
    rel  = hdr[rpm.RPMTAG_RELEASE]
    epoch = hdr[rpm.RPMTAG_EPOCH]
    arch = hdr[rpm.RPMTAG_ARCH]
    if epoch is None: epoch = 0
    return (name, epoch, ver, rel, arch)

decorate(traceLog())
def cmpKernelEVR(str1, str2):
    'compare two kernel version strings and return -1, 0, 1 for less, equal, greater'
    return rpm.evrCompare(str1, str2)

decorate(traceLog())
def getAddtlReqs(hdr, conf):
    # Add the 'more_buildreqs' for this SRPM (if defined in config file)
    (name, epoch, ver, rel, arch) = getNEVRA(hdr)
    reqlist = []
    for this_srpm in ['-'.join([name, ver, rel]),
                      '-'.join([name, ver]),
                      '-'.join([name]),]:
        if conf.has_key(this_srpm):
            more_reqs = conf[this_srpm]
            if type(more_reqs) in (type(u''), type(''),):
                reqlist.append(more_reqs)
            else:
                reqlist.extend(more_reqs)
            break

    #return rpmUtils.miscutils.unique(reqlist)
    return list(set(reqlist))  # remove duplicates from list

# not traced...
def chomp(line):
    if line.endswith("\n"):
        return line[:-1]
    else:
        return line

decorate(traceLog())
def unshare(flags):
    getLog().debug("Unsharing. Flags: %s" % flags)
    try:
        res = _libc.unshare(flags)
        if res:
            raise UnshareFailed(os.strerror(_errno.value))
    except AttributeError, e:
        pass

# these are called in child process, so no logging
def condChroot(chrootPath):
    if chrootPath is not None:
        saved = { "ruid": os.getuid(), "euid": os.geteuid(), }
        uid.setresuid(0,0,0)
        os.chdir(chrootPath)
        os.chroot(chrootPath)
        uid.setresuid(saved['ruid'], saved['euid'])


def condChdir(cwd):
    if cwd is not None:
        os.chdir(cwd)

def condDropPrivs(uid, gid):
    if gid is not None:
        os.setregid(gid, gid)
    if uid is not None:
        os.setreuid(uid, uid)

def condPersonality(per=None):
    if per is None or per in ('noarch',):
        return
    if personality_defs.get(per, None) is None:
        return
    res = _libc.personality(personality_defs[per])
    if res == -1:
        raise OSError(_errno.value, os.strerror(_errno.value))


def logOutput(fds, logger, returnOutput=1, start=0, timeout=0, quiet=False, verbose=False):
    output=""
    done = 0

    # set all fds to nonblocking
    for fd in fds:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if not fd.closed:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags| os.O_NONBLOCK)

    tail = ""
    re_progress = re.compile('^ +(\d+)/(\d+): ([\w-]+) +#+$')

    def __write(text, newline=False):
        if quiet:
            return
        sys.stdout.write('\r%-80s'%text)
        if newline:
            sys.stdout.write('\n')
        sys.stdout.flush()

    need_erase = False
    while not done:
        if (time.time() - start)>timeout and timeout!=0:
            done = 1
            break

        i_rdy,o_rdy,e_rdy = select.select(fds,[],[],1)
        for s in i_rdy:
            # slurp as much input as is ready
            input = s.read()
            if input == "":
                done = 1
                break
            if logger is not None:
                lines = input.split("\n")
                if tail:
                    lines[0] = tail + lines[0]
                # we may not have all of the last line
                tail = lines.pop()
                for line in lines:
                    if line == '': continue
                    logger.debug(line)
                    res = re_progress.match(line)
                    if res:
                        (n, of, name) = res.groups()
                        if name=='ccache' and of == '1' and not verbose:
                            __write('Installing ccache', newline=True)
                        else:
                            need_erase = True
                            if not verbose:
                                __write('Installing [%s/%s]: %s' % (n, of, name), newline=nl)

                for h in logger.handlers:
                    h.flush()
            if returnOutput:
                output += input
    if need_erase:
        __write('Installed packages: %s' % of, newline=True)
    if tail and logger is not None:
        logger.debug(tail)
    return output

decorate(traceLog())
def selinuxEnabled():
    """Check if SELinux is enabled (enforcing or permissive)."""
    try:
        if open("/selinux/enforce").read().strip() in ("1", "0"):
            return True
    except:
        pass
    return False

decorate(traceLog())
def get_proxy_environment(config):
    env = {}
    for proto in ('http', 'https', 'ftp', 'no'):
        key = '%s_proxy' % proto
        value = config.get(key)
        if value:
            env[key] = value
    return env

decorate(traceLog())
def cleanEnv():

    env = {'TERM' : 'vt100',
           'SHELL' : '/bin/bash',
           'HOME' : '/builddir',
           'PATH' : '/usr/sbin:/sbin:/usr/bin:/bin',
           }
    #env['LANG'] = os.environ.setdefault('LANG', 'en_US.UTF-8')
    return env

# logger =
# output = [1|0]
# chrootPath
#
# The "Not-as-complicated" version
#

decorate(traceLog())
def do(command, shell=False, chrootPath=None, cwd=None, timeout=0, raiseExc=True, returnOutput=0, stdin=None, uid=None, gid=None, personality=None, env=None, quiet=False, verbose=False, *args, **kargs):

    logger = kargs.get("logger", getLog())
    output = ""
    start = time.time()
    preexec = ChildPreExec(personality, chrootPath, cwd, uid, gid)
    if env is None:
        env = cleanEnv()

    try:
        child = None
        logger.debug("Executing command: %s" % command)
        if stdin is None:
            print ("Executing command1: %s" % command)
            child = subprocess.Popen(
                command,
                shell=shell,
                env=env,
                bufsize=0, close_fds=True,
                stdin=open("/dev/null", "r"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn = preexec,
                )
            # use select() to poll for output so we dont block
            output = logOutput([child.stdout, child.stderr],
                               logger, returnOutput, start, timeout, quiet, verbose)
        else:
            print ("Executing command2: " + str(command))
            child = subprocess.Popen(
                command,
                shell=shell,
                env=env,
                bufsize=0, close_fds=True,
                stdin=None,
                stdout=None,
                stderr=None,
                preexec_fn = preexec,
                )
            # use select() to poll for output so we dont block
            output=None;
#            output = logOutput([child.stdout, child.stderr],
#                               logger, returnOutput, start, timeout, quiet, verbose)

    except:
        # kill children if they arent done
        if child is not None and child.returncode is None:
            os.killpg(child.pid, 9)
        try:
            if child is not None:
                os.waitpid(child.pid, 0)
        except:
            pass

        raise

    # wait until child is done, kill it if it passes timeout
    niceExit=1
    while child.poll() is None:
        if (time.time() - start)>timeout and timeout!=0:
            niceExit=0
            os.killpg(child.pid, 15)
        if (time.time() - start)>(timeout+1) and timeout!=0:
            niceExit=0
            os.killpg(child.pid, 9)
    if not niceExit:
        raise commandTimeoutExpired, ("Timeout(%s) expired for command:\n # %s\n%s" % (timeout, command, output))

    logger.debug("Child returncode was: %s" % str(child.returncode))
    if raiseExc and child.returncode:
        if returnOutput:
            raise mock_urpm.exception.Error, ("Command failed: \n # %s\n%s" % (command, output), child.returncode)
        else:
            raise mock_urpm.exception.Error, ("Command failed. See logs for output.\n # %s" % (command,), child.returncode)
    return output

class ChildPreExec(object):
    def __init__(self, personality, chrootPath, cwd, uid, gid):
        self.personality = personality
        self.chrootPath  = chrootPath
        self.cwd = cwd
        self.uid = uid
        self.gid = gid

    def __call__(self, *args, **kargs):
        os.setsid()
        condPersonality(self.personality)
        condChroot(self.chrootPath)
        condDropPrivs(self.uid, self.gid)
        condChdir(self.cwd)



def is_in_dir(path, directory):
    """Tests whether `path` is inside `directory`."""
    # use realpath to expand symlinks
    path = os.path.realpath(path)
    directory = os.path.realpath(directory)

    return os.path.commonprefix([path, directory]) == directory
