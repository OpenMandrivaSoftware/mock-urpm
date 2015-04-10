#!/usr/bin/python -tt
# vim:expandtab:autoindent:tabstop=4:shiftwidth=4:filetype=python:textwidth=0:
# Originally written by Seth Vidal
# Sections taken from Mach by Thomas Vander Stichele
# Major reorganization and adaptation by Michael Brown
# Copyright (C) 2007 Michael E Brown <mebrown@michaels-house.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
"""
    usage:
           mock-urpm [options] {--init|--clean|--scrub=[all,chroot,cache,root-cache,c-cache]}
           mock-urpm [options] [--rebuild] /path/to/srpm(s)
           mock-urpm [options] --buildsrpm {--spec /path/to/spec --sources /path/to/src|--scm-enable [--scm-option key=value]}
           mock-urpm [options] {--shell|--chroot} <cmd>
           mock-urpm [options] --installdeps {SRPM|RPM}
           mock-urpm [options] --install PACKAGE
           mock-urpm [options] --copyin path [..path] destination
           mock-urpm [options] --readdrepo
           mock-urpm [options] --copyout path [..path] destination
           mock-urpm [options] --scm-enable [--scm-option key=value]
"""

# library imports
import ConfigParser
import grp
import logging
import logging.config
import os
import os.path
import pwd
import sys
import time
from optparse import OptionParser
from glob import glob
import pwd

#FIXME
#unsetting LC_ALL leads to perl locale warnings
#import locale
#locale.setlocale(locale.LC_ALL, '')

# all of the variables below are substituted by the build system
__VERSION__ = "1.1.12-urpm"
version = str(sys.version_info.major) + "." + str(sys.version_info.minor)
SITEDIR = sys.prefix + "/lib/python" + version + "/site-packages"
SYSCONFDIR = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "../..", "etc")
PYTHONDIR = os.path.dirname(os.path.realpath(sys.argv[0]))
PKGPYTHONDIR = os.path.join(SITEDIR, "mock_urpm")
MOCKCONFDIR = os.path.join(SYSCONFDIR, "mock-urpm")
# end build system subs

# import all mock_urpm.* modules after this.
sys.path.insert(0, PYTHONDIR)

# set up basic logging until config file can be read
FORMAT = "%(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT, level=logging.WARNING)
log = logging.getLogger()

# our imports
import mock_urpm.exception
from mock_urpm.trace_decorator import traceLog, decorate
import mock_urpm.backend
import mock_urpm.scm
import mock_urpm.uid
import mock_urpm.util

def scrub_callback(option, opt, value, parser):
    parser.values.scrub.append(value)
    parser.values.mode = "clean"

def command_parse(config_opts):
    """return options and args from parsing the command line"""
    parser = OptionParser(usage=__doc__, version=__VERSION__)

    # modes (basic commands)
    parser.add_option("--rebuild", action="store_const", const="rebuild",
                      dest="mode", default='rebuild',
                      help="rebuild the specified SRPM(s)")
    parser.add_option("--buildsrpm", action="store_const", const="buildsrpm",
                      dest="mode",
                      help="Build a SRPM from spec (--spec ...) and sources (--sources ...) or from SCM")
    parser.add_option("--shell", action="store_const",
                      const="shell", dest="mode",
                      help="run the specified command interactively within the chroot."
                           " Default command: /bin/sh")
    parser.add_option("--chroot", action="store_const",
                      const="chroot", dest="mode",
                      help="run the specified command noninteractively within the chroot.")
    parser.add_option("--clean", action="store_const", const="clean",
                      dest="mode",
                      help="completely remove the specified chroot")
    scrub_choices = ('chroot', 'cache', 'root-cache', 'c-cache', 'all')
    scrub_metavar = "[all|chroot|cache|root-cache|c-cache]"
    parser.add_option("--scrub", action="callback", type="choice", default=[],
                      choices=scrub_choices, metavar=scrub_metavar,
                      callback=scrub_callback,
                      help="completely remove the specified chroot or cache dir or all of the chroot and cache")
    parser.add_option("--init", action="store_const", const="init", dest="mode",
                      help="initialize the chroot, do not build anything")
    parser.add_option("--installdeps", action="store_const", const="installdeps",
                      dest="mode",
                      help="install build dependencies for a specified SRPM")
    parser.add_option("--install", action="store_const", const="install",
                      dest="mode",
                      help="install packages using urpmi")
    parser.add_option("--update", action="store_const", const="update",
                      dest="mode",
                      help="update installed packages using urpmi")
    parser.add_option("--orphanskill", action="store_const", const="orphanskill",
                      dest="mode",
                      help="Kill all processes using specified buildroot.")

    parser.add_option("--copyin", action="store_const", const="copyin",
                      dest="mode",
                      help="Copy file(s) into the specified chroot")

    parser.add_option("--readdrepo", action="store_const", const="readdrepo",
                      dest="mode",
                      help="Add repositories from default config from scratch")

    parser.add_option("--copyout", action="store_const", const="copyout",
                      dest="mode",
                      help="Copy file(s) from the specified chroot")

    # options
    parser.add_option("-r", "--root", action="store", type="string", dest="chroot",
                      help="chroot name/config file name default: %default",
                      default='default')

    parser.add_option("--no-clean", action="store_false", dest="clean",
                      help="do not clean chroot before building", default=True)
    parser.add_option("--cleanup-after", action ="store_true",
                      dest="cleanup_after", default=None,
                      help="Clean chroot after building. Use with --resultdir."
                           " Only active for 'rebuild'.")
    parser.add_option("--no-cleanup-after", action="store_false",
                      dest="cleanup_after", default=None,
                      help="Dont clean chroot after building. If automatic"
                           " cleanup is enabled, use this to disable.", )
    parser.add_option("--arch", action ="store", dest="arch",
                      default=None, help="Sets kernel personality().")
    parser.add_option("--target", action ="store", dest="rpmbuild_arch",
                      default=None, help="passed to rpmbuild as --target")
    parser.add_option("--sign", action ="store_true", dest="rpmbuild_sign",
                      default=None, help="add --sign option to rpmbuild")
    parser.add_option("--autosign", action ="store", dest="rpmbuild_passphrase",
                      default=None, help="add --sign option to rpmbuild and automarically provide given passphrase to rpmbuild")
    parser.add_option("-D", "--define", action="append", dest="rpmmacros",
                      default=[], type="string", metavar="'MACRO EXPR'",
                      help="define an rpm macro (may be used more than once)")
    parser.add_option("--with", action="append", dest="rpmwith",
                      default=[], type="string", metavar="option",
                      help="enable configure option for build (may be used more than once)")
    parser.add_option("--without", action="append", dest="rpmwithout",
                      default=[], type="string", metavar="option",
                      help="disable configure option for build (may be used more than once)")
    parser.add_option("--resultdir", action="store", type="string",
                      default=None, help="path for resulting files to be put")
    parser.add_option("--uniqueext", action="store", type="string",
                      default=None,
                      help="Arbitrary, unique extension to append to buildroot"
                           " directory name")
    parser.add_option("--configdir", action="store", dest="configdir",
                      default=None,
                      help="Change where config files are found")
    parser.add_option("--rpmbuild_timeout", action="store",
                      dest="rpmbuild_timeout", type="int", default=None,
                      help="Fail build if rpmbuild takes longer than 'timeout'"
                           " seconds ")
    parser.add_option("--unpriv", action="store_true", default=False,
                      help="Drop privileges before running command when using --chroot")
    parser.add_option("--cwd", action="store", default=None,
                      metavar="DIR",
                      help="Change to the specified directory (relative to the chroot)"
                           " before running command when using --chroot")

    parser.add_option("--spec", action="store",
                      help="Specifies spec file to use to build an SRPM (used only with --buildsrpm)")
    parser.add_option("--sources", action="store",
                      help="Specifies sources (either a single file or a directory of files)"
                      "to use to build an SRPM (used only with --buildsrpm)")

    # verbosity
    parser.add_option("-v", "--verbose", action="store_const", const=2,
                      dest="verbose", default=1, help="verbose build")
    parser.add_option("-q", "--quiet", action="store_const", const=0,
                      dest="verbose", help="quiet build")
    parser.add_option("--trace", action="store_true", default=False,
                      dest="trace", help="Enable internal mock-urpm tracing output.")

    # plugins
    parser.add_option("--enable-plugin", action="append",
                      dest="enabled_plugins", type="string", default=[],
                      help="Enable plugin. Currently-available plugins: %s"
                        % repr(config_opts['plugins']))
    parser.add_option("--disable-plugin", action="append",
                      dest="disabled_plugins", type="string", default=[],
                      help="Disable plugin. Currently-available plugins: %s"
                           % repr(config_opts['plugins']))

    parser.add_option("--print-root-path", help="print path to chroot root",
                      dest="printrootpath", action="store_true",
                      default=False)

    # SCM options
    parser.add_option("--scm-enable", help="build from SCM repository",
                      dest="scm", action="store_true",
                      default=None)
    parser.add_option("--scm-option", action="append", dest="scm_opts",
                      default=[], type="string",
                      help="define an SCM option (may be used more than once)")

    (options, args) = parser.parse_args()
    if len(args) and args[0] in ('chroot', 'shell',
            'rebuild', 'install', 'installdeps', 'init', 'clean'):
        options.mode = args[0]
        args = args[1:]

    if options.mode == 'buildsrpm' and not (options.spec and options.sources):
        if not options.scm:
            raise mock_urpm.exception.BadCmdline, "Must specify both --spec and --sources with --buildsrpm"
    if options.spec:
        options.spec = os.path.expanduser(options.spec)
    if options.sources:
        options.sources = os.path.expanduser(options.sources)

    return (options, args)

decorate(traceLog())
def setup_default_config_opts(config_opts, unprivUid):
    "sets up default configuration."
    # global
    config_opts['version'] = __VERSION__
    config_opts['basedir'] = '/var/lib/mock-urpm' # root name is automatically added to this
    config_opts['resultdir'] = '%(basedir)s/%(root)s/result'
    config_opts['cache_topdir'] = '/var/cache/mock-urpm'
    config_opts['clean'] = True
    config_opts['chroothome'] = '/builddir'
    config_opts['log_config_file'] = 'logging.ini'
    config_opts['rpmbuild_timeout'] = 0
    config_opts['chrootuid'] = unprivUid

    config_opts['urpmi_path'] = '/usr/sbin/urpmi'
    config_opts['urpmi_addmedia_path'] = '/usr/sbin/urpmi.addmedia'

    try:
        config_opts['chrootgid'] = grp.getgrnam("mock-urpm")[2]
    except KeyError:
        #  'mock' group doesnt exist, must set in config file
        pass
    config_opts['build_log_fmt_name'] = "unadorned"
    config_opts['root_log_fmt_name']  = "detailed"
    config_opts['state_log_fmt_name'] = "state"
    ###config_opts['online'] = True

    config_opts['internal_dev_setup'] = True
    config_opts['internal_setarch'] = True

    # cleanup_on_* only take effect for separate --resultdir
    # config_opts provides fine-grained control. cmdline only has big hammer
    config_opts['cleanup_on_success'] = True
    config_opts['cleanup_on_failure'] = True

    ###config_opts['createrepo_on_rpms'] = False
    ###config_opts['createrepo_command'] = '/usr/bin/createrepo -d -q -x *.src.rpm' # default command
    # (global) plugins and plugin configs.
    # ordering constraings: tmpfs must be first.
    #    root_cache next.
    #    after that, any plugins that must create dirs
    #    any plugins without preinit hooks should be last.
    config_opts['plugins'] = ['tmpfs', 'root_cache', 'bind_mount', 'ccache', 'selinux']
    config_opts['plugin_dir'] = os.path.join(PKGPYTHONDIR, "plugins")
    config_opts['plugin_conf'] = {
            'ccache_enable': False,
            'ccache_opts': {
                'max_cache_size': "4G",
                'dir': "%(cache_topdir)s/%(root)s/ccache/"},
            'root_cache_enable': True,
            'root_cache_opts': {
                'max_age_days': 15,
                'dir': "%(cache_topdir)s/%(root)s/root_cache/",
                'compress_program': 'pigz',
                'extension': '.gz'},
            'bind_mount_enable': True,
            'bind_mount_opts': {'dirs': [
                # specify like this:
                # ('/host/path', '/bind/mount/path/in/chroot/' ),
                # ('/another/host/path', '/another/bind/mount/path/in/chroot/'),
                ]},
            'tmpfs_enable': False,
            'tmpfs_opts': {
                'required_ram_mb': 500,
                'max_fs_size': '90%'},
            'selinux_enable': False,
            'selinux_opts': {},
            }

    config_opts['environment'] = {
            'TERM': 'vt100',
            'SHELL': '/bin/bash',
            'HOME': '/builddir',
            'PATH': '/usr/sbin:/sbin:/usr/bin:/bin',
            'PROMPT_COMMAND': 'PS1="mock-urpm@\W>"',
            'LANG': os.environ.setdefault('LANG', 'en_US.UTF-8'),
            }

    runtime_plugins = [runtime_plugin
                       for (runtime_plugin, _)
                       in [os.path.splitext(os.path.basename(tmp_path))
                           for tmp_path
                           in glob(config_opts['plugin_dir'] + "/*.py")]
                       if runtime_plugin not in config_opts['plugins']]
    for runtime_plugin in sorted(runtime_plugins):
        config_opts['plugins'].append(runtime_plugin)
        config_opts['plugin_conf'][runtime_plugin + "_enable"] = False
        config_opts['plugin_conf'][runtime_plugin + "_opts"] = {}

    # SCM defaults
    config_opts['scm'] = False
    config_opts['scm_opts'] = {
            'method': 'git',
            'cvs_get': 'cvs -d /srv/cvs co SCM_BRN SCM_PKG',
            'git_get': 'git clone SCM_BRN git://localhost/SCM_PKG.git SCM_PKG',
            'svn_get': 'svn co file:///srv/svn/SCM_PKG/SCM_BRN SCM_PKG',
            'spec': 'SCM_PKG.spec',
            'ext_src_dir': '/dev/null',
            'write_tar': False,
            'chdir': '',
            }

    # dependent on guest OS
    config_opts['useradd'] = \
        '/usr/sbin/useradd -o -m -u %(uid)s -g %(gid)s -d %(home)s -N %(user)s'
    config_opts['use_host_resolv'] = True
    config_opts['target_arch'] = 'i586'
    config_opts['rpmbuild_arch'] = None # <-- None means set automatically from target_arch

    config_opts['rpmbuild_sign'] = None
    config_opts['rpmbuild_passphrase'] = None

    ###config_opts['yum.conf'] = ''
    config_opts['more_buildreqs'] = {}
    config_opts['files'] = {}
    config_opts['macros'] = {
        '%_topdir': '%s/build' % config_opts['chroothome'],
        #'%_rpmfilename': '%%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm',
        '%_rpmfilename': '%{___NVRA}.rpm',
        }

    config_opts['urpmi_media_distrib'] = []
    config_opts['urpmi_media'] = {}
    config_opts['use_system_media'] = True
    config_opts['urpmi_config_dir'] = '/etc/urpmi/'

decorate(traceLog())
def set_config_opts_per_cmdline(config_opts, options, args):
    "takes processed cmdline args and sets config options."
    # do some other options and stuff
    if options.arch:
        config_opts['target_arch'] = options.arch

    if options.rpmbuild_sign:
        config_opts['rpmbuild_sign'] = options.rpmbuild_sign
    if options.rpmbuild_passphrase is not None:
        config_opts['rpmbuild_passphrase'] = options.rpmbuild_passphrase

    if options.rpmbuild_arch:
        config_opts['rpmbuild_arch'] = options.rpmbuild_arch
    elif config_opts['rpmbuild_arch'] is None:
        config_opts['rpmbuild_arch'] = config_opts['target_arch']

    if not options.clean:
        config_opts['clean'] = options.clean

    for option in options.rpmwith:
        options.rpmmacros.append("_with_%s --with-%s" %
                                 (option.replace("-", "_"), option))

    for option in options.rpmwithout:
        options.rpmmacros.append("_without_%s --without-%s" %
                                 (option.replace("-", "_"), option))

    for macro in options.rpmmacros:
        try:
            k, v = macro.split(" ", 1)
            if not k.startswith('%'):
                k = '%%%s' % k
            config_opts['macros'].update({k: v})
        except:
            raise mock_urpm.exception.BadCmdline(
                "Bad option for '--define' (%s).  Use --define 'macro expr'"
                % macro)

    if options.resultdir:
        config_opts['resultdir'] = os.path.expanduser(options.resultdir)
    if options.uniqueext:
        config_opts['unique-ext'] = options.uniqueext
    if options.rpmbuild_timeout is not None:
        config_opts['rpmbuild_timeout'] = options.rpmbuild_timeout

    for i in options.disabled_plugins:
        if i not in config_opts['plugins']:
            raise mock_urpm.exception.BadCmdline(
                "Bad option for '--disable-plugin=%s'. Expecting one of: %s"
                % (i, config_opts['plugins']))
        config_opts['plugin_conf']['%s_enable' % i] = False
    for i in options.enabled_plugins:
        if i not in config_opts['plugins']:
            raise mock_urpm.exception.BadCmdline(
                "Bad option for '--enable-plugin=%s'. Expecting one of: %s"
                % (i, config_opts['plugins']))
        config_opts['plugin_conf']['%s_enable' % i] = True

    if options.mode in ("rebuild",) and len(args) > 1 and not options.resultdir:
        raise mock_urpm.exception.BadCmdline(
            "Must specify --resultdir when building multiple RPMS.")

    if options.cleanup_after == False:
        config_opts['cleanup_on_success'] = False
        config_opts['cleanup_on_failure'] = False

    if options.cleanup_after == True:
        config_opts['cleanup_on_success'] = True
        config_opts['cleanup_on_failure'] = True
    # cant cleanup unless resultdir is separate from the root dir
    rootdir = os.path.join(config_opts['basedir'], config_opts['root'])
    if mock_urpm.util.is_in_dir(config_opts['resultdir'] % config_opts, rootdir):
        config_opts['cleanup_on_success'] = False
        config_opts['cleanup_on_failure'] = False

    ###config_opts['online'] = options.online

    if options.scm:
        config_opts['scm'] = options.scm
        for option in options.scm_opts:
            try:
                k, v = option.split("=", 1)
                config_opts['scm_opts'].update({k: v})
            except:
                raise mock_urpm.exception.BadCmdline(
                "Bad option for '--scm-option' (%s).  Use --scm-option 'key=value'"
                % option)

legal_arches = {
    'i386'   : ('i386', 'i586', 'i686'),
    'i686'   : ('i386', 'i586', 'i686'),
    'x86_64' : ('i386', 'i586', 'i686', 'x86_64'),
    'ppc'    : ('ppc',),
    'ppc64'  : ('ppc', 'ppc64'),
    'sparc'  : ('sparc',),
    'sparc64': ('sparc', 'sparc64'),
    's390x'  : ('s390', 's390x',),
}

decorate(traceLog())
def check_arch_combination(target_arch, config_opts):
    try:
        legal = config_opts['legal_host_arches']
    except KeyError:
        return
    host_arch = os.uname()[-1]
    if host_arch not in legal:
        raise mock_urpm.exception.InvalidArchitecture(
            "Cannot build target %s on arch %s" % (target_arch, host_arch))

decorate(traceLog())
def do_rebuild(config_opts, chroot, srpms):
    "rebuilds a list of srpms using provided chroot"
    if len(srpms) < 1:
        log.critical("No package specified to rebuild command.")
        sys.exit(50)

    # check that everything is kosher. Raises exception on error
    for hdr in mock_urpm.util.yieldSrpmHeaders(srpms):
        pass

    start = time.time()
    try:
        for srpm in srpms:
            start = time.time()
            log.info("Start(%s)  Config(%s)" % (srpm, chroot.sharedRootName))
            if config_opts['clean'] and chroot.state() != "clean" \
                    and not config_opts['scm']:
                chroot.clean()
            chroot.init()
            chroot.build(srpm, timeout=config_opts['rpmbuild_timeout'])
            elapsed = time.time() - start
            log.info("Done(%s) Config(%s) %d minutes %d seconds"
                % (srpm, config_opts['chroot_name'], elapsed//60, elapsed%60))
            log.info("Results and/or logs in: %s" % chroot.resultdir)

        if config_opts["cleanup_on_success"]:
            log.info("Cleaning up build root ('clean_on_success=True')")
            chroot.clean()

        ###if config_opts["createrepo_on_rpms"]:
        ###    log.info("Running createrepo on binary rpms in resultdir")
        ###    chroot.uidManager.dropPrivsTemp()
        ###    cmd = config_opts["createrepo_command"].split()
        ###    cmd.append(chroot.resultdir)
        ###    mock_urpm.util.do(cmd)
        ###    chroot.uidManager.restorePrivs()

    except (Exception, KeyboardInterrupt):
        elapsed = time.time() - start
        log.error("Exception(%s) Config(%s) %d minutes %d seconds"
            % (srpm, chroot.sharedRootName, elapsed//60, elapsed%60))
        log.info("Results and/or logs in: %s" % chroot.resultdir)
        if config_opts["cleanup_on_failure"]:
            log.info("Cleaning up build root ('clean_on_failure=True')")
            chroot.clean()
        raise

def do_buildsrpm(config_opts, chroot, options, args):
    start = time.time()
    try:
        # TODO: validate spec path (exists)
        # TODO: validate SOURCES path (exists)

        log.info("Start(%s)  Config(%s)" % (os.path.basename(options.spec), chroot.sharedRootName))
        if config_opts['clean'] and chroot.state() != "clean":
            chroot.clean()
        chroot.init()

        srpm = chroot.buildsrpm(spec=options.spec, sources=options.sources, timeout=config_opts['rpmbuild_timeout'], raiseExc=True)
        elapsed = time.time() - start
        log.info("Done(%s) Config(%s) %d minutes %d seconds"
            % (os.path.basename(options.spec), config_opts['chroot_name'], elapsed//60, elapsed%60))
        log.info("Results and/or logs in: %s" % chroot.resultdir)

        if config_opts["cleanup_on_success"]:
            log.info("Cleaning up build root ('clean_on_success=True')")
            chroot.clean()

        return srpm

    except (Exception, KeyboardInterrupt):
        elapsed = time.time() - start
        log.error("Exception(%s) Config(%s) %d minutes %d seconds"
            % (os.path.basename(options.spec), chroot.sharedRootName, elapsed//60, elapsed%60))
        log.info("Results and/or logs in: %s" % chroot.resultdir)
        if config_opts["cleanup_on_failure"]:
            log.info("Cleaning up build root ('clean_on_failure=True')")
            chroot.clean()
        raise

def rootcheck(raise_exception=True):
    "verify mock-urpm was started correctly (either by sudo or consolehelper)"
    # if we're root due to sudo or consolehelper, we're ok
    # if not raise an exception and bail
    res = (os.getuid() == 0 and not (os.environ.get("SUDO_UID") or os.environ.get("USERHELPER_UID")))
    if res:
        if raise_exception:
            raise RuntimeError, "mock-urpm will not run from the root account (needs an unprivileged uid so it can drop privs)"
    return res

def groupcheck(raise_exception=True):
    "verify that the user running mock-urpm is part of the mock-urpm group"
    # verify that we're in the mock-urpm group (so all our uid/gid manipulations work)
    sudo_user = None
    if 'SUDO_USER' in os.environ:
        sudo_user = os.environ['SUDO_USER']
    elif 'USERHELPER_UID' in os.environ:
        sudo_user = pwd.getpwuid(int(os.environ['USERHELPER_UID'])).pw_name
    else:
        sudo_user = pwd.getpwuid(os.geteuid()).pw_name

    groups = [x.gr_name for x in grp.getgrall() if sudo_user in x.gr_mem]
    inmockgrp = 'mock-urpm' in groups
    if raise_exception:
        if not inmockgrp:
            raise RuntimeError, "Must be member of 'mock-urpm' group to run mock!"
    return (inmockgrp, sudo_user)

def main(ret):
    "Main executable entry point."

    # initial sanity check for correct invocation method
    rootcheck()

    # drop unprivileged to parse args, etc.
    #   uidManager saves current real uid/gid which are unprivileged (callers)
    #   due to suid helper, our current effective uid is 0
    #   also supports being run by sudo
    #
    #   setuid wrapper has real uid = unpriv,  effective uid = 0
    #   sudo sets real/effective = 0, and sets env vars
    #   setuid wrapper clears environment, so there wont be any conflict between these two

    # old setuid wrapper
    unprivUid = os.getuid()
    unprivGid = os.getgid()

    # sudo
    if os.environ.get("SUDO_UID") is not None:
        unprivUid = int(os.environ['SUDO_UID'])
        username = os.environ.get("SUDO_USER")
        groups = [ g[2] for g in grp.getgrall() if username in g[3]]
        os.setgroups(groups)
        unprivGid = int(os.environ['SUDO_GID'])

    # consolehelper
    if os.environ.get("USERHELPER_UID") is not None:
        unprivUid = int(os.environ['USERHELPER_UID'])
        username = pwd.getpwuid(unprivUid)[0]
        groups = [ g[2] for g in grp.getgrall() if username in g[3]]
        os.setgroups(groups)
        unprivGid = pwd.getpwuid(unprivUid)[3]

    uidManager = mock_urpm.uid.uidManager(unprivUid, unprivGid)
    # go unpriv only when root to make --help etc work for non-mock-urpm users
    if os.geteuid() == 0:
        uidManager._becomeUser(unprivUid, unprivGid)

    # verify that our unprivileged uid is in the mock-urpm group
    groupcheck()

    # defaults
    config_opts = {}
    setup_default_config_opts(config_opts, unprivUid)
    (options, args) = command_parse(config_opts)

    if options.printrootpath:
        options.verbose = 0

    # config path -- can be overridden on cmdline
    config_path = MOCKCONFDIR
    if options.configdir:
        config_path = options.configdir

    uidManager._becomeUser(0, 0)
    fix_configs(config_path)
    uidManager._becomeUser(unprivUid, unprivGid)


    # array to save config paths
    config_opts['config_paths'] = []
    config_opts['verbose'] = options.verbose
    # Read in the config files: default, and then user specified
    for cfg in ( os.path.join(config_path, 'site-defaults.cfg'), '%s/%s.cfg' % (config_path, options.chroot)):
        if os.path.exists(cfg):
            config_opts['config_paths'].append(cfg)
            execfile(cfg)
        else:
            log.error("Could not find required config file: %s" % cfg)
            if options.chroot == "default": log.error("  Did you forget to specify the chroot to use with '-r'?")
            sys.exit(1)

    # configure logging
    config_opts['chroot_name'] = options.chroot
    log_ini = os.path.join(config_path, config_opts["log_config_file"])

    if not os.path.exists(log_ini):
        log.error("Could not find required logging config file: %s" % log_ini)
        sys.exit(50)
    try:
        if not os.path.exists(log_ini): raise IOError, "Could not find log config file %s" % log_ini
        log_cfg = ConfigParser.ConfigParser()
        logging.config.fileConfig(log_ini)
        log_cfg.read(log_ini)
    except (IOError, OSError, ConfigParser.NoSectionError), exc:
        log.error("Log config file(%s) not correctly configured: %s" % (log_ini, exc))
        sys.exit(50)

    try:
        # set up logging format strings
        config_opts['build_log_fmt_str'] = log_cfg.get("formatter_%s" % config_opts['build_log_fmt_name'], "format", raw=1)
        config_opts['root_log_fmt_str'] = log_cfg.get("formatter_%s" % config_opts['root_log_fmt_name'], "format", raw=1)
        config_opts['state_log_fmt_str'] = log_cfg.get("formatter_%s" % config_opts['state_log_fmt_name'], "format", raw=1)
    except ConfigParser.NoSectionError, exc:
        log.error("Log config file (%s) missing required section: %s" % (log_ini, exc))
        sys.exit(50)

    # set logging verbosity
    if options.verbose == 0:
        log.handlers[0].setLevel(logging.WARNING)
        logging.getLogger("mock_urpm.Root.state").handlers[0].setLevel(logging.WARNING)
    elif options.verbose == 1:
        log.handlers[0].setLevel(logging.INFO)
    elif options.verbose == 2:
        log.handlers[0].setLevel(logging.DEBUG)
        logging.getLogger("mock_urpm.Root.build").propagate = 1
        logging.getLogger("mock-urpm").propagate = 1

    # enable tracing if requested
    logging.getLogger("trace").propagate=0
    if options.trace:
        logging.getLogger("trace").propagate=1

    # cmdline options override config options
    set_config_opts_per_cmdline(config_opts, options, args)

    # verify that we're not trying to build an arch that we can't
    check_arch_combination(config_opts['rpmbuild_arch'], config_opts)

    # default /etc/hosts contents
    if not config_opts['use_host_resolv'] and not config_opts['files'].has_key('etc/hosts'):
        config_opts['files']['etc/hosts'] = '''
127.0.0.1 localhost localhost.localdomain
::1       localhost localhost.localdomain localhost6 localhost6.localdomain6
'''

    # Fetch and prepare sources from SCM
    if config_opts['scm']:
        scmWorker = mock_urpm.scm.scmWorker(log, config_opts['scm_opts'])
        scmWorker.get_sources()
        (options.sources, options.spec) = scmWorker.prepare_sources()

    # elevate privs
    uidManager._becomeUser(0, 0)

    # do whatever we're here to do
    log.info("mock_urpm.py version %s starting..." % __VERSION__)
    chroot = mock_urpm.backend.Root(config_opts, uidManager)

    if options.printrootpath:
        print chroot.makeChrootPath('')
        sys.exit(0)

    # dump configuration to log
    log.debug("mock-urpm final configuration:")
    for k, v in config_opts.items():
        log.debug("    %s:  %s" % (k, v))

    ret["chroot"] = chroot
    ret["config_opts"] = config_opts
    os.umask(002)

    # New namespace starting from here
    try:
        mock_urpm.util.unshare(mock_urpm.util.CLONE_NEWNS)
    except:
        log.info("Namespace unshare failed.")

    # set personality (ie. setarch)
    if config_opts['internal_setarch']:
        mock_urpm.util.condPersonality(config_opts['target_arch'])

    if options.mode == 'init':
        if config_opts['clean']:
            chroot.clean()
        chroot.init()

    elif options.mode == 'clean':
        if len(options.scrub) == 0:
            chroot.clean()
        else:
            chroot.scrub(options.scrub)

    elif options.mode == 'shell':
        chroot.tryLockBuildRoot()
        if not os.path.exists(chroot.makeChrootPath()):
            raise RuntimeError, "chroot %s not initialized!" % chroot.makeChrootPath()
        try:
            chroot._setupDev(interactive=True)
            chroot._mountall()
            cmd = ' '.join(args)
            if options.unpriv:
                arg = '--userspec=%s:%s' % (chroot.chrootuid, chroot.chrootgid)
            else:
                arg = ''
            os.environ.update(chroot.env)
            status = os.system("/usr/sbin/chroot %s %s %s" % (arg, chroot.makeChrootPath(), cmd))
            ret['exitStatus'] = os.WEXITSTATUS(status)

        finally:
            chroot._umountall()
        chroot.unlockBuildRoot()

    elif options.mode == 'chroot':
        shell=False

        res = chroot.GetChrootState()
        if res != "initialized":
            log.critical(res)
            sys.exit(50)

        if len(args) == 0:
            log.critical("You must specify a command to run")
            sys.exit(50)
        elif len(args) == 1:
            args = args[0]
            shell=True

        log.info("Running in chroot: %s" % args)
        chroot.tryLockBuildRoot()
        chroot._resetLogging()
        try:
            chroot._mountall()
            if options.unpriv:
                output = chroot.doChroot(args, shell=shell, env=chroot.env, returnOutput=True, uid=chroot.chrootuid, gid=chroot.chrootgid, cwd=options.cwd)
            else:
                output = chroot.doChroot(args, shell=shell, env=chroot.env, cwd=options.cwd, returnOutput=True)
        finally:
            chroot._umountall()
        chroot.unlockBuildRoot()
        if output:
            print output,

    elif options.mode == 'installdeps':
        if len(args) == 0:
            log.critical("You must specify an SRPM file.")
            sys.exit(50)

        for hdr in mock_urpm.util.yieldSrpmHeaders(args, plainRpmOk=1):
            pass
        chroot.tryLockBuildRoot()
        try:
            chroot._mountall()
            chroot.installSrpmDeps(*args)
        finally:
            chroot._umountall()
        chroot.unlockBuildRoot()

    elif options.mode == 'install':
        if len(args) == 0:
            log.critical("You must specify a package list to install.")
            sys.exit(50)

        chroot._resetLogging()
        chroot.tryLockBuildRoot()
        chroot.urpmInstall(*args)
        chroot.unlockBuildRoot()

    elif options.mode == 'update':
        chroot._resetLogging()
        chroot.tryLockBuildRoot()
        chroot.urpmUpdate()
        chroot.unlockBuildRoot()

    elif options.mode == 'rebuild':
        if config_opts['scm']:
            srpm = do_buildsrpm(config_opts, chroot, options, args)
            if srpm:
                args.append(srpm)
            scmWorker.clean()
        do_rebuild(config_opts, chroot, args)

    elif options.mode == 'buildsrpm':
        do_buildsrpm(config_opts, chroot, options, args)

    elif options.mode == 'orphanskill':
        mock_urpm.util.orphansKill(chroot.makeChrootPath())
    elif options.mode == 'readdrepo':
        chroot.readdrepo()
    elif options.mode == 'copyin':
        chroot.tryLockBuildRoot()
        chroot._resetLogging()
        #uidManager.dropPrivsForever()
        if len(args) < 2:
            log.critical("Must have source and destinations for copyin")
            sys.exit(50)
        dest = chroot.makeChrootPath(args[-1])
        if len(args) > 2 and not os.path.isdir(dest):
            log.critical("multiple source files and %s is not a directory!" % dest)
            sys.exit(50)
        args = args[:-1]
        import shutil
        for src in args:
            log.info("copying %s to %s" % (src, dest))
            if os.path.isdir(src):
                shutil.copytree(src, dest)
            else:
                shutil.copy(src, dest)
        chroot.unlockBuildRoot()

    elif options.mode == 'copyout':
        chroot.tryLockBuildRoot()
        chroot._resetLogging()
        uidManager.dropPrivsForever()
        if len(args) < 2:
            log.critical("Must have source and destinations for copyout")
            sys.exit(50)
        dest = args[-1]
        if len(args) > 2 and not os.path.isdir(dest):
            log.critical("multiple source files and %s is not a directory!" % dest)
            sys.exit(50)
        args = args[:-1]
        import shutil
        for f in args:
            src = chroot.makeChrootPath(f)
            log.info("copying %s to %s" % (src, dest))
            if os.path.isdir(src):
                shutil.copytree(src, dest)
            else:
                shutil.copy(src, dest)
        chroot.unlockBuildRoot()

    chroot.state("end")

def fix_configs(config_path):
    # set default configuration file
    if not os.path.exists(config_path + '/default.cfg'):
        files = os.listdir(config_path)
        print 'Avaliable configurations: '
        out = []
        for f in files:
            if not f.endswith('.cfg'):
                continue
            if f == 'site-defaults.cfg':
                continue
            out.append(f[:-4])

        print ', '.join(out)
        res = None
        while res not in out:
            if res is not None:
                print '"%s" is not a valid configuration.' % res
            res = raw_input('Select one (it will be remembered): ')
        os.symlink(config_path + '/%s.cfg' % res, config_path + '/default.cfg')

def fix_group():
    # check 'mock-urpm' group
    if os.getuid() != 0:
        print "You should have sudo rights to run mock-urpm."
        exit(1)
    rootcheck()

    ingroup, sudo_user = groupcheck(raise_exception=False)
    if not ingroup:
        os.system('groupadd -r -f mock-urpm')
        print 'Adding user %s to group mock-urpm...' % sudo_user
        os.system('usermod -a -G mock-urpm ' + sudo_user)

    #create symlinks
    if not os.path.exists('/etc/bash_completion.d/mock-urpm'):
        os.symlink('/usr/share/bash-completion/mock-urpm', '/etc/bash_completion.d/mock-urpm')
    if not os.path.exists('/usr/bin/mock-urpm'):
        os.symlink('/usr/bin/consolehelper', '/usr/bin/mock-urpm')


if __name__ == '__main__':
    # fix for python 2.4 logging module bug:
    logging.raiseExceptions = 0
    fix_group()

    exitStatus = 0
    killOrphans = 1

    try:
        # sneaky way to ensure that we get passed back parameter even if
        # we hit an exception.
        retParams = {}
        main(retParams)
        exitStatus = retParams.get("exitStatus", exitStatus)

    except (SystemExit,):
        raise

    except (OSError,), e:
        if e.errno == 1:
            print
            log.error("%s" % str(e))
            print
            log.error("The most common cause for this error is trying to run /usr/sbin/mock-urpm as an unprivileged user.")
            log.error("Check your path to make sure that /usr/bin/ is listed before /usr/sbin, or manually run /usr/bin/mock-urpm to see if that fixes this problem.")
            print
        else:
            raise
    except (KeyboardInterrupt,):
        exitStatus = 7
        log.error("Exiting on user interrupt, <CTRL>-C")

    except (mock_urpm.exception.ResultDirNotAccessible,), exc:
        exitStatus = exc.resultcode
        log.error(str(exc))
        killOrphans = 0

    except (mock_urpm.exception.BadCmdline, mock_urpm.exception.BuildRootLocked), exc:
        exitStatus = exc.resultcode
        log.error(str(exc))
        killOrphans = 0

    except (mock_urpm.exception.Error), exc:
        exitStatus = exc.resultcode
        log.error(str(exc))

    except (Exception,), exc:
        exitStatus = 1
        log.exception(exc)

    if killOrphans and retParams:
        mock_urpm.util.orphansKill(retParams["chroot"].makeChrootPath())

    logging.shutdown()
    sys.exit(exitStatus)



