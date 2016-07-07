#!/usr/bin/env python3
# encoding: utf-8

import lxc
import sys
import logging
import argparse
import socket
import os
import inspect
import shutil
import pprint
import locale


__programm__ = ""
__version__  = "1"

pp = pprint.PrettyPrinter(indent=4)



class Printer:

    def __init__(self, verbose=False):
        self.verbose = verbose

    def set_verbose(self):
        self.verbose = True

    def err(self, msg):
        sys.stderr.write(msg)

    def verbose(self, msg):
        if not self.verbose:
            return
        sys.stderr.write(msg)

    def msg(self, msg):
        return sys.stdout.write(msg) - 1

    def line(self, length, char='-'):
        sys.stdout.write(char * length + "\n")

    def msg_underline(self, msg, pre_news=0, post_news=0):
        str_len = len(msg)
        if pre_news:
            self.msg("\n" * pre_news)
        self.msg(msg)
        self.msg("\n" + '=' * str_len)
        if post_news:
            self.msg("\n" * post_news)



class Utils:

    def exec(self, args):
        os.system(args)


class HostCreator():


    def __init__(self, config):
        self.u = Utils()
        self.config = config

    def create(self):
        u.exec("sudo LC_ALL=C lxc-create --bdev dir -f $(dirname "${BASH_SOURCE[0]}")/lxc-config -n $name -t $distribution --logpriority=DEBUG --logfile $logpath -- -r xenial")
        u.exec("sudo lxc-start -n $name -d")
        u.exec("cat $(dirname "${BASH_SOURCE[0]}")/etc.network.interfaces | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/etc/network/interfaces'")
        u.exec("sudo lxc-stop -n $name")
        u.exec("sudo lxc-start -n $name -d")
        u.exec("sudo lxc-attach -n  $name --clear-env -- bash -c 'mkdir -p /etc/olsrd/'")
        u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/post-install-phase-01.sh | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/tmp/post-install-phase-01.sh'")
        u.exec("lxc-exec-root $name "/tmp/post-install-phase-01.sh"")
        u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/vimrc | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/home/admin/.vimrc'")
        u.exec("cat $HOME/.bashrc | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/home/admin/.bashrc'")
        u.exec("cat /etc/apt/apt.conf | sudo lxc-attach -n  $name --clear-env -- bash -c 'cat >/etc/apt/apt.conf'")
        u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/post-install-phase-02.sh | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/tmp/post-install-phase-02.sh'")
        u.exec("lxc-exec $name "admin" "bash /tmp/post-install-phase-02.sh"")
        u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/post-install-phase-03.sh | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/tmp/post-install-phase-03.sh'")
        u.exec("lxc-exec $name "admin" "bash /tmp/post-install-phase-03.sh"")
        u.exec("sudo lxc-stop -n $name")


class Creator():

    def __init__(self):
        self.p = Printer()
        self.parse_local_options()


    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument( "-v", "--verbose", dest="verbose", default=False,
                          action="store_true", help="show verbose")
        parser.add_argument("topology", help="name of the topology", type=str)
        self.args = parser.parse_args(sys.argv[2:])
        if self.args.verbose:
            self.p.set_verbose()

    def run(self):
        h = HostCreator()
        h.create()



class Lister():

    def __init__(self):
        self.p = Printer()
        self.parse_local_options()


    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument( "-v", "--verbose", dest="verbose", default=False,
                          action="store_true", help="show verbose")
        self.args = parser.parse_args(sys.argv[2:])
        if self.args.verbose:
            self.p.set_verbose()

    def run(self):
        print("Available container: ")
        for container in lxc.list_containers(as_object=True):
            print(container.name)
            if not container.running:
                print("\tnot running ")
            else:
                print("\t    running ")






class VHostManager:

    modes = {
       "create": [ "Creator",    "create topologies" ],
       "list":   [ "Lister",     "list available container" ]
            }

    def __init__(self):
        pass


    def print_version(self):
        sys.stdout.write("%s\n" % (__version__))

    def print_usage(self):
        sys.stderr.write("Usage: vhost-manager [-h | --help]" +
                         " [--version]" +
                         " <submodule> [<submodule-options>]\n")

    def print_modules(self):
        for i in VHostManager.modes.keys():
            sys.stderr.write("   %-15s - %s\n" % (i, VHostManager.modes[i][1]))

    def args_contains(self, argv, *cmds):
        for cmd in cmds:
            for arg in argv:
                if arg == cmd: return True
        return False

    def parse_global_otions(self):
        if len(sys.argv) <= 1:
            self.print_usage()
            sys.stderr.write("Available submodules:\n")
            self.print_modules()
            return None

        self.binary_path = sys.argv[-1]

        # --version can be placed somewhere in the
        # command line and will evalutated always: it is
        # a global option
        if self.args_contains(sys.argv, "--version"):
            self.print_version()
            return None

        # -h | --help as first argument is treated special
        # and has other meaning as a submodule
        if self.args_contains(sys.argv[1:2], "-h", "--help"):
            self.print_usage()
            sys.stderr.write("Available modules:\n")
            self.print_modules()
            return None

        submodule = sys.argv[1].lower()
        if submodule not in VHostManager.modes:
            self.print_usage()
            sys.stderr.write("Modules \"%s\" not known, available modules are:\n" %
                             (submodule))
            self.print_modules()
            return None

        classname = VHostManager.modes[submodule][0]
        return classname


    def run(self):
        classtring = self.parse_global_otions()
        if not classtring:
            return 1

        classinstance = globals()[classtring]()
        classinstance.run()
        return 0


if __name__ == "__main__":
    try:
        vhm = VHostManager()
        sys.exit(vhm.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
