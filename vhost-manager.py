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
import json
import tempfile
import time
import stat
import atexit
import platform


INET_IFACE_NAME = "inet0"
INET_BRIDGE_NAME = "lxcbr0"



__programm__ = "vhost-manager"
__version__  = "1"

pp = pprint.PrettyPrinter(indent=4)

TMPDIR = tempfile.mkdtemp()

class ArgumentException(Exception): pass

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

    def msg(self, msg, stoptime=None):
        ret = sys.stdout.write(msg) - 1
        if stoptime:
            time.sleep(stoptime)
        return ret

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

    def clear(self):
        os.system("clear")


class Utils:

    def exec(self, args):
        print("execute: \"{}\"".format(args))
        os.system(args)
    
    def query_yes_no(self, question, default="yes"):
        valid = {"yes": True, "y": True, "ye": True,
                "no": False, "n": False}
        if default is None:
            prompt = " [y/n] "
        elif default == "yes":
            prompt = " [Y/n] "
        elif default == "no":
            prompt = " [y/N] "
        else:
            raise ValueError("invalid default answer: '%s'" % default)
        
        while True:
            sys.stdout.write(question + prompt)
            choice = input().lower()
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' "
                                 "(or 'y' or 'n').\n")


class Configuration():

    def __init__(self, topology_name):
        self.db = self.load_configuration("conf.json")
        self.topology_name = topology_name

    def load_configuration(self, filename):
        with open(filename) as json_data:
            d = json.load(json_data)
            json_data.close()
            return d

    def is_valid(self):
        for topology in self.db["topologies"]:
            if self.topology_name == topology:
                return True
        raise ArgumentException("topology not found: {}".format(self.topology_name))

    def bridge_handle(self, bridge_name):
        return bridge_name

    def terminal_gen_config(self, terminal_data):
        d = {}
        # standard data always present
        e  = "auto lo\n"
        e += "iface lo inet loopback\n\n"
        e += "auto inet0\n"
        e += "iface inet0 inet dhcp\n\n"

        # Debian Network section
        for interface_name, interface_data in terminal_data["interfaces"].items():
            e += "auto {}\n".format(interface_name)
            e += "iface {} inet static\n".format(interface_name)
            e += "  address {}\n".format(interface_data["ipv4-addr"])
            e += "  netmask {}\n".format(interface_data["ipv4-addr-netmask"])
            if "post-up" in interface_data:
                assert isinstance(interface_data["post-up"], list)
                for line in interface_data["post-up"]:
                    e += "  post-up {}\n".format(line)
            e += "\n"
        d["conf-debian-interface"] = e

        # LXC section
        e  = "lxc.network.type = veth\n"
        e += "lxc.network.name = {}\n".format(INET_IFACE_NAME)
        e += "lxc.network.flags = up\n"
        e += "lxc.network.link = {}\n".format(INET_BRIDGE_NAME)
        e += "lxc.network.hwaddr = 00:11:xx:xx:xx:xx\n\n"
        
        for interface_name, interface_data in terminal_data["interfaces"].items():
            e += "lxc.network.type = veth\n"
            e += "lxc.network.name = {}\n".format(interface_name)
            e += "lxc.network.flags = up\n"
            e += "lxc.network.link = {}\n".format(interface_data["lxr-link"])
            e += "lxc.network.hwaddr = {}\n\n".format(interface_data["lxr-hw-addr"])
        d["conf-lxc"] = e
        return d

    def terminal_handle(self, terminal_name):
        d = dict()
        if terminal_name not in self.db["devices"]["terminals"]:
            print("terminal {} not defined".format(terminal_name)) 
            sys.exit(1)
        terminal = self.db["devices"]["terminals"][terminal_name]
        d['config'] = self.terminal_gen_config(terminal)
        return d

    def load_topo(self):
        topo = self.db["topologies"][self.topology_name]
        ret = dict()
        ret['terminals'] = list()
        ret['routers'] = list()
        ret['ues'] = list()
        ret['bridges'] = list()
        for k, v in topo["topo"].items():
            if k == "bridges":
                for bridge in v:
                    e = self.bridge_handle(bridge)
                    ret['bridges'].append([bridge, e])
            if k == "terminals":
                for terminal in v:
                    e = self.terminal_handle(terminal)
                    ret['terminals'].append([terminal, e])
        return ret



class BridgeCreator():
    pass


class HostCreator():

    def __init__(self, utils, name, config):
        self.u = utils
        self.name = name
        self.config = config
        self.container = None

    def remove_tmp_files(self):
        close(self.tf_lxc)
        close(self.tf_net)

    def tmp_file_new(self, string):
        name = os.path.join(TMPDIR, string)
        fd = open(name,"w")
        return fd, name

    def tmp_file_destroy(self, name):
        os.remove(name)

    def create_container(self):
        fd, name = self.tmp_file_new("lxc-conf")
        config = self.config['config']['conf-lxc']
        fd.write(config)
        os.fsync(fd); fd.close()

        # sudo LC_ALL=C lxc-create --bdev dir -f $(dirname "${BASH_SOURCE[0]}")/lxc-config -n $name -t $distribution --logpriority=DEBUG --logfile $logpath -- -r xenial")
        cmd  = "sudo LC_ALL=C lxc-create --bdev dir -n {} ".format(self.name)
        cmd += "-f {} -t ubuntu -- -r xenial".format(name)
        self.u.exec(cmd)
        self.tmp_file_destroy(name)

    def start_container(self):
        self.u.exec("sudo lxc-start -n {} -d".format(self.name))
        self.container = lxc.Container(self.name)

    def stop_container(self):
        self.u.exec("sudo lxc-stop -n {}".format(self.name))

    def copy_interface_conf(self):
        tmp_fd, tmp_name = self.tmp_file_new("lxc-conf")
        config = self.config['config']['conf-debian-interface']
        tmp_fd.write(config)
        os.fsync(tmp_fd); tmp_fd.close()

        cmd  = "cat {} | lxc-attach -n {} ".format(tmp_name, self.name)
        cmd += " --clear-env -- bash -c 'cat >/etc/network/interfaces'"
        self.u.exec(cmd)
        time.sleep(.5)

        self.tmp_file_destroy(tmp_name)



    def create(self):
        self.create_container()
        self.start_container()
        self.copy_interface_conf()

        #u.exec("cat $(dirname "${BASH_SOURCE[0]}")/etc.network.interfaces | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/etc/network/interfaces'")
        #u.exec("sudo lxc-stop -n $name")
        #u.exec("sudo lxc-start -n $name -d")
        #u.exec("sudo lxc-attach -n  $name --clear-env -- bash -c 'mkdir -p /etc/olsrd/'")
        #u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/post-install-phase-01.sh | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/tmp/post-install-phase-01.sh'")
        #u.exec("lxc-exec-root $name "/tmp/post-install-phase-01.sh"")
        #u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/vimrc | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/home/admin/.vimrc'")
        #u.exec("cat $HOME/.bashrc | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/home/admin/.bashrc'")
        #u.exec("cat /etc/apt/apt.conf | sudo lxc-attach -n  $name --clear-env -- bash -c 'cat >/etc/apt/apt.conf'")
        #u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/post-install-phase-02.sh | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/tmp/post-install-phase-02.sh'")
        #u.exec("lxc-exec $name "admin" "bash /tmp/post-install-phase-02.sh"")
        #u.exec("cat $(dirname "${BASH_SOURCE[0]}")/../shared/post-install-phase-03.sh | sudo lxc-attach -n $name --clear-env -- bash -c 'cat >/tmp/post-install-phase-03.sh'")
        #u.exec("lxc-exec $name "admin" "bash /tmp/post-install-phase-03.sh"")
        #u.exec("sudo lxc-stop -n $name")


class Creator():

    def __init__(self):
        self.u = Utils()
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

    def create_bridge(self, name, bridge):
        print("create bridge: {}".format(bridge))

    def create_host(self, name, config):
        h = HostCreator(self.u, name, config)
        h.create()

    def create_terminal(self, name, terminal):
        self.create_host(name, terminal)

    def create_router(self, name, router):
        self.create_host(name, router)

    def create_ue(self, name, ue):
        self.create_host(name, ue)

    def checktopo(self, topo):
        searched = ('terminals', 'routers', 'ues')
        for search in searched:
            for name, data in topo[search]:
                print(name)
                c = lxc.Container(name)
                if c.defined:
				
                    print("Container already exists")
                    question = "Delete container or exit?"
                    answer = self.u.query_yes_no(question, default="no")
                    if answer == True:
                        print("Delete container in 5 seconds ...")
                        time.sleep(5)
                        c.stop()
                        if not c.destroy():
                            print("Failed to destroy the container!")
                            sys.exit(1)
                    else:
                        print("exiting, call \"sudo lxc-ls --fancy\" to see all container")
                        exit(1)


    def run(self):
        try:
            c = Configuration(self.args.topology)
        except ArgumentException as e:
            print("not a valid topology: {}".format(e))
            sys.exit(1)
        topo = c.load_topo()
        self.checktopo(topo)
        for name, data in topo['bridges']:
            self.create_bridge(name, data)
        for name, data in topo['terminals']:
            self.create_terminal(name, data)
        for name, data in topo['routers']:
            self.create_router(name, data)
        for name, data in topo['ues']:
            self.create_ue(name, data)


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
        self.p = Printer()
        self.check_env()

    def install_packages_ubuntu(self):
        os.system("apt-get --yes --force-yes install lxc tmux")
        return True

    def install_packages_arch(self):
        os.system("pacman -Sy --noconfirm ebtables community/lxc community/debootstrap community/tmux")
        return True

    def check_installed_packages(self):
        distribution = platform.linux_distribution()
        if distribution[0] == "Ubuntu":
            self.p.msg("seems you are using Ubuntu, great ...\n")
            return self.install_packages_ubuntu()
        elif distribution[0] == "Arch":
            self.p.msg("seems you are using Arch, great ...\n")
            return self.install_packages_arch()
        else:
            self.p.msg("Can't figure out your distribution\n")

        return False

    def first_startup(self):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        touch_dir  = os.path.join(script_dir, "tmp")
        touch_file = os.path.join(touch_dir, "already-started")
        if not os.path.isfile(touch_file):
            self.p.clear()
            self.p.msg("Welcome!\n", stoptime=.5)
            self.p.msg("Seems you are new - great!\n", stoptime=1.0)
            self.p.msg("I will make sure every requird package is installed ...\n")
            ok = self.check_installed_packages()
            if ok:
                os.makedirs(touch_dir, exist_ok=True)
                with open(touch_file, "w") as f:
                    f.write("{}".format(time.time()))
        
        sys.exit(0)


    def check_env(self):
        self.first_startup()


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

def remove_tmp_dir():
    shutil.rmtree(TMPDIR, ignore_errors=True)

if __name__ == "__main__":
    try:
        atexit.register(remove_tmp_dir)
        euid = os.geteuid() 
        if euid != 0:
            print("Need to be root")
            print("➡ sudo {}".format(sys.argv[0]))
            exit(1)

        vhm = VHostManager()
        sys.exit(vhm.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
