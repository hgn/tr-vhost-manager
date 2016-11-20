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
import pwd
import collections
import urllib
import re

# interface/bridge for local internet bridging
INET_IFACE_NAME = "inet0"
INET_BRIDGE_NAME = "lxcbr0"

# debug interface for debugging
DEBUG_IFACE_NAME = "debug0"
DEBUG_BRIDGE_NAME = "brdebug0"
DEBUG_IFACE_V4_ADDR = "1.1.1.250"
DEBUG_IFACE_V4_MASK = 16

__programm__ = "vhost-manager"
__version__  = "1"

pp = pprint.PrettyPrinter(indent=4)

TMPDIR = tempfile.mkdtemp()
DEBUG  = False

class ConfigurationException(Exception): pass
class ArgumentException(Exception): pass
class EnvironmentException(Exception): pass
class InternalException(Exception): pass


class TopologyDb(object):

    def __init__(self, connections, directed=False):
        self._graph = collections.defaultdict(set)
        self._directed = directed
        self.add_connections(connections)

    def format(self, thing):
        fmt = "\"{}\" [ {} ]\n".format(str(thing), thing.graphviz_repr())
        return fmt

    def gen_digraph(self):
        d  =  "digraph foo { node [ fontname = \"DejaVu Sans\" ];"
        d += " edge [ fontname = \"DejaVu Sans\" ];\n\n"

        done = []
        for k, v in self._graph.items():
            for v2 in v:
                if str(k) in done: continue
                d += self.format(k)
                done.append(str(k))
            if str(v2) in done: continue
            d += self.format(v2)
            done.append(v2.graphviz_repr())
        d += "\n"

        for k, v in self._graph.items():
            for v2 in v:
                ks = str(k)
                vs = str(v2)
                d += "  \"{}\" -> \"{}\" [ arrowhead = \"none\", arrowtail = \"normal\"];\n".format(ks, vs)
        d += "}\n"
        return d

    def get_bridges(self):
        ret = []
        for k, v in self._graph.items():
            for v2 in v:
                if v2 is not None and isinstance(v2, Bridge):
                    ret.append(v2)
            if k is not None and isinstance(k, Bridge):
                ret.append(k)

        done = []; reti = []
        for bridge in ret:
            if bridge.name in done:
                continue
            done.append(bridge.name)
            reti.append(bridge)
        return reti

    def get_hosts(self):
        ret = []
        for k, v in self._graph.items():
            for v2 in v:
                if v2 is not None and isinstance(v2, Host):
                    ret.append(v2)
            if k is not None and isinstance(k, Host):
                ret.append(k)

        done = []; reti = []
        for host in ret:
            if host.name in done:
                continue
            done.append(host.name)
            reti.append(host)
        return reti

    def add_connections(self, connections):
        if not connections: return
        for node1, node2 in connections:
            self.add(node1, node2)

    def add(self, node1, node2):
        self._graph[node1].add(node2)
        if not self._directed:
            self._graph[node2].add(node1)

    def remove(self, node):
        for n, cxns in self._graph.iteritems():
            try:
                cxns.remove(node)
            except KeyError:
                pass
        try:
            del self._graph[node]
        except KeyError:
            pass

    def is_connected(self, node1, node2):
        return node1 in self._graph and node2 in self._graph[node1]

    def find_path(self, node1, node2, path=[]):
        path = path + [node1]
        if node1 == node2:
            return path
        if node1 not in self._graph:
            return None
        for node in self._graph[node1]:
            if node not in path:
                new_path = self.find_path(node, node2, path)
                if new_path:
                    return new_path
        return None

    def __str__(self):
        return '{}({})'.format(self.__class__.__name__, dict(self._graph))

    def destroy_bridges(self):
        for bridge in self.get_bridges():
            bridge.destroy()

    def destroy_hosts(self):
        for host in self.get_hosts():
            host.destroy()

    def stop_hosts(self):
        for host in self.get_hosts():
            host.stop()



class Host:

    def __init__(self, name, p, u, c, h):
        self.u = u
        self.c = c
        self.p = p
        self.name = name
        self.config = h
        self.container = None
        self.init_user_credentials()

    def __str__(self):
        return "{}".format(self.name)

    def init_user_credentials(self):
        userdata = self.c.db["user"]
        self.username = userdata["username"]
        self.userpass = userdata["userpass"]

    def remove_tmp_files(self):
        close(self.tf_lxc)
        close(self.tf_net)

    def tmp_file_new(self, string):
        name = os.path.join(TMPDIR, string)
        fd = open(name, "w")
        return fd, name

    def tmp_file_destroy(self, name):
        if DEBUG: return
        os.remove(name)

    def create_container(self):
        fd, name = self.tmp_file_new("lxc-conf")
        config = self.config['config']['conf-lxc']
        ret = fd.write(config)
        os.fsync(fd); fd.close()

        # sudo LC_ALL=C lxc-create --bdev dir -f $(dirname "${BASH_SOURCE[0]}")/lxc-config
        # -n $name -t $distribution --logpriority=DEBUG --logfile $logpath -- -r xenial")
        # FIXME: logging should be activatable
        cmd  = "sudo LC_ALL=C lxc-create --bdev dir -n {} ".format(self.name)
        cmd += "-f {} -t ubuntu -- -r xenial".format(name)
        self.u.exec(cmd)
        self.tmp_file_destroy(name)

    def start_container(self):
        self.u.exec("sudo lxc-start -n {} -d".format(self.name))
        self.container = lxc.Container(self.name)

    def stop_container(self):
        self.u.exec("sudo lxc-stop -n {}".format(self.name))

    def restart_container(self):
        self.stop_container()
        self.start_container()

    def exec(self, cmd, user=None):
        if user:
            cmd = "lxc-attach -n {} --clear-env -- bash -c \"su - {} -c \'{}\'\"".format(self.name, user, cmd)
        else:
            cmd = "lxc-attach -n {} --clear-env -- bash -c \"{}\"".format(self.name, cmd)
        self.u.exec(cmd)

    def container_file_copy(self, name, src_path, dst_path, user=None):
        cmd  = "cat {} | lxc-attach -n {} ".format(src_path, name)
        cmd += " --clear-env -- bash -c 'cat >{}'".format(dst_path)
        self.u.exec(cmd)
        # we don't want a race here: we don't know when the new process
        # is scheduled, so we sleep here for a short period, just to make sure[TM]
        # that the new process is executed.
        time.sleep(.5)
        if user:
            self.exec("chown -R {}:{} {}".format(user, user, dst_path))

    def copy_interface_conf(self):
        tmp_fd, tmp_name = self.tmp_file_new("lxc-conf")
        config = self.config['config']['conf-debian-interface']
        tmp_fd.write(config)
        os.fsync(tmp_fd); tmp_fd.close()
        self.container_file_copy(self.name, tmp_name, "/etc/network/interfaces")
        self.tmp_file_destroy(tmp_name)

    def create_user_account(self):
        self.exec("useradd --create-home --shell /bin/bash --user-group {}".format(self.username))
        self.exec("echo '{}:{}' | chpasswd".format(self.username, self.userpass))
        self.exec("echo '{} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers".format(self.username))

    def create_ssh_environment(self):
        ssh_dir = os.path.join("/home", self.username, ".ssh")
        self.exec("mkdir -p {}".format(ssh_dir), user=self.username)
        src_ssh_pub_path = os.path.join("tmp", "ssh-id-rsa.pub")
        if not os.path.isfile(src_ssh_pub_path):
            raise InternalException("ssh-id-rsa.pub not found {}".format(src_ssh_pub_path))
        dst_ssh_path = os.path.join(ssh_dir, "authorized_keys",)
        self.container_file_copy(self.name, src_ssh_pub_path, dst_ssh_path, user=self.username)

    def user_home_dir(self):
        # this function handles also SUDO invoked calls
        if "SUDO_UID" not in os.environ:
            path = pwd.getpwuid(os.getresuid()[0])[5]
        else:
            path = pwd.getpwuid(int(os.getenv("SUDO_UID")))[5]
        return path

    def copy_dotfiles_plain(self, assets_dir):
        vimrc_path = os.path.join(assets_dir, "vimrc")
        dst_home_path = os.path.join("/home", self.username)
        assert os.path.isfile(vimrc_path)
        dst_path = os.path.join(dst_home_path, ".vimrc")
        self.container_file_copy(self.name, vimrc_path, dst_path, user=self.username)

        # bashrc, if user has local one we prefer this one (e.g. proxy settings)
        # note: we assume here the user is using sudo, the real user home path
        effective_home_path = self.user_home_dir()
        bashrc_path = os.path.join(effective_home_path, ".bashrc")
        dst_path = os.path.join(dst_home_path, ".bashrc")
        if not os.path.isfile(bashrc_path):
            # take own provided bashrc
            bashrc_path = os.path.join(assets_dir, "bashrc")
        self.container_file_copy(self.name, bashrc_path, dst_path, user=self.username)
        # we copy bashrc to root too, just that potential proxy settings are
        # also available for root too
        self.container_file_copy(self.name, bashrc_path, "/root/.bashrc")


    def copy_dotfiles(self):
        root_dir = os.path.dirname(os.path.realpath(__file__))
        assets_dir = os.path.join(root_dir, "assets")
        self.copy_dotfiles_plain(assets_dir)

    def copy_distribution_specific(self):
        # apt.conf contains proxy settings
        script_dir = os.path.dirname(os.path.realpath(__file__))
        src_path = os.path.join(script_dir, "tmp", "apt.conf")
        dst_path = "/etc/apt/apt.conf"
        if os.path.isfile(src_path):
            self.container_file_copy(self.name, src_path, dst_path)

        # wget for proxy things
        src_path = os.path.join(script_dir, "tmp", "wgetrc")
        dst_path = "/etc/wgetrc"
        if os.path.isfile(src_path):
            self.container_file_copy(self.name, src_path, dst_path)

    def install_base_packages(self):
        self.exec("apt-get -y update")
        self.exec("apt-get -y install git vim bash python3")
        # we do not want that our recently written wget conf is
        # overwritten.
        self.exec('apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install wget')

    def bootstrap_packages(self):
        self.exec("git clone https://github.com/hgn/tr-bootstrapper.git", user=self.username)
        self.exec("python3 tr-bootstrapper/bootstrap.py -vvv", user=self.username)

    def set_utc_timezone(self):
        # http://yellerapp.com/posts/2015-01-12-the-worst-server-setup-you-can-make.html
        self.exec("echo 'Etc/UTC' > /etc/timezone")
        self.exec("dpkg-reconfigure --frontend noninteractive tzdata")

    def create(self):
        self.p.msg("Create container: {}\n".format(self), stoptime=1.0)
        self.create_container()
        self.start_container()
        self.copy_interface_conf()
        self.restart_container()
        self.create_user_account()
        self.set_utc_timezone()
        self.copy_dotfiles()
        self.create_ssh_environment()
        self.copy_distribution_specific()
        self.install_base_packages()
        self.bootstrap_packages()
        self.stop_container()

    def destroy(self):
        c = lxc.Container(self.name)
        if c.defined:
            question = "Delete container {}?".format(self.name)
            answer = self.u.query_yes_no(question, default="no")
            if answer == True:
                self.p.msg("Delete container in 2 seconds ...\n", color="red", stoptime=2.0)
                c.stop()
                if not c.destroy():
                    self.p.msg("Failed to destroy the container!\n", color="red")
                    sys.exit(1)
        else:
            self.p.msg("Container {} not available, cannot delete non-existing\n".format(self.name))

    def start(self):
        c = lxc.Container(self.name)
        if not c.defined:
            self.p.msg("Topology not created, at least {} not created".format(self.name), color="red")
            sys.exit(1)
            return
        c.start()

    def stop(self):
        c = lxc.Container(self.name)
        if not c.defined:
            self.p.msg("Topology not created, at least {} not created".format(self.name), color="red")
            sys.exit(1)
            return
        c.stop()


class Terminal(Host):

    def graphviz_repr(self):
        iface_info = ""
        for k, v in sorted(self.config['terminal-data']['interfaces'].items()):
            a = v['ipv4-addr']
            n = v['ipv4-addr-netmask']
            c = "{}/{}".format(a, n)
            iface_info += "<font point-size=\"4\">{} IPv4: {}<br/></font>\n".format(k, c)

        t = "Terminal"
        fmt  = "label = <<font color=\"blue\">{}</font><br/>".format(self.name)
        fmt += iface_info
        fmt += "<font point-size=\"6\">{}</font>>".format(t)
        fmt += ",shape = \"box\""
        return fmt

    def __str__(self):
        return "Terminal({})".format(self.name)


class Router(Host):

    def graphviz_repr(self):
        iface_info = ""
        for k, v in sorted(self.config['terminal-data']['interfaces'].items()):
            a = v['ipv4-addr']
            n = v['ipv4-addr-netmask']
            c = "{}/{}".format(a, n)
            iface_info += "<font point-size=\"4\">{} IPv4: {}<br/></font>\n".format(k, c)

        t = "Router"
        fmt  = "label = <<font color=\"blue\">{}</font><br/>".format(self.name)
        fmt += iface_info
        fmt += "<font point-size=\"6\">{}</font>>".format(t)
        fmt += ",shape = \"box\""
        return fmt

    def __str__(self):
        return "Router({})".format(self.name)


class UE(Host):

    def graphviz_repr(self):
        iface_info = ""
        for k, v in sorted(self.config['terminal-data']['interfaces'].items()):
            a = v['ipv4-addr']
            n = v['ipv4-addr-netmask']
            c = "{}/{}".format(a, n)
            iface_info += "<font point-size=\"4\">{} IPv4: {}<br/></font>\n".format(k, c)

        t = "UE"
        fmt  = "label = <<font color=\"blue\">{}</font><br/>".format(self.name)
        fmt += iface_info
        fmt += "<font point-size=\"6\">{}</font>>".format(t)
        fmt += ",shape = \"box\""
        return fmt

    def __str__(self):
        return "UE({})".format(self.name)


class Bridge:

    def __init__(self, name, p, u, c, h):
        self.name = name
        self.p = p
        self.u = u
        self.c = c
        self.netem = self.__deserialize_netem(h)


    def __construct_netem_cmd(self, data):
        cmd = ""
        for k, v in data.items():
            if type(v) == list:
                fv = ""
                for vv in v:
                    fv += "{} ".format(vv)
            elif type(v) == str:
                fv = v
            else:
                raise "format not supported {}".format(type(v))
            cmd += " {} {}".format(k, fv)
        return cmd


    def __construct_netem_atoms(self, data):
        return data


    def __parse_netem_static(self, data):
        d = dict()
        d["class"] = data["class"]
        d["description"] = data["description"]
        d["cmd-start"] = self.__construct_netem_cmd(data["data"])
        d["atoms"] = self.__construct_netem_atoms(data["data"])
        return d


    def __parse_netem_dynamic(self, data):
        d = dict()
        d["class"] = data["class"]
        d["description"] = data["description"]
        d["cmd-start"] = self.__construct_netem_cmd(data["data"])
        d["atoms"] = self.__construct_netem_atoms(data["data"])

        ar = []
        for line in data["op-data"]:
            dd = dict()
            dd["time"] = line[0]
            dd["cmd"] = self.__construct_netem_cmd(line[1])
            dd["atoms"] = self.__construct_netem_atoms(line[1])
            ar.append(dd)
        d["cmd-runs"] = ar
        return d


    def __deserialize_netem(self, h):
        if h is None:
            return None
        if "description" not in h:
            raise ConfigurationException("Netem class has no description: {}\n".format(h))
        if "class" not in h:
            raise ConfigurationException("Netem class has no class: {}\n".format(h))
        if "data" not in h:
            raise ConfigurationException("Netem class has no data: {}\n".format(h))
        if h["class"] == "dynamic" and not "op-data" in h:
            raise ConfigurationException("Netem class is dyanmic but no op-data given{}\n".format(h))

        if h["class"] == "static":
            return self.__parse_netem_static(h)
        # dynmic case
        return self.__parse_netem_dynamic(h)


    def __str__(self):
        return "Bridge({})".format(self.name)

    @staticmethod
    def create_debug_bridge():
        sys.stderr.write("Create debug bridge: {}\n".format(DEBUG_BRIDGE_NAME))
        brige_path = os.path.join("/sys/class/net", DEBUG_BRIDGE_NAME)
        if os.path.isdir(brige_path):
            sys.stderr.write("debug bridge {} already created\n".format(DEBUG_BRIDGE_NAME))
            return
        Utils.sexec("brctl addbr {}".format(DEBUG_BRIDGE_NAME))
        Utils.sexec("brctl setfd {} 0".format(DEBUG_BRIDGE_NAME))
        Utils.sexec("brctl sethello {} 5".format(DEBUG_BRIDGE_NAME))
        Utils.sexec("ip link set dev {} up".format(DEBUG_BRIDGE_NAME))
        Utils.sexec("ip addr add {}/{} dev {}".format(DEBUG_IFACE_V4_ADDR, DEBUG_IFACE_V4_MASK, DEBUG_BRIDGE_NAME))

    @staticmethod
    def destroy_debug_bridge():
        brige_path = os.path.join("/sys/class/net", DEBUG_BRIDGE_NAME)
        if not os.path.isdir(brige_path):
            return
        sys.stderr.write("Delete bridge {}\n".format(DEBUG_BRIDGE_NAME))
        Utils.sexec("ip link set dev {} down".format(DEBUG_BRIDGE_NAME))
        Utils.sexec("brctl delbr {}".format(DEBUG_BRIDGE_NAME))

    @staticmethod
    def netem_exec(bridge_name, cmd):
        cmd =  "tc qdisc change dev {} root netem {}".format(bridge_name, cmd)
        print("  bridge exec: {}".format(cmd))
        Utils.sexec(cmd)

    def create(self):
        self.p.msg("Create bridge: {}\n".format(self.name))
        brige_path = os.path.join("/sys/class/net", self.name)
        if os.path.isdir(brige_path):
            self.p.msg("bridge {} already created\n".format(self.name), color="magenta")
            return
        self.u.exec("brctl addbr {}".format(self.name))
        self.u.exec("brctl setfd {} 0".format(self.name))
        self.u.exec("brctl sethello {} 5".format(self.name))
        self.u.exec("ip link set dev {} up".format(self.name))

    def destroy(self):
        brige_path = os.path.join("/sys/class/net", self.name)
        if not os.path.isdir(brige_path):
            return
        self.p.msg("Delete bridge {}\n".format(self.name))
        self.u.exec("ip link set dev {} down".format(self.name))
        self.u.exec("brctl delbr {}".format(self.name))

    def graphviz_repr(self):
        netem = " "
        if self.netem and 'cmd' in self.netem:
            netem = "Netem: {}".format(self.netem['cmd'])
        fmt  = "label = <<font point-size=\"6\">Bridge: {}</font><br/>".format(self.name)
        fmt += "<font point-size=\"4\">{}</font>>".format(netem)
        fmt += ",shape = \"rect\""
        return fmt

    def __connected_interfaces(self):
        path = "/sys/devices/virtual/net/{}/brif/".format(self.name)
        if not os.path.isdir(path):
            self.p.msg("device not available, topology started?", color="red")
            return None
        return os.listdir(path)

    def start_netem(self):
        if not self.netem:
            # nothin to do, skip this bridge
            return
        veth_names = self.__connected_interfaces()
        for veth_name in veth_names:
            self.p.msg("apply netem rule to interface {}\n".format(veth_name), color=None)
            self.p.msg(" netem cmd: {}\n".format(self.netem["cmd"]), color=None)
            self.u.exec("tc qdisc add dev {} root netem {}".format(veth_name, self.netem["cmd"]))


class Printer:

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.init_colors()

    def init_colors(self):
        self.color_palette = {
                'red':    '\033[31m',
                'green':  '\033[32m',
                'yellow': '\033[33m',
                'blue':   '\033[34m',
                'magenta':'\033[35m',
                'cyan':   '\033[36m',

                'lightred':    '\033[91m',
                'lightgreen':  '\033[92m',
                'lightyellow': '\033[93m',
                'lightblue':   '\033[94m',
                'lightmagenta':'\033[95m',
                'lightcyan':   '\033[96m',

                'end':'\033[0m'
                }
        is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        if not is_a_tty:
            for key, value in self.color_palette.items():
                self.color_palette[key] = ""

    def set_verbose(self):
        self.verbose = True

    def err(self, msg):
        sys.stderr.write(msg)

    def verbose(self, msg):
        if not self.verbose:
            return
        sys.stderr.write(msg)

    def msg(self, msg, stoptime=None, color="yellow", clear=False):
        if clear: self.clear()
        if color:
            if color in self.color_palette:
                msg = "{}{}{}".format(self.color_palette[color], msg, self.color_palette['end'])
            else:
                raise InternalException("Color not known")
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

    @staticmethod
    def sexec(args):
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

    def valid_url(self, url):
        import urllib.parse
        # see https://docs.python.org/3.0/library/urllib.parse.html
        # for valid attributes to check
        to_check = ("scheme", "netloc")
        token = urllib.parse.urlparse(url)
        return all([getattr(token, qualifying_attr) for qualifying_attr in to_check])

    @staticmethod
    def get_tree_size(path):
        total = 0
        for entry in os.scandir(path):
            if entry.is_dir(follow_symlinks=False):
                total += Utils.get_tree_size(entry.path)
            else:
                total += entry.stat(follow_symlinks=False).st_size
        return total

    @staticmethod
    def human_byte_size(size):
        suffixes = ('B','KB','MB','GB','TB')
        suffix_index = 0
        while size > 1024 and suffix_index < len(suffixes) - 1:
            suffix_index += 1
            size = size / 1024.0
        return "{:.2f}{}".format(size, suffixes[suffix_index])

class Configuration():

    def __init__(self, topology=None):
        self.db = self.load_configuration("conf.json")
        self.topology_name = topology

    def load_configuration(self, filename):
        with open(filename) as json_data:
            d = json.load(json_data)
            json_data.close()
            return d

    def topologies(self):
        r = []
        for k, v in self.db["topologies"].items():
            r.append([k, v["description"]])
        return r

    def is_valid(self):
        for topology in self.db["topologies"]:
            if self.topology_name == topology:
                return True
        raise ArgumentException("topology not found: {}".format(self.topology_name))

    def terminal_gen_config(self, terminal_data):
        d = {}

        # standard data always present
        e  = "auto lo\n"
        e += "iface lo inet loopback\n\n"

        # upstream interface towards "internet"
        e += "auto inet0\n"
        e += "iface inet0 inet dhcp\n\n"

        # for debug interface
        e += "auto {}\n".format(DEBUG_IFACE_NAME)
        e += "iface {} inet static\n".format(DEBUG_IFACE_NAME)
        e += "  address {}\n".format(terminal_data['interface-debug']["ipv4-addr"])
        e += "  netmask {}\n\n".format(terminal_data['interface-debug']["ipv4-addr-netmask"])

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

        # LXC section for debug interface
        e += "lxc.network.type = veth\n"
        e += "lxc.network.name = {}\n".format(DEBUG_IFACE_NAME)
        e += "lxc.network.flags = up\n"
        e += "lxc.network.link = {}\n".format(DEBUG_BRIDGE_NAME)
        e += "lxc.network.hwaddr = 00:00:xx:xx:xx:xx\n\n"
        
        for interface_name, interface_data in terminal_data["interfaces"].items():
            e += "lxc.network.type = veth\n"
            e += "lxc.network.name = {}\n".format(interface_name)
            e += "lxc.network.flags = up\n"
            e += "lxc.network.link = {}\n".format(interface_data["lxr-link"])
            e += "lxc.network.hwaddr = {}\n\n".format(interface_data["lxr-hw-addr"])
        d["conf-lxc"] = e
        return d

    def host_handle(self, name):
        d = dict()
        for i in ("terminals", "router", "ue"):
            if name in self.db["devices"][i]:
                terminal = self.db["devices"][i][name]
                d['terminal-data'] = terminal
                d['config'] = self.terminal_gen_config(terminal)
                return d
        raise ConfigurationException("entity (router, terminal, ...) not found: {}".format(name))

    def link_class_by_name(self, name):
        if "link-classes" not in self.db:
            return None
        if name not in self.db["link-classes"]:
            self.p.msg("link-class not available: {}\n".format(self.db["link-classes"]))
            sys.exit(1)
        return self.db["link-classes"][name]

    def bridge_handle(self, bridge_name):
        topo_db = self.db["topologies"][self.topology_name]
        if "netem" not in topo_db:
            # nothing to do
            return
        netem = self.db["topologies"][self.topology_name]["netem"]
        for netem_entry in netem:
            bridge, netem_conf = netem_entry
            entry_bridge_name = bridge.split('(')[1].split(')')[0]
            if entry_bridge_name != bridge_name:
                continue
            return self.link_class_by_name(netem_conf)
        return None

    def create_entity_object(self, entry_type, entry_name, p, u, c):
        if entry_type == "Router":
            h = self.host_handle(entry_name)
            return Router(entry_name, p, u, c, h)
        if entry_type == "Terminal":
            h = self.host_handle(entry_name)
            return Terminal(entry_name, p, u, c, h)
        if entry_type == "UE":
            h = self.host_handle(entry_name)
            return UE(entry_name, p, u, c, h)
        if entry_type == "Bridge":
            h = self.bridge_handle(entry_name)
            return Bridge(entry_name, p, u, c, h)
        assert False
        

    def create_topology_db(self, topology_name, p, u, c):
        if not self.topology_name in self.db["topologies"]:
            raise ArgumentException("Topology {} not available".format(self.topology_name))
        topo = self.db["topologies"][self.topology_name]
        g = TopologyDb(None, directed=True)
        for item in topo["map"]:
            entries = item.split()
            assert len(entries) == 3
            assert entries[1] == "<->"
            # src
            entity_pair = entries[0].split('(')
            entity_type = entity_pair[0]
            entity_name = entity_pair[1].split(')')[0]
            o1 = self.create_entity_object(entity_type, entity_name, p, u, c)

            # dst
            entity_pair = entries[2].split('(')
            entity_type = entity_pair[0]
            entity_name = entity_pair[1].split(')')[0]
            o2 = self.create_entity_object(entity_type, entity_name, p, u, c)
            g.add(o1, o2)
        return g



class BridgeCreator():

    def __init__(self, utils, printer, name):
        self.u = utils
        self.p = printer
        self.bridge_name = name

    def create(self):
        brige_path = os.path.join("/sys/class/net", self.bridge_name)
        if os.path.isdir(brige_path):
            self.p.msg("bridge {} already created\n".format(self.bridge_name))
            return
        self.u.exec("brctl addbr {}".format(self.bridge_name))
        self.u.exec("brctl setfd {} 0".format(self.bridge_name))
        self.u.exec("brctl sethello {} 5".format(self.bridge_name))
        self.u.exec("ip link set dev {} up".format(self.bridge_name))



class TopologyCreate():

    def __init__(self):
        uid0_required()
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

    def start_container(self, host):
        c = lxc.Container(host.name)
        if c.defined:
            c.start()

    def tmp_dig_fd_new(self, string):
        name = os.path.join(TMPDIR, string)
        fd = open(name,"w")
        return fd, name

    def run(self):
        try:
            self.c = Configuration(topology=self.args.topology)
        except ArgumentException as e:
            print("not a valid topology: {}".format(e))
            sys.exit(1)

        self.p.msg("Create topology {}\n".format(self.args.topology), stoptime=1.0)

        topology_db = self.c.create_topology_db(self.args.topology, self.p, self.u, self.c)
        topology_db.destroy_bridges()
        topology_db.destroy_hosts()

        # create bridges first, if not already created
        Bridge.destroy_debug_bridge()
        Bridge.create_debug_bridge()
        for bridge in topology_db.get_bridges():
            bridge.create()

        for host in topology_db.get_hosts():
            host.create()

        self.p.msg("Start container:\n")
        for host in topology_db.get_hosts():
            self.p.msg("  {}\n".format(host.name))
            self.start_container(host)

        cnt_size_byte = Utils.get_tree_size("/var/lib/lxc/")
        cnt_size_human = Utils.human_byte_size(cnt_size_byte)
        self.p.msg("Created container size {}\n".format(cnt_size_human))



class TopologyGraph():

    def __init__(self):
        self.u = Utils()
        self.p = Printer()
        self.parse_local_options()
        self.file_out_name = "topology-graph.png"

    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("topology", help="name of the topology", type=str)
        self.args = parser.parse_args(sys.argv[2:])

    def tmp_dig_fd_new(self, string):
        name = os.path.join(TMPDIR, string)
        fd = open(name, "w")
        return fd, name

    def gen_digraph_image(self, topology_db):
        d = topology_db.gen_digraph()
        fd, name = self.tmp_dig_fd_new("digraph.data")
        fd.write(d)
        os.fsync(fd); fd.close()
        self.p.msg("Generate topology file: {}\n".format(self.file_out_name), color=None)
        os.system("cat {} | dot -Tpng -Gsize=20,80\! -Gdpi=200 > {}".format(name, self.file_out_name))

    def run(self):
        try:
            self.c = Configuration(topology=self.args.topology)
        except ArgumentException as e:
            self.p.msg("Not a valid topology: {}".format(e))
            sys.exit(1)

        topology_db = self.c.create_topology_db(self.args.topology, self.p, self.u, self.c)
        self.p.msg("Generate graph of topopolgy\n")
        self.gen_digraph_image(topology_db)


class TopologyConnect():

    def __init__(self):
        uid0_required()
        self.u = Utils()
        self.p = Printer()
        self.parse_local_options()

    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("topology", help="name of the topology", type=str)
        self.args = parser.parse_args(sys.argv[2:])

    def prepare_tmux(self):
        os.system("tmux -f \"assets/tmux.conf\"  new-session -s lxc -n \"control\"  -d")
    
    def finish_tmux(self):
        self.p.msg("ok, will now connect to tmux session, bye\n", color="magenta", stoptime=2.0)
        os.system("tmux select-window -t lxc:2")
        os.execv("/usr/bin/tmux", [ "-2", "attach-session", "-t", "lxc" ])

    def run(self):
        try:
            self.c = Configuration(topology=self.args.topology)
        except ArgumentException as e:
            self.p.msg("Not a valid topology: {}".format(e))
            sys.exit(1)

        topology_db = self.c.create_topology_db(self.args.topology, self.p, self.u, self.c)
        self.prepare_tmux()

        # should be replaced by ssh command:
        # sudo ssh -oStrictHostKeyChecking=no -i tmp/ssh-id-rsa superuser@1.1.1.1
        # this will also allow later automatic processes on the guests
        i = 2
        for host in sorted(topology_db.get_hosts(), key=lambda entry: entry.name):
            self.p.msg("  {}\n".format(host.name))
            os.system("tmux new-window -t lxc:{} -n {} 'sudo lxc-console -n {}'".format(i, host.name, host.name))
            i += 1
        self.finish_tmux()


class TopologyList():

    def __init__(self):
        self.p = Printer()
        self.parse_local_options()


    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument( "-v", "--verbose", dest="verbose", default=False,
                          action="store_true", help="show verbose")
        self.args = parser.parse_args(sys.argv[2:])
        if self.args.verbose: self.p.set_verbose()

    def run(self):
        c = Configuration()
        self.p.msg("Available topologies:\n")
        for t in c.topologies():
            self.p.msg("  {}  -  {}\n".format(t[0], t[1]), color=None)


class TopologyDestroy():

    def __init__(self):
        uid0_required()
        self.u = Utils()
        self.p = Printer()
        self.parse_local_options()

    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("topology", help="name of the topology", type=str)
        self.args = parser.parse_args(sys.argv[2:])

    def run(self):
        try:
            self.c = Configuration(topology=self.args.topology)
        except ArgumentException as e:
            self.p.msg("Not a valid topology: {}".format(e))
            sys.exit(1)

        self.p.msg("Delete container and bridges\n")
        topology_db = self.c.create_topology_db(self.args.topology, self.p, self.u, self.c)
        Bridge.destroy_debug_bridge()
        topology_db.destroy_bridges()
        topology_db.destroy_hosts()


class TopologyStart():

    def __init__(self):
        uid0_required()
        self.u = Utils()
        self.p = Printer()
        self.parse_local_options()

    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("topology", help="name of the topology", type=str)
        self.args = parser.parse_args(sys.argv[2:])

    def run(self):
        try:
            self.c = Configuration(topology=self.args.topology)
        except ArgumentException as e:
            self.p.msg("Not a valid topology: {}".format(e))
            sys.exit(1)

        self.p.msg("Start bridges and container\n")
        topology_db = self.c.create_topology_db(self.args.topology, self.p, self.u, self.c)

        self.p.msg("Create topology bridges\n")
        Bridge.destroy_debug_bridge()
        Bridge.create_debug_bridge()
        for bridge in topology_db.get_bridges():
            bridge.create()

        self.p.msg("Start container\n")
        for host in topology_db.get_hosts():
            self.p.msg("  {}\n".format(host.name), color=None)
            host.start()


class TopologyStop():

    def __init__(self):
        uid0_required()
        self.u = Utils()
        self.p = Printer()
        self.parse_local_options()

    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("topology", help="name of the topology", type=str)
        self.args = parser.parse_args(sys.argv[2:])

    def run(self):
        try:
            self.c = Configuration(topology=self.args.topology)
        except ArgumentException as e:
            self.p.msg("Not a valid topology: {}".format(e))
            sys.exit(1)

        self.p.msg("Stop container and delete bridges\n")
        topology_db = self.c.create_topology_db(self.args.topology, self.p, self.u, self.c)
        topology_db.destroy_bridges()

        self.p.msg("Destroy bridges\n")
        for bridge in topology_db.get_bridges():
            self.p.msg("  {}\n".format(bridge.name), color=None)
            bridge.destroy()

        self.p.msg("Stop container\n")
        for host in topology_db.get_hosts():
            self.p.msg("  {}\n".format(host.name), color=None)
            host.stop()



class TopologyNetemStart():


    def __init__(self):
        uid0_required()
        self.u = Utils()
        self.p = Printer()
        self.player_resolution = 1
        self.parse_local_options()


    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("topology", help="name of the topology", type=str)
        parser.add_argument( "-g", "--generate-graph", dest="graph", default=False,
                          action="store_true", help="generate a PDF of the topology")
        parser.add_argument( "-l", "--loop", dest="loop", default=False,
                          action="store_true", help="re-loop after last netem command was execed")
        self.args = parser.parse_args(sys.argv[2:])
        if self.args.graph:
            self.__check_mathplot_mod()
            self._graph_x_axis_data = ('loss', 'delay', 'rate')


    def __check_mathplot_mod(self):
        try:
            import matplotlib
        except Exeption as e:
            self.p.msg("You specified \"--generate-graph\" but no matplotlib is installed!\n", color="red")
            self.p.msg("{}\n".format(e.str()), color="red")
            self.p.msg("Exiting now, bye bye ...\n", color="red")
            sys.exit(1)


    def __graph_account(self, plot_db, time, interface, atoms):
        if time not in plot_db:
            plot_db[time] = dict()
        plot_db[time][interface] = atoms


    def __graph_interfaces(self, plot_db):
        interfaces = []
        for k, v in plot_db.items():
            for entry in list(v.keys()):
                interfaces.append(entry)
        # return and filter duplicates first
        return list(set(interfaces))


    def __graph_convert(self, d, time, interface, data):
        for i in self._graph_x_axis_data:
            d[interface][i].append(data[i])


    def __graph_plot_data_init(self, interfaces):
        d = dict()
        for interface in interfaces:
            d[interface] = {}
            for what in self._graph_x_axis_data:
                d[interface][what] = list()
        return d

    def _graph_rm_unit(self, value):
        if value.endswith('%'):
            return value[0:len(value) - 1]
        if value.endswith('ms'):
            return value[0:len(value) - 2]
        if value.endswith('kbit'):
            return value[0:len(value) - 4]

    def _graph_rm_units(self, values):
        r = []
        for value in values:
            r.append(self._graph_rm_unit(value))
        return r

    def _graph_rm_var(self, values):
        r = []
        for value in values:
            r.append(self._graph_rm_unit(value[0]))
        return r


    def __graph_data(self, ctrl, plot_db):
        from matplotlib import pyplot as plt
        atoms_last = {}; plot_data = {}
        interfaces = self.__graph_interfaces(plot_db)
        plot_data = self.__graph_plot_data_init(interfaces)
        time_max = ctrl['time']
        if time_max == 0: return
        plot_data['time'] = list(range(time_max + 1))
        for i in range(time_max + 1):
            for interface in interfaces:
                if not i in plot_db:
                    # not accounted seconds
                    self.__graph_convert(plot_data, i, interface, atoms_last[interface])
                else:
                    if interface in plot_db[i]:
                        self.__graph_convert(plot_data, i, interface, plot_db[i][interface])
                        atoms_last[interface] = plot_db[i][interface]
                    else:
                        self.__graph_convert(plot_data, i, interface, atoms_last[interface])
        columns = len(self._graph_x_axis_data)
        rows = len(interfaces)
        entry = 1
        pprint.pprint(plot_data)
        fig = plt.figure()
        for interface in interfaces:
            for what in self._graph_x_axis_data:
                axis = fig.add_subplot(rows, columns, entry)
                if what in ("rate", "loss"):
                    axis.plot(plot_data['time'], self._graph_rm_units(plot_data[interface][what]))
                elif what == "delay":
                    axis.plot(plot_data['time'], self._graph_rm_var(plot_data[interface][what]))
                entry += 1
        plt.show()

    def _loop_re_spawn_data(self, data_arr, time_delta):
        for data in data_arr:
            data[0] += time_delta

    def __play(self, data_arr, ctrl, max_exec_time, plot_db):
        while True:
            self.p.msg("\rEmulation time: {}s".format(ctrl['time']), color="magenta")
            for data in data_arr:
                if data[0] == ctrl['time']:
                    cmd = data[1]
                    interface_name = data[2]
                    atoms = data[3]
                    print("")
                    Bridge.netem_exec(interface_name, cmd)
                    if self.args.graph:
                        self.__graph_account(plot_db, ctrl['time'], data[2], data[3])
            if self.args.loop and ctrl['time'] != 0 and ctrl['time'] % max_exec_time == 0:
                self._loop_re_spawn_data(data_arr, max_exec_time)
            ctrl['time'] += self.player_resolution
            time.sleep(self.player_resolution)


    def __execute_inits(self, inits, plot_db):
        self.p.msg("Initial setup of Netem Rules:\n")
        for i in inits:
            Bridge.netem_exec(i[1], i[0])
            if self.args.graph:
                self.__graph_account(plot_db, 0, i[1], i[2])


    def run(self):
        max_exec_time = -1
        try:
            self.c = Configuration(topology=self.args.topology)
        except ArgumentException as e:
            self.p.msg("Not a valid topology: {}".format(e))
            sys.exit(1)

        topology_db = self.c.create_topology_db(self.args.topology, self.p, self.u, self.c)
        self.p.msg("Network Emulation Starting Sequence\n")
        if self.args.graph:
            msg = "Generate a PDF of the bridge characteristics\n"
        else:
            msg = "Generate NO PDF of the bridge characteristics (--generate-graph)\n"
        self.p.msg(msg, color=None)
        bridges = sorted(topology_db.get_bridges(), key=lambda k: k.name)
        cmds_init = []; cmds_run = []
        for bridge in bridges:
            enabled = "none" if bridge.netem is None else "enabled "
            desc    = "" if bridge.netem is None else "\"" + bridge.netem["description"] + "\""
            self.p.msg("  {}: {} {}\n".format(bridge.name, enabled, desc), color=None)
            if not bridge.netem:
                continue
            # remember init data ...
            cmds_init.append([bridge.netem["cmd-start"], bridge.name, bridge.netem["atoms"]])
            # .. and dynamic ones too
            if bridge.netem["class"] == "dynamic":
                for i in bridge.netem["cmd-runs"]:
                    max_exec_time = max(max_exec_time, i['time'])
                    cmds_run.append([i["time"], i["cmd"], bridge.name, i["atoms"]])

        plot_db = dict(); ctrl = {}; ctrl['time'] = 0
        self.__execute_inits(cmds_init, plot_db)
        try:
            self.__play(cmds_run, ctrl, max_exec_time, plot_db)
        except KeyboardInterrupt:
            if self.args.graph:
                self.__graph_data(ctrl, plot_db)




class ContainerLister():

    def __init__(self):
        uid0_required()
        self.p = Printer()
        self.parse_local_options()

    def parse_local_options(self):
        parser = argparse.ArgumentParser()
        parser.add_argument( "-v", "--verbose", dest="verbose", default=False,
                          action="store_true", help="show verbose")
        self.args = parser.parse_args(sys.argv[2:])
        if self.args.verbose: self.p.set_verbose()

    def run(self):
        for container in lxc.list_containers(as_object=True):
            self.p.msg("{} ".format(container.name))
            if not container.running:
                self.p.msg("  not running ", color="red")
            else:
                self.p.msg("      running ", color="green")
            self.p.msg("\n")




class VHostManager:

    modes = {
       "topology-create":      [ "TopologyCreate", "create given topolology, including bridge and container" ],
       "topology-start":       [ "TopologyStart", "start involved container and create bridges" ],
       "topology-stop":        [ "TopologyStop", "stop involved container and destroy bridges" ],
       "topology-graph":       [ "TopologyGraph", "create image of a given toplogy" ],
       "topology-list":        [ "TopologyList",  "list available topologies" ],
       "topology-connect":     [ "TopologyConnect",  "start and tmux connect to topology" ],
       "topology-destroy":     [ "TopologyDestroy",  "Purge container and all bridges" ],
       "topology-netem-start": [ "TopologyNetemStart",  "Start network emulation for topology" ],
       "container-list":       [ "ContainerLister",  "list available container" ],
       "container-stop":       [ "ContainerStop",  "start particular container" ],
       "container-start":      [ "ContainerStart",  "start particular container" ],
       "container-exec":       [ "ContainerExec",  "execute command on (all) container" ],
            }

    def __init__(self):
        self.p = Printer()
        self.check_env()

    def install_packages_ubuntu(self):
        os.system("apt-get --yes --force-yes update")
        os.system("apt-get --yes --force-yes install lxc tmux ssh graphviz")
        return True

    def install_packages_debian(self):
        self.install_packages_ubuntu()

    def install_packages_arch(self):
        os.system("pacman -Syu --noconfirm")
        os.system("pacman -Sy --noconfirm ebtables community/lxc community/debootstrap community/tmux")
        return True

    def check_installed_packages(self):
        self.p.msg("I will make sure every required package is installed ...\n",
                   stoptime=2.0)
        distribution = platform.linux_distribution()
        if distribution[0] == "Ubuntu":
            self.p.msg("seems you are using Ubuntu, great ...\n")
            self.install_packages_ubuntu()
        elif distribution[0] == "arch":
            self.p.msg("seems you are using Arch, great ...\n")
            self.install_packages_arch()
        elif distribution[0] == "debian":
            self.p.msg("seems you are using Debian, great ...\n")
            self.install_packages_debian()
        else:
            raise EnvironmentException("Distribution not detected")

    def determine_proxy(self):
        apt_conf_path = "/etc/apt/apt.conf"
        p = re.compile('.*Acquire::http::Proxy.*\"(.*)\"', re.IGNORECASE)
        if not os.path.isfile(apt_conf_path):
            return None
        if not os.access(apt_conf_path, os.R_OK):
            return None
        with open(apt_conf_path) as fd:
            for line in fd:
                 m = p.match(line)
                 if m and m.group(1):
                     return m.group(1)
        return None



    def ask_proxy(self):
        u = Utils()
        self.p.msg("Configuration of system proxy settings\n")
        proxy = self.determine_proxy()
        if proxy:
            answer = u.query_yes_no("Is proxy \"{}\" correct?\n".format(proxy))
            if answer == True: return proxy
        self.p.msg("If your are behing a proxy, enter the proxy url now or leave blank for none\n", color=None)
        res = False
        while True:
            self.p.msg("URL must be in the form http://USER:PASS@url[:port]/\n", color=None)
            line = input("")
            if line == "":
                answer = u.query_yes_no("No proxied environment, correct?")
            else:
                if not u.valid_url(line):
                    self.p.msg("url not valid: {}\n".format(line), color=None)
                    continue
                answer = u.query_yes_no("Is \"{}\" correct?".format(line), default="no")
            if answer == True:
                break
        if line == "":
            return None
        else:
            return line

    def manage_proxy(self, tmp_dir):
        proxy_url = self.ask_proxy()
        if not proxy_url:
            return
        # apt specific proxy settings
        config =  "Acquire::http::Proxy \"{}\";\n".format(proxy_url)
        config += "Acquire::https::Proxy \"{}\";\n".format(proxy_url)
        apt_conf_file = os.path.join(tmp_dir, "apt.conf")
        with open(apt_conf_file, "w") as f:
            f.write("{}".format(config))
        # shell specific proxy settings
        config =  'export http_proxy=\"{}\"\n'.format(proxy_url)
        config += 'export https_proxy=\"{}\"\n'.format(proxy_url)
        apt_conf_file = os.path.join(tmp_dir, "shell-proxy.sh")
        with open(apt_conf_file, "w") as f:
            f.write("{}".format(config))
        # wget ...
        config =  "http_proxy = {}\n".format(proxy_url)
        config += "https_proxy = {}\n".format(proxy_url)
        apt_conf_file = os.path.join(tmp_dir, "wgetrc")
        with open(apt_conf_file, "w") as f:
            f.write("{}".format(config))

    def prepare_bashrc(self, tmp_dir):
        root_dir = os.path.dirname(os.path.realpath(__file__))
        proxy_sh_path = os.path.join(tmp_dir, "shell-proxy.sh")
        src_bashrc_path = os.path.join(root_dir, "assets", "bashrc")
        dst_bashrc_path = os.path.join(tmp_dir, "bashrc")
        # copy vanilla bashrc
        shutil.copyfile(src_bashrc_path, dst_bashrc_path)

        if not os.path.isfile(proxy_sh_path):
            return
        with open(proxy_sh_path) as f:
            content = f.read()
        with open(dst_bashrc_path, "a") as f:
            f.write("\n# proxy settings\n\n{}\n".format(content))
        Utils.sexec("sync")

    def first_startup(self, tmp_dir):
        touch_file = os.path.join(tmp_dir, "already-started")
        if not os.path.isfile(touch_file):
            self.p.clear()
            self.p.msg("Seems you are new - great!\n", stoptime=1.0)
            self.check_installed_packages()
            self.manage_proxy(tmp_dir)
            self.prepare_bashrc(tmp_dir)
            self.check_ssh_keys(tmp_dir)
            with open(touch_file, "w") as f:
                f.write("{}".format(time.time()))

    def check_ssh_keys(self, tmp_dir):
        ssh_file = os.path.join(tmp_dir, "ssh-id-rsa")
        if not os.path.isfile(ssh_file):
            self.p.msg("No SSH key found! I will generate a new one ...\n", stoptime=2.0)
            os.system("ssh-keygen -f tmp/ssh-id-rsa -N ''")

    def check_env(self):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        tmp_dir    = os.path.join(script_dir, "tmp")
        os.makedirs(tmp_dir, exist_ok=True)

        self.first_startup(tmp_dir)

    def print_version(self):
        sys.stdout.write("%s\n" % (__version__))

    def print_usage(self):
        sys.stderr.write("Usage: vhost-manager [-h | --help]" +
                         " [--version]" +
                         " <submodule> [<submodule-options>]\n")

    def print_modules(self):
        for i in sorted(VHostManager.modes.items(), key=lambda x: x[0]):
            sys.stderr.write("   %-25s - %s\n" % (i[0], i[1][1]))

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

def uid0_required():
    euid = os.geteuid()
    if euid != 0:
        sys.stderr.write("Need to be root\n")
        sys.stderr.write("➡ sudo {}\n".format(" ".join(sys.argv)))
        exit(1)


if __name__ == "__main__":
    try:
        if not DEBUG:
            atexit.register(remove_tmp_dir)
        vhm = VHostManager()
        sys.exit(vhm.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
