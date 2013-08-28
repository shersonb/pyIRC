#!/usr/bin/python

from threading import Thread, Lock
import re
import time
import sys
import string
import socket
import os
import platform
import traceback
import Queue
import ssl
import urllib2


class LogRotate(Thread):
    def __init__(self, logger):
        self.logger = logger
        Thread.__init__(self)
        self.daemon = True
        self.start()

    def run(self):
        Y, M, D, h, m, s, w, d, dst = time.localtime()
        nextrotate = int(time.mktime((Y, M, D+1, 0, 0, 0, 0, 0, -1)))
        #print time.time()-nextrotate
        #print time.localtime(), time.localtime(nextrotate)
        while True:
            while nextrotate > time.time():  # May need to do this in a loop in case the following time.sleep command wakes up a second too early.
                time.sleep(max(0.1, min((nextrotate-time.time(), 3600))))
            with self.logger.rotatelock:
                if all([not log or log.closed for log in self.logger.consolelogs.values()+self.logger.channellogs.values()]):
                    ### If there are no logs to rotate, we are going to terminate this thread. Logger will spawn another LogRotate thread when needed.
                    self.logger.logrotate = None
                    break
            now = time.localtime()
            timestamp = reduce(lambda x, y: x+":"+y, [str(t)
                                                      .rjust(2, "0") for t in now[0:6]])
            for IRC in self.logger.labels.keys():
                if IRC.connected:
                    with IRC.lock:
                        try:
                            self.logger.rotateConsoleLog(IRC)
                        except:
                            with IRC.loglock:
                                exc, excmsg, tb = sys.exc_info()
                                print >>IRC.log, "%(timestamp)s !!! [LogRotate] Exception in module %(module)s" % vars()
                                for tbline in traceback.format_exc().split("\n"):
                                    print >>IRC.log, "%(timestamp)s !!! [LogRotate] %(tbline)s" % vars()
                                IRC.log.flush()
                        if IRC.identity:
                            for channel in IRC.identity.channels:
                                try:
                                    self.logger.rotateChannelLog(channel)
                                except:
                                    with IRC.loglock:
                                        exc, excmsg, tb = sys.exc_info()
                                        print >>IRC.log, "%(timestamp)s !!! [LogRotate] Exception in module %(module)s" % vars()
                                        for tbline in traceback.format_exc().split("\n"):
                                            print >>IRC.log, "%(timestamp)s !!! [LogRotate] %(tbline)s" % vars()
                                        IRC.log.flush()
            nextrotate += 3600*24


class Logger(object):
    def __init__(self, logroot):
        self.logroot = logroot
        path = [logroot]
        #print path
        while not os.path.isdir(path[0]):
            split = os.path.split(path[0])
            path.insert(1, split[1])
            path[0] = split[0]
            #print path
        while len(path) > 1:
            path[0] = os.path.join(*path[:2])
            del path[1]
            #print path
            os.mkdir(path[0])
        #return
        self.consolelogs = {}
        self.channellogs = {}
        self.labels = {}
        self.rotatelock = Lock()
        self.logrotate = None

    def onModuleAdd(self, IRC, label):
        if label in self.labels.values():
            raise BaseException("Label already exists")
        if IRC in self.labels.keys():
            raise BaseException("Network already exists")
        if not os.path.isdir(os.path.join(self.logroot, label)):
            os.mkdir(os.path.join(self.logroot, label))
        self.labels[IRC] = label
        if IRC.connected:
            self.openConsoleLog(IRC)
            if IRC.identity:
                for channel in IRC.identity.channels:
                    self.openChannelLog(channel)

    def onModuleRem(self, IRC):
        if IRC.connected:
            for channel in self.channellogs.keys():
                if channel in IRC.channels:
                    if not self.channellogs[channel].closed:
                        self.closeChannelLog(channel)
                    del self.channellogs[channel]
            if not self.consolelogs[IRC].closed:
                self.closeConsoleLog(IRC)
        del self.labels[IRC]
        del self.consolelogs[IRC]

    def openConsoleLog(self, IRC):
        with self.rotatelock:
            if not self.logrotate or not self.logrotate.isAlive():
                self.logrotate = LogRotate(self)
        now = time.localtime()
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in now[0:6]])
        self.consolelogs[IRC] = open(os.path.join(self.logroot, self.labels[
            IRC], "console-%04d.%02d.%02d.log"%now[:3]), "a")
        print >>self.consolelogs[IRC], "%s %s ### Log session started" % (
            timestamp, time.tzname[now[-1]])
        self.consolelogs[IRC].flush()

    def closeConsoleLog(self, IRC):
        if IRC in self.consolelogs.keys() and type(self.consolelogs[IRC]) == file and not self.consolelogs[IRC].closed:
            now = time.localtime()
            timestamp = reduce(lambda x, y: x+":"+y, [str(t)
                                                      .rjust(2, "0") for t in now[0:6]])
            print >>self.consolelogs[IRC], "%s %s ### Log session ended" % (
                timestamp, time.tzname[now[-1]])
            self.consolelogs[IRC].close()

    def rotateConsoleLog(self, IRC):
        self.closeConsoleLog(IRC)
        self.openConsoleLog(IRC)

    def openChannelLog(self, channel):
        with self.rotatelock:
            if not self.logrotate or not self.logrotate.isAlive():
                self.logrotate = LogRotate(self)
                self.logrotate.daemon = True
                self.logrotate.start()
        now = time.localtime()
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in now[0:6]])
        label = self.labels[channel.context]
        self.channellogs[channel] = open(os.path.join(self.logroot, label, "channel-%s-%04d.%02d.%02d.log"%((urllib2.quote(channel.name.lower()).replace("/", "%2f"),)+now[:3])), "a")
        print >>self.channellogs[channel], "%s %s ### Log session started" % (
            timestamp, time.tzname[now[-1]])
        self.channellogs[channel].flush()
        if channel.context.identity in channel.users:
            if channel.topic:
                print >>self.channellogs[channel], "%s %s <<< :%s 332 %s %s :%s" % (timestamp, time.tzname[now[-1]], channel.context.serv, channel.context.identity.nick, channel.name, channel.topic)
            if channel.topicsetby and channel.topictime:
                print >>self.channellogs[channel], "%s %s <<< :%s 333 %s %s %s %s" % (timestamp, time.tzname[now[-1]], channel.context.serv, channel.context.identity.nick, channel.name, channel.topicsetby, channel.topictime)
            if channel.users:
                secret = "s" in channel.modes.keys() and channel.modes["s"]
                private = "p" in channel.modes.keys() and channel.modes["p"]
                namesusers = []
                modes, symbols = channel.context.supports["PREFIX"]
                print >>self.channellogs[channel], "%s %s <<< :%s 353 %s %s %s :%s" % (timestamp, time.tzname[now[-1]],
                                                                                       channel.context.serv,
                                                                                       channel.context.identity.nick,
                                                                                       "@" if secret else ("*" if private else "="),
                                                                                       channel.name,
                                                                                       " ".join(["".join([symbols[k] if modes[k] in channel.modes.keys() and user in channel.modes[modes[k]] else "" for k in xrange(len(modes))])+user.nick for user in channel.users]))
            if channel.modes:
                modes = channel.modes.keys()
                modestr = "".join([mode for mode in modes if mode not in channel.context.supports["CHANMODES"][0]+channel.context.supports["PREFIX"][0] and channel.modes[mode]])
                params = " ".join([channel.modes[mode] for mode in modes if mode in channel.context.supports["CHANMODES"][1]+channel.context.supports["CHANMODES"][2] and channel.modes[mode]])
                print >>self.channellogs[channel], "%s %s <<< :%s 324 %s %s +%s %s" % (timestamp, time.tzname[now[-1]], channel.context.server, channel.context.identity.nick, channel.name, modestr, params)
            if channel.created:
                print >>self.channellogs[channel], "%s %s <<< :%s 329 %s %s %s" % (timestamp, time.tzname[now[-1]], channel.context.serv, channel.context.identity.nick, channel.name, channel.created)
        self.channellogs[channel].flush()

    def closeChannelLog(self, channel):
        if channel in self.channellogs.keys() and type(self.channellogs[channel]) == file and not self.channellogs[channel].closed:
            now = time.localtime()
            timestamp = reduce(lambda x, y: x+":"+y, [str(t)
                                                      .rjust(2, "0") for t in now[0:6]])
            print >>self.channellogs[channel], "%s %s ### Log session ended" % (timestamp, time.tzname[now[-1]])
            self.channellogs[channel].close()

    def rotateChannelLog(self, channel):
        self.closeChannelLog(channel)
        self.openChannelLog(channel)

    def onRecv(self, IRC, line, data):
        modemapping = dict(Y="ircop", q="owner", a="admin", o="op",
                           h="halfop", v="voice")
        now = time.localtime()
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in now[0:6]])
        if data is None:
            print >>self.consolelogs[IRC], "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            self.consolelogs[IRC].flush()
            return
        (origin, ident, host, cmd, target, params, extinfo) = data
        if re.match("^\\d+$", cmd):
            cmd = int(cmd)
        if cmd in (324, 329):
            modeparams = params.split()
            channame = modeparams[0]
            channel = IRC.channel(channame)
            if channel in self.channellogs.keys() and not self.channellogs[channel].closed:
                log = self.channellogs[channel]
            else:
                log = self.consolelogs[IRC]
            print >>log, "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            log.flush()
        elif cmd == 332:
            channel = IRC.channel(params)
            if channel in self.channellogs.keys() and not self.channellogs[channel].closed:
                log = self.channellogs[channel]
            else:
                log = self.consolelogs[IRC]
            print >>log, "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            log.flush()
        elif cmd == 333:
            (channame, nick, dt) = params.split()
            channel = IRC.channel(channame)
            if not self.channellogs[channel].closed:
                print >>self.channellogs[channel], "%s %s <<< %s" % (
                    timestamp, time.tzname[now[-1]], line)
                self.channellogs[channel].flush()
        elif cmd == 353:
            (flag, channame) = params.split()
            channel = IRC.channel(channame)
            if not self.channellogs[channel].closed:
                print >>self.channellogs[channel], "%s %s <<< %s" % (
                    timestamp, time.tzname[now[-1]], line)
                self.channellogs[channel].flush()
        elif cmd == "JOIN":
            user = IRC.user(origin)
            channel = IRC.channel(target if len(target) else extinfo)
            if user == IRC.identity:
                self.openChannelLog(channel)
            print >>self.channellogs[channel], "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            self.channellogs[channel].flush()
        elif cmd == "PRIVMSG":
            if target and target[0] in IRC.supports["CHANTYPES"]:
                channel = IRC.channel(target)
                if ident and host:
                    user = IRC.user(origin)
                    classes = " ".join([modemapping[mode] for mode in IRC.supports["PREFIX"][0] if mode in channel.modes.keys() and user in channel.modes[mode]])
                else:
                    classes = "server"
                if classes:
                    print >>self.channellogs[channel], "%s %s %s <<< %s" % (timestamp, time.tzname[now[-1]], classes, line)
                else:
                    print >>self.channellogs[channel], "%s %s <<< %s" % (timestamp, time.tzname[now[-1]], line)
                self.channellogs[channel].flush()
        elif cmd == "NOTICE":
            if target and (target[0] in IRC.supports["CHANTYPES"] or (len(target) > 1 and target[0] in IRC.supports["PREFIX"][1] and target[1] in IRC.supports["CHANTYPES"])):
                if target[0] in IRC.supports["PREFIX"][1]:
                    channel = IRC.channel(target[1:])
                else:
                    channel = IRC.channel(target)
                if ident and host:
                    user = IRC.user(origin)
                    classes = " ".join([modemapping[mode] for mode in IRC.supports["PREFIX"][0] if mode in channel.modes.keys() and user in channel.modes[mode]])
                else:
                    classes = "server"
                if classes:
                    print >>self.channellogs[channel], "%s %s %s <<< %s" % (timestamp, time.tzname[now[-1]], classes, line)
                else:
                    print >>self.channellogs[channel], "%s %s <<< %s" % (timestamp, time.tzname[now[-1]], line)
                self.channellogs[channel].flush()
            elif target.lower() == IRC.identity.nick.lower() and not ident and not host:
                print >>self.consolelogs[IRC], "%s %s <<< %s" % (
                    timestamp, time.tzname[now[-1]], line)
                self.consolelogs[IRC].flush()
        elif cmd == "TOPIC":
            channel = IRC.channel(target)
            print >>self.channellogs[channel], "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            self.channellogs[channel].flush()
        elif cmd == "PART":
            user = IRC.user(origin)
            channel = IRC.channel(target)
            print >>self.channellogs[channel], "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            self.channellogs[channel].flush()
            if user == IRC.identity:
                self.closeChannelLog(channel)
        elif cmd == "KICK":
            kicked = IRC.user(params)
            channel = IRC.channel(target)
            print >>self.channellogs[channel], "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            self.channellogs[channel].flush()
            if kicked == IRC.identity:
                self.closeChannelLog(channel)
        elif cmd == "MODE":
            if target and target[0] in IRC.supports["CHANTYPES"]:
                channel = IRC.channel(target)
                print >>self.channellogs[channel], "%s %s <<< %s" % (
                    timestamp, time.tzname[now[-1]], line)
                self.channellogs[channel].flush()
            else:
                print >>self.consolelogs[IRC], "%s %s <<< %s" % (
                    timestamp, time.tzname[now[-1]], line)
                self.consolelogs[IRC].flush()
        elif cmd in ("NICK", "QUIT"):
            user = IRC.user(origin)
            for channel in user.channels:
                print >>self.channellogs[channel], "%s %s <<< %s" % (
                    timestamp, time.tzname[now[-1]], line)
                self.channellogs[channel].flush()
        else:
            print >>self.consolelogs[IRC], "%s %s <<< %s" % (
                timestamp, time.tzname[now[-1]], line)
            self.consolelogs[IRC].flush()

    def onConnectAttempt(self, IRC):
        if IRC not in self.consolelogs.keys() or (not self.consolelogs[IRC]) or self.consolelogs[IRC].closed:
            self.openConsoleLog(IRC)
        now = time.localtime()
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in now[0:6]])
        print >>self.consolelogs[IRC], "%s %s *** Attempting connection to %s:%s." % (timestamp, time.tzname[now[-1]], IRC.server, IRC.port)

    def onConnect(self, IRC):
        if IRC not in self.consolelogs.keys() or (not self.consolelogs[IRC]) or self.consolelogs[IRC].closed:
            self.openConsoleLog(IRC)
        #self.openConsoleLog(IRC)
        now = time.localtime()
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in now[0:6]])
        print >>self.consolelogs[IRC], "%s %s *** Connection to %s:%s established." % (timestamp, time.tzname[now[-1]], IRC.server, IRC.port)

    def onDisconnect(self, IRC):
        now = time.localtime()
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in now[0:6]])
        for channel in IRC.identity.channels:
            print >>self.channellogs[channel], "%s %s *** Connection to %s:%s terminated." % (timestamp, time.tzname[now[-1]], IRC.server, IRC.port)
            self.channellogs[channel].flush()
            self.closeChannelLog(channel)
        print >>self.consolelogs[IRC], "%s %s *** Connection %s:%s terminated." % (timestamp, time.tzname[now[-1]], IRC.server, IRC.port)
        self.consolelogs[IRC].flush()
        self.closeConsoleLog(IRC)

    def onSend(self, IRC, line, data, origin):
        modemapping = dict(Y="ircop", q="owner", a="admin", o="op",
                           h="halfop", v="voice")
        now = time.localtime()
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in now[0:6]])
        (cmd, target, params, extinfo) = data
        if IRC.registered and cmd == "PRIVMSG" and "CHANTYPES" in IRC.supports.keys() and len(target) and target[0] in IRC.supports["CHANTYPES"]:
            channel = IRC.channel(target)
            if channel in IRC.identity.channels:
                classes = " ".join([modemapping[mode] for mode in IRC.supports["PREFIX"][0] if mode in channel.modes.keys() and IRC.identity in channel.modes[mode]])
                if classes:
                    print >>self.channellogs[channel], "%s %s %s >>> :%s!%s@%s %s" % (timestamp, time.tzname[now[-1]], classes, IRC.identity.nick, IRC.identity.idnt, IRC.identity.host, line)
                else:
                    print >>self.channellogs[channel], "%s %s >>> :%s!%s@%s %s" % (timestamp, time.tzname[now[-1]], IRC.identity.nick, IRC.identity.idnt, IRC.identity.host, line)
                self.channellogs[channel].flush()
            else:
                print >>self.consolelogs[IRC], "%s %s >>> :%s!%s@%s %s" % (timestamp, time.tzname[now[-1]], IRC.identity.nick, IRC.identity.idnt, IRC.identity.host, line)
                self.consolelogs[IRC].flush()
        if IRC.registered and len(target) and (target[0] in IRC.supports["CHANTYPES"] or (len(target) > 1 and target[0] in IRC.supports["PREFIX"][1] and target[1] in IRC.supports["CHANTYPES"])) and cmd == "NOTICE":
            channel = IRC.channel(target[1:] if target[0]
                                  in IRC.supports["PREFIX"][1] else target)
            if channel in IRC.identity.channels:
                classes = " ".join([modemapping[mode] for mode in IRC.supports["PREFIX"][0] if mode in channel.modes.keys() and IRC.identity in channel.modes[mode]])
                if classes:
                    print >>self.channellogs[channel], "%s %s %s >>> :%s!%s@%s %s" % (timestamp, time.tzname[now[-1]], classes, IRC.identity.nick, IRC.identity.idnt, IRC.identity.host, line)
                else:
                    print >>self.channellogs[channel], "%s %s >>> :%s!%s@%s %s" % (timestamp, time.tzname[now[-1]], IRC.identity.nick, IRC.identity.idnt, IRC.identity.host, line)
                self.channellogs[channel].flush()
            else:
                print >>self.consolelogs[IRC], "%s %s >>> :%s!%s@%s %s" % (timestamp, time.tzname[now[-1]], IRC.identity.nick, IRC.identity.idnt, IRC.identity.host, line)
                self.consolelogs[IRC].flush()
