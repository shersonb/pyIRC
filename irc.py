#!/usr/bin/python
from threading import Thread, Event, Lock
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


class Connection(Thread):
    def __init__(self, server, nick="ircbot", ident="python", realname="Python IRC Library", passwd=None, port=None, ipv6=False, ssl=False, autoreconnect=True, log=sys.stderr, timeout=300, retrysleep=5, maxretries=15, onlogin=None):
        self.__name__ = "pyIRC"
        self.__version__ = "1.0.0rc2"
        self.__author__ = "Brian Sherson"
        self.__date__ = "August 26, 2013"

        if port is None:
            self.port = 6667 if not ssl else 6697
        else:
            self.port = port

        if type(nick) in (str, unicode):
            self.nick = [nick]
        elif type(nick) in (list, tuple):
            self.nick = nick

        self.realname = realname
        self.idnt = ident
        self.passwd = passwd
        self.server = server
        self.ssl = ssl
        self.ipv6 = ipv6

        self.connected = False
        self.registered = False
        self.connection = None

        self.autoreconnect = autoreconnect
        self.maxretries = maxretries
        self.timeout = timeout
        self.retrysleep = retrysleep

        self.quitexpected = False
        self.log = log

        self.modules = []
        self.trusted = []

        ### Initialize IRC environment variables
        self.motdgreet = ""
        self.motd = []
        self.identity = None
        self.users = []
        self.channels = []
        self.supports = {}

        self.lock = Lock()
        self.loglock = Lock()
        self.sendlock = Lock()
        self.outgoing = Queue.Queue()

        Thread.__init__(self)

    def event(self, method, modlist, exceptions=False, **params):
        #print method, modlist
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in time.localtime()[0:6]])
        for module in modlist:
            #print module, dir(module)
            #if modlist is not self.modules and module in self.modules: continue
            if method in dir(module) and callable(getattr(module, method)):
                try:
                    getattr(module, method)(self, **params)
                except:
                    with self.loglock:
                        exc, excmsg, tb = sys.exc_info()
                        print >>self.log, "%(timestamp)s !!! Exception in module %(module)s" % vars()
                        for tbline in traceback.format_exc().split("\n"):
                            print >>self.log, "%(timestamp)s !!! %(tbline)s" % vars()
                        self.log.flush()
                    if exceptions:  # If set to true, we raise the exception.
                        raise

    def addModule(self, module, trusted=False, **params):
        if module in self.modules:
            raise BaseException("Module already added.")
        with self.lock:
            self.event("onModuleAdd", [module], exceptions=True, **params)
            self.modules.append(module)
            if trusted:
                self.trusted.append(module)

    def insertModule(self, index, module, trusted=False, **params):
        if module in self.modules:
            raise BaseException("Module already added.")
        with self.lock:
            self.event("onModuleAdd", [module], exceptions=True, **params)
            self.modules.insert(index, module)
            if trusted:
                self.trusted.append(module)

    def rmModule(self, module, **params):
        with self.lock:
            self.modules.remove(module)
            self.event("onModuleRem", [module], exceptions=True, **params)
            if module in self.trusted:
                self.trusted.remove(module)

    def run(self):
        self.quitexpected = False
        outgoingthread = None
        server = self.server
        if self.ipv6 and ":" in server:
            server = "[%s]"%server
        port = self.port
        try:
            modules = list(self.modules)
            for channel in self.channels:
                for module in channel.modules:
                    if module not in modules:
                        modules.append(module)
            with self.lock:
                self.event("onLogOpen", modules)

            with self.loglock:
                timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(
                    2, "0") for t in time.localtime()[0:6]])
                print >>self.log, "%(timestamp)s ### Log session started" % vars()
                self.log.flush()

            attempt = 1
            while True:  # An entire connection lives within this while loop. When the connection fails, will try to reestablish, unless self.autoreconnect is set to False.
                while True:  # Enter retry loop
                    with self.loglock:
                        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2, "0") for t in time.localtime()[0:6]])
                        print >>self.log, "%(timestamp)s *** Attempting connection to %(server)s:%(port)s." % vars()
                        self.log.flush()

                    with self.lock:
                        self.event("onConnectAttempt", self.modules)

                        try:
                            if self.ssl:
                                s = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(self.timeout)
                                self.connection = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
                            else:
                                self.connection = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
                            self.connection.connect((self.server, self.port, 0, 0) if self.ipv6 else (self.server, self.port))
                            self.connected = True
                            self.connection.settimeout(self.timeout)

                            ### Setting up thread responsible for sending data back to IRC server.
                            outgoingthread = Outgoing(self)
                            outgoingthread.daemon = True
                            outgoingthread.start()

                            ### Run onConnect on all modules to signal connection was established.
                            modules = list(self.modules)
                            for channel in self.channels:
                                for module in channel.modules:
                                    if module not in modules:
                                        modules.append(module)
                            self.event("onConnect", modules)
                            with self.loglock:
                                timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2, "0") for t in time.localtime()[0:6]])
                                print >>self.log, "%(timestamp)s *** Connection to %(server)s:%(port)s established." % vars()
                                self.log.flush()
                            break
                        except socket.error:
                            with self.loglock:
                                exc, excmsg, tb = sys.exc_info()
                                timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2, "0") for t in time.localtime()[0:6]])
                                print >>self.log, "%(timestamp)s *** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars()
                                self.log.flush()

                    if self.quitexpected:
                        sys.exit()
                    if attempt < self.maxretries or self.maxretries == -1:
                        time.sleep(self.retrysleep)
                        attempt += 1
                    else:
                        with self.loglock:
                            timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2, "0") for t in time.localtime()[0:6]])
                            print >>self.log, "%(timestamp)s *** Maximum number of attempts reached. Giving up. (%(server)s:%(port)s)" % vars()
                            self.log.flush()
                        break

                ### Connection succeeded
                try:
                    ### Attempt initial registration.
                    nick = self.nick[0]
                    trynick = 0
                    if self.passwd:
                        self.raw("PASS :%(passwd)s" % vars(self))
                    self.raw("NICK :%(nick)s" % vars())
                    self.raw("USER %(idnt)s * * :%(realname)s" % vars(self))

                    ### Initialize buffers
                    linebuf = []
                    readbuf = ""

                    while True:  # Main loop of IRC connection.
                        while len(linebuf) == 0:  # Need Moar Data
                            read = self.connection.recv(512)

                            ### If read was empty, connection is terminated.
                            if read == "":
                                sys.exit()

                            ### If read was successful, parse away!
                            readbuf += read
                            lastlf = readbuf.rfind("\n")
                            if lastlf >= 0:
                                linebuf.extend(string.split(readbuf[0:lastlf],
                                                            "\n"))
                                readbuf = readbuf[lastlf+1:]

                        line = string.rstrip(linebuf.pop(0))

                        ### If received PING, then just pong back transparently.
                        ping = re.findall("^PING :?(.*)$", line)
                        if len(ping):
                            with self.lock:
                                self.connection.send("PONG :%s\n" % ping[0])
                            continue

                        with self.loglock:
                            timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2, "0") for t in time.localtime()[0:6]])
                            print >> self.log, "%(timestamp)s <<< %(line)s" % vars()
                            self.log.flush()

                        ### Attempts to match against pattern ":src cmd target params :extinfo"
                        matches = re.findall("^:(.+?)(?:!(.+?)@(.+?))?\\s+(.+?)(?:\\s+(.+?)(?:\\s+(.+?))??)??(?:\\s+:(.*))?$", line)

                        ### We have a match!
                        if len(matches):
                            parsed = (origin, ident, host, cmd, target, params, extinfo) = matches[0]
                            if re.match("^\\d+$", cmd):
                                cmd = int(cmd)  # Code is a numerical response
                            else:
                                cmd = cmd.upper()

                            if not self.registered:
                                if type(cmd) == int and target != "*":  # Registration complete!
                                    with self.lock:
                                        self.registered = True
                                        self.identity = self.user(target)
                                        self.serv = origin

                                        modules = list(self.modules)
                                        for channel in self.channels:
                                            for module in channel.modules:
                                                if module not in modules:
                                                    modules.append(module)
                                        self.event("onRegistered", modules)

                                elif cmd == 433 and target == "*":  # Server reports nick taken, so we need to try another.
                                    trynick += 1
                                    (q, s) = divmod(trynick, len(self.nick))
                                    nick = self.nick[s]
                                    if q > 0:
                                        nick += str(q)
                                    self.raw("NICK :%(nick)s" % vars())
                                if not self.registered:  # Registration is not yet complete
                                    continue

                            ### Major codeblock here! Track IRC state.
                            ### Send line to modules first
                            with self.lock:
                                self.event("onRecv", self.modules, line=line, data=parsed)
                                if cmd == 1:
                                    self.welcome = extinfo  # Welcome message
                                elif cmd == 2:
                                    self.hostinfo = extinfo  # Your Host
                                elif cmd == 3:
                                    self.servinfo = extinfo  # Server Created
                                elif cmd == 4:
                                    self.serv004 = params  # What is this code?
                                elif cmd == 5:  # Server Supports
                                    support = dict(re.findall("([A-Za-z0-9]+)(?:=(\\S*))?", params))
                                    if "CHANMODES" in support:
                                        support["CHANMODES"] = support["CHANMODES"].split(",")
                                    if "PREFIX" in support:
                                        matches = re.findall("\\((.*)\\)(.*)", support["PREFIX"])
                                        if matches:
                                            support["PREFIX"] = matches[0]
                                        else:
                                            del support["PREFIX"]  # Might as well delete the info if it doesn't match expected pattern
                                    self.supports.update(support)
                                    if "serv005" in dir(self) and type(self.serv005) == list:
                                        self.serv005.append(params)
                                    else:
                                        self.serv005 = [params]
                                elif cmd == 8:  # Channel Modes
                                    self.identity.snomask = params.lstrip("+")
                                    if "s" not in self.identity.modes:
                                        self.snomask = ""
                                elif cmd == 221:  # Channel Modes
                                    self.identity.modes = (params if params else extinfo).lstrip("+")
                                    if "s" not in self.identity.modes:
                                        self.snomask = ""
                                elif cmd == 251:
                                    self.netstats = extinfo
                                elif cmd == 252:
                                    self.opcount = int(params)
                                elif cmd == 254:
                                    self.chancount = int(params)
                                elif cmd == 311:  # WHOIS data
                                    pass
                                elif cmd == 321:  # Start LIST
                                    self.chanlistbegin = (params, extinfo)
                                    self.chanlist = {}
                                elif cmd == 322:  # LIST item
                                    (chan, pop) = params.split(" ", 1)
                                    self.chanlist[chan] = (pop, extinfo)
                                elif cmd == 323:
                                    self.chanlistend = extinfo  # End of LIST
                                elif cmd == 324:  # Channel Modes
                                    modeparams = params.split()
                                    channame = modeparams.pop(0)
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    setmodes = modeparams.pop(0)
                                    for mode in setmodes:
                                        if mode == "+":
                                            continue
                                        elif mode in self.supports["CHANMODES"][2]:
                                            param = modeparams.pop(0)
                                            channel.modes[mode] = param
                                        elif mode in self.supports["CHANMODES"][3]:
                                            channel.modes[mode] = True
                                elif cmd == 329:  # Channel created
                                    channame, created = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    channel.created = int(created)
                                elif cmd == 332:  # Channel Topic
                                    channame = params
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    channel.topic = extinfo
                                elif cmd == 333:  # Channel Topic info
                                    (channame, nick, dt) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    channel.topicsetby = nick
                                    channel.topictime = dt
                                elif cmd == 346:  # Invite
                                    (channame, invite, nick, invtime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    if "I" in channel.modes:
                                        if invite.lower() not in [m.lower() for (m, b, t) in channel.modes["I"]]:
                                            channel.modes["I"].append((invite, nick, int(invtime)))
                                    else:
                                        channel.modes["I"] = [(invite, nick, int(invtime))]
                                elif cmd == 348:  # Ban Exception
                                    (channame, exception, nick, exctime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    if "e" in channel.modes:
                                        if exception.lower() not in [m.lower() for (m, b, t) in channel.modes["e"]]:
                                            channel.modes["e"].append((exception, nick, int(exctime)))
                                    else:
                                        channel.modes["e"] = [(exception, nick, int(exctime))]
                                elif cmd == 352:  # WHO reply
                                    (channame, ident, host, serv, nick, flags) = params.split()
                                    (hops, realname) = extinfo.split(" ", 1)
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    user = self.user(nick)
                                    if user.nick != nick:
                                        user.nick = nick
                                    user.hops = hops
                                    user.realname = realname
                                    user.idnt = ident
                                    user.host = host
                                    user.server = serv
                                    user.away = "G" in flags
                                    user.ircop = "*" in flags
                                    if user not in channel.users:
                                        channel.users.append(user)
                                    if channel not in user.channels:
                                        user.channels.append(channel)
                                    for (mode, prefix) in zip(*self.supports["PREFIX"]):
                                        if prefix in flags:
                                            if mode in channel.modes.keys() and user not in channel.modes[mode]:
                                                channel.modes[mode].append(user)
                                            elif mode not in channel.modes.keys():
                                                channel.modes[mode] = [user]
                                elif cmd == 353:  # NAMES reply
                                    (devnull, channame) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    if "PREFIX" in self.supports:
                                        names = re.findall("(["+re.escape(self.supports["PREFIX"][1])+"]*)(\\S+)", extinfo)
                                    else:
                                        names = [("", name) for name in extinfo.split()]  # Still put it into tuple form for compatibility in the next structure
                                    for (symbs, nick) in names:
                                        user = self.user(nick)
                                        if user.nick != nick:
                                            user.nick = nick
                                        if channel not in user.channels:
                                            user.channels.append(channel)
                                        if user not in channel.users:
                                            channel.users.append(user)
                                        if "PREFIX" in self.supports:
                                            for symb in symbs:
                                                mode = self.supports["PREFIX"][0][self.supports["PREFIX"][1].index(symb)]
                                                if mode not in channel.modes:
                                                    channel.modes[mode] = [user]
                                                elif user not in channel.modes[mode]:
                                                    channel.modes[mode].append(user)
                                elif cmd == 367:  # Channel Ban
                                    (channame, ban, nick, bantime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    if "b" in channel.modes.keys():
                                        if ban.lower() not in [m.lower() for (m, b, t) in channel.modes["b"]]:
                                            channel.modes["b"].append((ban, nick, int(bantime)))
                                    else:
                                        channel.modes["b"] = [(ban, nick, int(bantime))]
                                elif cmd == 372:
                                    self.motd.append(extinfo)  # MOTD item
                                elif cmd == 375:  # Begin MOTD
                                    self.motdgreet = extinfo
                                    self.motd = []
                                elif cmd == 376:
                                    self.motdend = extinfo  # End of MOTD
                                elif cmd == 386 and "q" in self.supports["PREFIX"][0]:  # Channel Admin (Unreal)
                                    (channame, admin) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    user = self.user(owner)
                                    if user.nick != owner:
                                        user.nick = owner
                                    if "q" in channel.modes:
                                        if user not in channel.modes["q"]:
                                            channel.modes["q"].append(user)
                                    else:
                                        channel.modes["q"] = [user]
                                elif cmd == 388 and "a" in self.supports["PREFIX"][0]:  # Channel Admin (Unreal)
                                    (channame, admin) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    user = self.user(admin)
                                    if user.nick != admin:
                                        user.nick = admin
                                    if "a" in channel.modes:
                                        if user not in channel.modes["a"]:
                                            channel.modes["a"].append(user)
                                    else:
                                        channel.modes["a"] = [user]
                                elif cmd == "NICK":
                                    user = self.user(origin)
                                    modules = []
                                    for channel in user.channels:
                                        for module in channel.modules:
                                            if module not in modules:
                                                modules.append(module)
                                    self.event(modules, line, parsed)
                                    newnick = extinfo if len(extinfo) else target
                                    #print user, newnick
                                    ### Need to check if newnick is still listed
                                    for u in self.users:
                                        #print u
                                        #print [u.nick, newnick, u.nick.lower(), newnick.lower()]
                                        if u.nick.lower() == newnick.lower():
                                            with self.loglock:
                                                print >>self.log, "%s *** Orphaned user %s!%s@%s was removed when %s!%s@%s changed his/her nick to %s."%(timestamp, u.nick, u.idnt, u.host, user.nick, user.idnt, user.host, newnick)
                                                self.log.flush()
                                            self.users.remove(u)
                                            for channel in self.channels:
                                                if u in channel.users:
                                                    channel.users.remove(u)
                                    user.nick = newnick
                                elif cmd == "JOIN":
                                    channame = target if len(target) else extinfo
                                    user = self.user(origin)
                                    if user.nick != origin:
                                        user.nick = origin
                                    if user.idnt != ident:
                                        user.idnt = ident
                                    if user.host != host:
                                        user.host = host

                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name

                                    if user == self.identity:  # This means the bot is entering the room,
                                        # and will reset all the channel data, on the assumption that such data may have changed.
                                        # Also, the bot must request modes
                                        channel.topic = ""
                                        channel.topicmod = ""
                                        channel.modes = {}
                                        channel.users = []
                                        self.raw("MODE %(channame)s" % vars())
                                        self.raw("WHO %(channame)s" % vars())
                                        self.raw("MODE %s :%s" % (channame, self.supports["CHANMODES"][0]))
                                    if channel not in user.channels:
                                        user.channels.append(channel)
                                    if user not in channel.users:
                                        channel.users.append(user)
                                elif cmd == "KICK":
                                    kicker = self.user(origin)
                                    if kicker.nick != origin:
                                        kicker.nick = origin
                                    if kicker.idnt != ident:
                                        kicker.idnt = ident
                                    if kicker.host != host:
                                        kicker.host = host

                                    kicked = self.user(params)
                                    if kicked.nick != params:
                                        kicked.nick = params

                                    channel = self.channel(target)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != target:
                                        channel.name = target  # Server seems to have changed the idea of the case of the channel name
                                    if channel in kicked.channels:
                                        kicked.channels.remove(channel)
                                    if kicked in channel.users:
                                        channel.users.remove(kicked)
                                    if "PREFIX" in self.supports:
                                        for mode in self.supports["PREFIX"][0]:
                                            if mode in channel.modes and kicked in channel.modes[mode]:
                                                channel.modes[mode].remove(kicked)
                                    #if not len(chanobj.users): #Let's remove this channel
                                    #       del self.channels[target.lower()]
                                    if all([kicked not in c.users for c in self.identity.channels]):
                                        with self.loglock:
                                            print >>self.log, "%s *** User %s!%s@%s was orphaned when being kicked from %s."%(timestamp, kicked.nick, kicked.idnt, kicked.host, channel.name)
                                            self.log.flush()
                                elif cmd == "PART":
                                    user = self.user(origin)
                                    if user.nick != origin:
                                        user.nick = origin
                                    if user.idnt != ident:
                                        user.idnt = ident
                                    if user.host != host:
                                        user.host = host

                                    channel = self.channel(target)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != target:
                                        channel.name = target  # Server seems to have changed the idea of the case of the channel name

                                    if channel in user.channels:
                                        user.channels.remove(channel)
                                    if user in channel.users:
                                        channel.users.remove(user)
                                    if "PREFIX" in self.supports:
                                        for mode in self.supports["PREFIX"][0]:
                                            if mode in channel.modes and user in channel.modes[mode]:
                                                channel.modes[mode].remove(user)
                                    if all([user not in c.users for c in self.identity.channels]):
                                        with self.loglock:
                                            print >>self.log, "%s *** User %s!%s@%s was orphaned when parting %s."%(timestamp, user.nick, user.idnt, user.host, channel.name)
                                            self.log.flush()
                                elif cmd == "QUIT":
                                    user = self.user(origin)
                                    if user.nick != origin:
                                        user.nick = origin
                                    if user.idnt != ident:
                                        user.idnt = ident
                                    if user.host != host:
                                        user.host = host
                                    channels = list(user.channels)
                                    for channel in user.channels:
                                        for module in channel.modules:
                                            if module not in modules:
                                                modules.append(module)
                                    self.event(modules, line, parsed)
                                    for channel in channels:
                                        channel.lock.acquire(True)
                                    for channel in user.channels:
                                        if user in channel.users:
                                            channel.users.remove(user)
                                        if "PREFIX" in self.supports:
                                            for mode in self.supports["PREFIX"][0]:
                                                if mode in channel.modes and user in channel.modes[mode]:
                                                    channel.modes[mode].remove(user)
                                        #if not len(chanobj.users): #Let's remove this channel
                                        #       del self.channels[chan]
                                        # On second thought, no, since we may want to save certain info
                                    user.channels = []
                                    for channel in channels:
                                        channel.lock.release()
                                    print >>self.log, "%s *** User %s!%s@%s was orphaned when quitting IRC."%(timestamp, user.nick, user.idnt, user.host)
                                elif cmd == "MODE":
                                    if target[0] in self.supports["CHANTYPES"]:
                                        user = self.user(origin)
                                        if user.nick != origin:
                                            user.nick = origin
                                        if user.idnt != ident:
                                            user.idnt = ident
                                        if user.host != host:
                                            user.host = host

                                        channel = self.channel(target)
                                        self.event("onRecv", channel.modules, line=line, data=parsed)
                                        with channel.lock:
                                            if channel.name != target:
                                                channel.name = target  # Server seems to have changed the idea of the case of the channel name

                                            modeparams = params.split()
                                            setmodes = modeparams.pop(0)
                                            modeset = "+"
                                            for mode in setmodes:
                                                if mode in "+-":
                                                    modeset = mode
                                                else:
                                                    if mode in self.supports["CHANMODES"][0]:
                                                        param = modeparams.pop(0)
                                                        if modeset == "+":
                                                            if mode in channel.modes:
                                                                if param.lower() not in [mask.lower() for (mask, setby, settime) in channel.modes[mode]]:
                                                                    channel.modes[mode].append((param, origin, int(time.time())))
                                                            else:
                                                                channel.modes[mode] = [(param, origin, int(time.time()))]
                                                        else:
                                                            if mode in channel.modes.keys():
                                                                if mode == "b":  # Inspircd mode is case insentive when unsetting the mode
                                                                    masks = [mask.lower() for (mask, setby, settime) in channel.modes[mode]]
                                                                    if param.lower() in masks:
                                                                        index = masks.index(param.lower())
                                                                        #print "Index: %d"%index
                                                                        del channel.modes[mode][index]
                                                                else:
                                                                    masks = [mask for (mask, setby, settime) in channel.modes[mode]]
                                                                    if param in masks:
                                                                        index = masks.index(param)
                                                                        del channel.modes[mode][index]
                                                    elif mode in self.supports["CHANMODES"][1]:
                                                        param = modeparams.pop(0)
                                                        if modeset == "+":
                                                            channel.modes[mode] = param
                                                        else:
                                                            channel.modes[mode] = None
                                                    elif mode in self.supports["CHANMODES"][2]:
                                                        if modeset == "+":
                                                            param = modeparams.pop(0)
                                                            channel.modes[mode] = param
                                                        else:
                                                            channel.modes[mode] = None
                                                    elif mode in self.supports["CHANMODES"][3]:
                                                        if modeset == "+":
                                                            channel.modes[mode] = True
                                                        else:
                                                            channel.modes[mode] = False
                                                    elif "PREFIX" in self.supports and mode in self.supports["PREFIX"][0]:
                                                        modenick = modeparams.pop(0)
                                                        modeuser = self.user(modenick)
                                                        if modeuser.nick != modenick:
                                                            modeuser.nick = modenick
                                                        if modeset == "+":
                                                            if mode in channel.modes and modeuser not in channel.modes[mode]:
                                                                channel.modes[mode].append(modeuser)
                                                            if mode not in channel.modes:
                                                                channel.modes[mode] = [modeuser]
                                                        elif mode in channel.modes and modeuser in channel.modes[mode]:
                                                            channel.modes[mode].remove(modeuser)
                                    else:
                                        user = self.user(target)
                                        modeparams = (params if params else extinfo).split()
                                        setmodes = modeparams.pop(0)
                                        modeset = "+"
                                        for mode in setmodes:
                                            if mode in "+-":
                                                modeset = mode
                                                continue
                                            if modeset == "+":
                                                if mode not in user.modes:
                                                    user.modes += mode
                                                if mode == "s" and len(modeparams):
                                                    snomask = modeparams.pop(0)
                                                    for snomode in snomask:
                                                        if snomode in "+-":
                                                            snomodeset = snomode
                                                            continue
                                                        if snomodeset == "+" and snomode not in user.snomask:
                                                            user.snomask += snomode
                                                        if snomodeset == "-" and snomode in user.snomask:
                                                            user.snomask = user.snomask.replace(snomode, "")
                                            if modeset == "-":
                                                if mode in user.modes:
                                                    user.modes = user.modes.replace(mode, "")
                                                if mode == "s":
                                                    user.snomask = ""
                                elif cmd == "TOPIC":
                                    user = self.user(origin)
                                    if user.nick != origin:
                                        user.nick = origin
                                    if user.idnt != ident:
                                        user.idnt = ident
                                    if user.host != host:
                                        user.host = host

                                    channel = self.channel(target)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)

                                    with channel.lock:
                                        if channel.name != target:
                                            channel.name = target  # Server seems to have changed the idea of the case of the channel name
                                        channel.topic = extinfo
                                elif cmd == "PRIVMSG":
                                    user = self.user(origin)
                                    if user.nick != origin:
                                        user.nick = origin
                                    if user.idnt != ident:
                                        user.idnt = ident
                                    if user.host != host:
                                        user.host = host

                                    if target[0] in self.supports["CHANTYPES"]:
                                        channel = self.channel(target)
                                        self.event("onRecv", channel.modules, line=line, data=parsed)
                                        if channel.name != target:
                                            channel.name = target  # Server seems to have changed the idea of the case of the channel name
                                    elif target[0] == "$":
                                        pass  # Server message -- Not implemented
                                    else:
                                        targetuser = self.user(target)
                                        if targetuser.nick != target:
                                            targetuser.nick = target  # Server seems to have changed the idea of the case of the nickname

                                    ### CTCP handling
                                    ctcp = re.findall("^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$", extinfo)
                                    if ctcp:
                                        (ctcptype, ext) = ctcp[0]
                                        if ctcptype.upper() == "VERSION":
                                            user.ctcpreply("VERSION", self.ctcpversion())
                                        if ctcptype.upper() == "TIME":
                                            tformat = time.ctime()
                                            tz = time.tzname[0]
                                            user.ctcpreply("TIME", "%(tformat)s %(tz)s" % vars())
                                        if ctcptype.upper() == "PING":
                                            user.ctcpreply("PING", "%(ext)s" % vars())
                                        if ctcptype.upper() == "FINGER":
                                            user.ctcpreply("FINGER", "%(ext)s" % vars())
                                elif cmd == 910:  # Channel Access List
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    if "w" in channel.modes.keys():
                                        if mask not in [m for (m, b, t) in channel.modes["w"]]:
                                            channel.modes["w"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["w"] = [(mask, setby, int(settime))]
                                elif cmd == 941:  # Channel spamfilter List
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    if "g" in channel.modes.keys():
                                        if mask not in [m for (m, b, t) in channel.modes["g"]]:
                                            channel.modes["g"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["g"] = [(mask, setby, int(settime))]
                                elif cmd == 954:  # Channel spamfilter List
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.modules, line=line, data=parsed)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    if "X" in channel.modes.keys():
                                        if mask not in [m for (m, b, t) in channel.modes["X"]]:
                                            channel.modes["X"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["X"] = [(mask, setby, int(settime))]
                                elif cmd in (495, 384, 385, 386, 468, 470, 366, 315, 482, 484, 953, 368, 482, 349, 940, 911, 489, 490, 492, 520, 530):  # Channels which appear in params
                                    for param in params.split():
                                        if len(param) and param[0] in self.supports["CHANTYPES"]:
                                            channel = self.channel(param)
                                            self.event("onRecv", channel.modules, line=line, data=parsed)

                        else:  # Line does NOT match ":src cmd target params :extinfo"
                            self.event("onRecv", self.modules, line=line,
                                       data=None)
                except SystemExit:  # Connection lost normally.
                    pass
                except socket.error:  # Connection lost due to either ping timeout or connection reset by peer. Not a fatal error.
                    with self.loglock:
                        exc, excmsg, tb = sys.exc_info()
                        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2, "0") for t in time.localtime()[0:6]])
                        print >>self.log, "%(timestamp)s *** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars()
                        self.log.flush()
                except:  # Unknown exception, treated as FATAL. Try to quit IRC and terminate thread with exception.
                    ### Quit with a (hopefully) useful quit message, or die trying.
                    try:
                        self.quit("%s" % traceback.format_exc()
                            .rstrip().split("\n")[-1])
                    except:
                        pass
                    raise
                finally:  # Post-connection operations after connection is lost, and must be executed, even if exception occurred.
                    with self.lock:
                        modules = list(self.modules)
                        for channel in self.channels:
                            for module in channel.modules:
                                if module not in modules:
                                    modules.append(module)
                        self.event("onDisconnect", self.modules)

                    ### Tell outgoing thread to quit.
                    self.outgoing.put("quit")

                    ### Wait until the outgoing thread dies.
                    if outgoingthread:
                        outgoingthread.join()
                        outgoingthread = None

                    self.connected = False
                    self.registered = False
                    self.identity = None

                    try:
                        self.connection.close()
                    except:
                        pass

                    with self.loglock:
                        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2, "0") for t in time.localtime()[0:6]])
                        print >>self.log, "%(timestamp)s *** Connection Terminated." % vars()
                        self.log.flush()

                if self.quitexpected or not self.autoreconnect:
                    sys.exit()

                ### If we make it to this point, then it is because connection was lost unexpectedly, and will attempt to reconnect if self.autoreconnect is True.
                time.sleep(self.retrysleep)

        except SystemExit:
            pass

        except:  # Print exception to log file
            with self.loglock:
                timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(
                    2, "0") for t in time.localtime()[0:6]])
                print >>self.log, "%(timestamp)s !!! Fatal Exception" % vars()
                for tbline in traceback.format_exc().split("\n"):
                    print >>self.log, "%(timestamp)s !!! %(tbline)s" % vars()
                self.log.flush()
            sys.exit()

        finally:
            with self.loglock:
                timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(
                    2, "0") for t in time.localtime()[0:6]])
                print >>self.log, "%(timestamp)s ### Log session ended" % vars(
                )
                self.log.flush()

            Thread.__init__(self)  # Makes thread restartable

    def __repr__(self):
        server = self.server
        if self.ipv6 and ":" in server:
            server = "[%s]"%server
        port = self.port
        if self.identity:
            nick = self.identity.nick
            ident = self.identity.idnt if self.identity.idnt else "*"
            host = self.identity.host if self.identity.host else "*"
        else:
            nick = "*"
            ident = "*"
            host = "*"
        if self.ssl and self.ipv6:
            protocol = "ircs6"
        elif self.ssl:
            protocol = "ircs"
        elif self.ipv6:
            protocol = "irc6"
        else:
            protocol = "irc"
        return "<IRC Context: %(nick)s!%(ident)s@%(host)s on %(protocol)s://%(server)s:%(port)s>" % locals()
        #else: return "<IRC Context: irc%(ssl)s://%(server)s:%(port)s>" % locals()

    def quit(self, msg="", origin=None):
        with self.lock:
            self.quitexpected = True
            if self.connected:
                if len(msg):
                    self.raw("QUIT :%(msg)s" % vars(), origin=origin)
                else:
                    self.raw("QUIT", origin=origin)

    def ctcpversion(self):
        reply = []
        ### Prepare reply for module
        reply.append("%(__name__)s %(__version__)s, %(__author__)s" %
                     vars(self))

        ### Prepare reply for Python and OS versions
        pyver = sys.version.split("\n")
        pyver[0] = "Python "+pyver[0]
        reply.extend(pyver)
        reply.extend(platform.platform().split("\n"))
        ### Prepare reply for extension modules
        for module in self.modules:
            try:
                r = "%(__name__)s %(__version__)s" % vars(module)
                if "__extinfo__" in vars(module):
                    r += ", %(__extinfo__)s" % vars()
                reply.append(r)
            except:
                pass
        return reduce(lambda x, y: "%s; %s" % (x, y), reply)

    def raw(self, line, origin=None):
        self.outgoing.put((line, origin))

    def user(self, nick):
        users = [user for user in self.users if user.nick.lower(
        ) == nick.lower()]
        if len(users):
            return users[0]
        else:
            user = User(nick, self)
            self.users.append(user)
            timestamp = reduce(lambda x, y: x+":"+y, [str(
                t).rjust(2, "0") for t in time.localtime()[0:6]])
            with self.loglock:
                print >>self.log, "%s *** User %s created."%(timestamp, nick)
                self.log.flush()
            return user

    def channel(self, name):
        channels = [chan for chan in self.channels if name.lower(
        ) == chan.name.lower()]
        if len(channels):
            return channels[0]
        else:
            timestamp = reduce(lambda x, y: x+":"+y, [str(
                t).rjust(2, "0") for t in time.localtime()[0:6]])
            chan = Channel(name, self)
            self.channels.append(chan)
            with self.loglock:
                print >>self.log, "%s *** Channel %s created."%(
                    timestamp, name)
                self.log.flush()
            return chan


class Channel(object):
    def __init__(self, name, context):
        self.name = name
        self.context = context
        self.modules = []
        self.topic = ""
        self.topicsetby = ""
        self.topictime = ()
        self.topicmod = ""
        self.modes = {}
        self.users = []
        self.created = None
        self.lock = Lock()

    def msg(self, msg, origin=None):
        chan = self.name
        self.context.raw("PRIVMSG %(chan)s :%(msg)s" % vars(), origin=origin)

    def settopic(self, msg, origin=None):
        chan = self.name
        self.context.raw("TOPIC %(chan)s :%(msg)s" % vars(), origin=origin)

    def notice(self, msg, target="", origin=None):
        chan = self.name
        self.context.raw("NOTICE %(target)s%(chan)s :%(msg)s" %
                         vars(), origin=origin)

    def ctcp(self, act, msg="", origin=None):
        if len(msg):
            self.msg("\01%(act)s %(msg)s\01" % vars(), origin=origin)
        else:
            self.msg("\01%(act)s\01" % vars())

    def ctcpreply(self, act, msg="", origin=None):
        if len(msg):
            self.notice("\01%(act)s %(msg)s\01" % vars(), origin=origin)
        else:
            self.notice("\01%(act)s\01" % vars(), origin=origin)

    def me(self, msg="", origin=None):
        self.ctcp("ACTION", msg, origin=origin)

    def part(self, msg="", origin=None):
        chan = self.name
        if msg:
            self.context.raw("PART %(chan)s :%(msg)s" % vars(), origin=origin)
        else:
            self.context.raw("PART %(chan)s" % vars(), origin)

    def join(self, key="", origin=None):
        chan = self.name
        if key:
            self.context.raw("JOIN :%(chan)s %(key)s" % vars(), origin=origin)
        else:
            self.context.raw("JOIN :%(chan)s" % vars(), origin=origin)

    def kick(self, nick, msg="", origin=None):
        chan = self.name
        if len(msg):
            self.context.raw("KICK %(chan)s %(nick)s :%(msg)s" %
                             vars(), origin=origin)
        else:
            self.context.raw("KICK %(chan)s %(nick)s" % vars(), origin=origin)

    def __repr__(self):
        return "<Channel: "+self.name+"@"+self.context.server+"/"+str(self.context.port)+">"


class User(object):
    def __init__(self, nick, context):
        self.nick = nick
        self.idnt = ""
        self.host = ""
        self.channels = []
        self.context = context
        self.modes = ""
        self.snomask = ""
        self.server = None
        self.hops = None
        self.ircop = False

    def __repr__(self):
        return "<User: %(nick)s!%(idnt)s@%(host)s>" % vars(self)

    def msg(self, msg, origin=None):
        nick = self.nick
        self.context.raw("PRIVMSG %(nick)s :%(msg)s" % vars(), origin=origin)

    def notice(self, msg, origin=None):
        nick = self.nick
        self.context.raw("NOTICE %(nick)s :%(msg)s" % vars(), origin=origin)

    def ctcp(self, act, msg="", origin=None):
        if len(msg):
            self.msg("\01%(act)s %(msg)s\01" % vars(), origin=origin)
        else:
            self.msg("\01%(act)s\01" % vars(), origin=origin)

    def ctcpreply(self, act, msg="", origin=None):
        if len(msg):
            self.notice("\01%(act)s %(msg)s\01" % vars(), origin=origin)
        else:
            self.notice("\01%(act)s\01" % vars(), origin=origin)

    def me(self, msg, origin=None):
        self.ctcp("ACTION", msg, origin=origin)


class SendLines(Thread):
    def __init__(self, connection, lines, origin=None):
        self.connection = connection
        self.lines = lines
        self.origin = origin
        Thread.__init__(self)

    def run(self):
        for line in self.lines:
            self.connection.raw(reply, origin=self.origin)
            self.connection.log.flush()
            time.sleep(2)


class Outgoing(Thread):
    def __init__(self, IRC, throttle=0.25, lines=40, t=5):
        self.IRC = IRC
        self.throttle = throttle
        self.lines = lines
        self.time = t
        #self.queue=Queue()
        Thread.__init__(self)

    def run(self):
        throttled = False
        timestamps = []
        while True:
            q = self.IRC.outgoing.get()
            if q == "quit" or not self.IRC.connected:
                break
            line, origin = q
            match = re.findall("^(.+?)(?:\\s+(.+?)(?:\\s+(.+?))??)??(?:\\s+:(.*))?$", line, re.I)
            (cmd, target, params, extinfo) = match[0]
            if cmd.upper() == "QUIT":
                self.IRC.quitexpected = True
            timestamp = reduce(lambda x, y: x+":"+y, [str(
                t).rjust(2, "0") for t in time.localtime()[0:6]])
            with self.IRC.lock:
                try:
                    self.IRC.connection.send("%(line)s\n" % vars())
                except socket.error:
                    try:
                        self.IRC.connection.shutdown(0)
                    except:
                        pass
                    raise

                ### Modify line if it contains a password so that the password is not logged or sent to any potentially untrustworthy modules
                #if re.match("^(.+?)(?:\\s+(.+?)(?:\\s+(.+?))??)??(?:\\s+:(.*))?$", line, re.I):
                if cmd.upper() == "PRIVMSG":
                    if target.upper() == "NICKSERV":
                        nscmd = re.findall(r"^\s*(\S+)\s+(\S+)(?:\s*(\S+)(?:\s*(.+))?)?$", extinfo, re.I)
                        if nscmd:
                            nscmd = nscmd[0]
                            if nscmd[0].upper() in ("IDENTIFY", "REGISTER"):
                                extinfo = "%s ********"%nscmd[0]
                                line = "%s %s :%s"%(cmd, target, extinfo)
                            elif nscmd[0].upper() in ("GROUP", "GHOST", "RECOVER", "RELEASE"):
                                extinfo = "%s %s ********"%nscmd[:2]
                                line = "%s %s :%s"%(cmd, target, extinfo)
                            elif nscmd[0].upper() == "SET":
                                if nscmd[1].upper() == "PASSWORD":
                                    extinfo = "%s %s ********"%nscmd[:2]
                                    line = "%s %s :%s"%(cmd, target, extinfo)
                            elif nscmd[0].upper() not in ("GLIST", "ACCESS", "SASET", "DROP", "SENDPASS", "ALIST", "INFO", "LIST", "LOGOUT", "STATUS", "UPDATE", "GETPASS", "FORBID", "SUSPEND", "UNSUSPEND", "OINFO"):
                                extinfo = "********"
                                line = "%s %s :%s"%(cmd, target, extinfo)
                    if target.upper() == "CHANSERV":
                        cscmd = re.findall(r"^\s*(\S+)\s+(\S+)\s+(\S+)(?:\s*(\S+)(?:\s*(.+))?)?$", extinfo, re.I)
                        if cscmd:
                            cscmd = cscmd[0]
                            if cscmd[0].upper() in ("IDENTIFY", "REGISTER"):
                                extinfo = "%s %s ********"%cscmd[:2]
                                line = "%s %s :%s"%(cmd, target, extinfo)
                            elif cscmd[0].upper() in ("GROUP", "GHOST", "RECOVER", "RELEASE"):
                                extinfo = "%s %s %s ********"%cscmd[:3]
                                line = "%s %s :%s"%(cmd, target, extinfo)
                            elif cscmd[0].upper() == "SET":
                                if cscmd[2].upper() == "PASSWORD":
                                    extinfo = "%s %s %s ********"%cscmd[:3]
                                    line = "%s %s :%s"%(cmd, target, extinfo)
                            elif cscmd[0].upper() not in ("GLIST", "ACCESS", "SASET", "DROP", "SENDPASS", "ALIST", "INFO", "LIST", "LOGOUT", "STATUS", "UPDATE", "GETPASS", "FORBID", "SUSPEND", "UNSUSPEND", "OINFO"):
                                extinfo = "********"
                                line = "%s %s :%s"%(cmd, target, extinfo)
                    #elif target.upper()=="CHANSERV":
                        #msg=extinfo.split(" ")
                        #if msg[0].upper() in ("IDENTIFY", "REGISTER") and len(msg)>2:
                            #msg[2]="********"
                            #extinfo=" ".join(msg)
                            #line="%s %s :%s"%(cmd, target, extinfo)
                elif cmd.upper() == "NS":
                    if target.upper() in ("IDENTIFY", "REGISTER"):
                        params = params.split(" ")
                        while "" in params:
                            params.remove("")
                        if len(params):
                            params[0] = "********"
                        params = " ".join(params)
                        line = "%s %s %s"%(cmd, target, params)
                    elif target.upper() in ("GROUP", "GHOST", "RECOVER", "RELEASE"):
                        params = params.split(" ")
                        while "" in params:
                            params.remove("")
                        if len(params) > 1:
                            params[1] = "********"
                        params = " ".join(params)
                        line = "%s %s %s"%(cmd, target, params)
                    elif target.upper() not in ("GLIST", "ACCESS", "SASET", "DROP", "SENDPASS", "ALIST", "INFO", "LIST", "LOGOUT", "STATUS", "UPDATE", "GETPASS", "FORBID", "SUSPEND", "UNSUSPEND", "OINFO"):
                        params = ""
                        target = "********"
                        line = "%s %s"%(cmd, target)
                elif cmd.upper() == "OPER":
                    params = "********"
                    line = "%s %s %s"%(cmd, target, params)
                elif cmd.upper() == "PASS":
                    extinfo = "********"
                    target = ""
                    line = "%s :%s"%(cmd, extinfo)
                elif cmd.upper() == "IDENTIFY":
                    target = "********"
                    line = "%s %s"%(cmd, target)
                self.IRC.event("onSend", self.IRC.modules, line=line, data=(cmd, target, params, extinfo), origin=origin)
            with self.IRC.loglock:
                print >>self.IRC.log, "%(timestamp)s >>> %(line)s" % vars()
                self.IRC.log.flush()
            timestamps.append(time.time())
            while timestamps[0] < timestamps[-1]-self.time-0.1:
                del timestamps[0]
            if throttled:
                if len(timestamps) < 2:
                    throttled = False
            else:
                if len(timestamps) >= self.lines:
                    throttled = True
            if throttled:
                time.sleep(max(timestamps[-1]+self.throttle-time.time(), 0))


class Pinger(Thread):
    def __init__(self, connection, lock=None):
        self.connection = connection
        self.lock = lock
        self.daemon = True
        Thread.__init__(self)

    def run(self):
        pass
