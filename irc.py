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
import ssl
import glob
import iqueue as Queue


def timestamp():
    t = time.time()
    ms = 1000*t%1000
    ymdhms = time.localtime(t)
    tz = time.altzone if ymdhms.tm_isdst else time.timezone
    sgn = "-" if tz >= 0 else "+"
    return "%04d-%02d-%02d %02d:%02d:%02d.%03d%s%02d:%02d"%(ymdhms[:6]+(1000*t%1000, sgn, abs(tz)/3600, abs(tz)/60%60))


class InvalidName(BaseException):
    pass


class InvalidPrefix(BaseException):
    pass


class InvalidCharacter(BaseException):
    pass


class Connection(Thread):
    def __init__(self, server, nick="ircbot", username="python", realname="Python IRC Library", passwd=None, port=None, ipv6=False, ssl=False, autoreconnect=True, log=sys.stderr, timeout=300, retrysleep=5, maxretries=15, onlogin=None):
        self.__name__ = "pyIRC"
        self.__version__ = "1.1"
        self.__author__ = "Brian Sherson"
        self.__date__ = "December 1, 2013"

        if port is None:
            self.port = 6667 if not ssl else 6697
        else:
            self.port = port

        if type(nick) in (str, unicode):
            self.nick = [nick]
        elif type(nick) in (list, tuple):
            self.nick = nick

        self.realname = realname
        self.username = username
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

        self.addons = []
        self.trusted = []

        ### Initialize IRC environment variables
        self.motdgreet = None
        self.motd = None
        self.motdend = None
        self.identity = None
        self.users = []
        self.channels = []
        self.supports = {}

        self.lock = Lock()
        self.loglock = Lock()
        self.sendlock = Lock()
        self.outgoing = Queue.Queue()
        self.outgoingthread = None

        Thread.__init__(self)

    def logwrite(self, *lines):
        with self.loglock:
            ts = timestamp()
            for line in lines:
                print >>self.log, "%s %s"%(ts, line)
            self.log.flush()

    def logopen(self, filename):
        with self.loglock:
            ts = timestamp()
            newlog = open(filename, "a")
            if type(self.log) == file and not self.log.closed:
                print >>self.log, "%s ### Log file closed" % (ts)
                if self.log not in (sys.stdout, sys.stderr):
                    self.log.close()
            self.log = newlog
            print >>self.log, "%s ### Log file opened" % (ts)
            self.log.flush()

    def event(self, method, modlist, exceptions=False, **params):
        timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(2,
                                                               "0") for t in time.localtime()[0:6]])
        handled = []
        unhandled = []
        errors = []
        for k, addon in enumerate(modlist):
            if modlist.index(addon) < k:
                continue
            if method in dir(addon) and callable(getattr(addon, method)):
                try:
                    getattr(addon, method)(self, **params)
                except:
                    exc, excmsg, tb = sys.exc_info()
                    errors.append((addon, exc, excmsg, tb))
                    self.logwrite(*["!!! Exception in addon %(addon)s" % vars()]+["!!! %s"%line for line in traceback.format_exc().split("\n")])
                    print >>sys.stderr, "Exception in addon %(addon)s" % vars()
                    print >>sys.stderr, traceback.format_exc()
                    if exceptions:  # If set to true, we raise the exception.
                        raise
                else:
                    handled.append(addon)
            else:
                unhandled.append(addon)
        return (handled, unhandled, errors)

    def addAddon(self, addon, trusted=False, **params):
        if addon in self.addons:
            raise BaseException("Addon already added.")
        with self.lock:
            self.event("onAddonAdd", [addon], exceptions=True, **params)
            self.addons.append(addon)
            if trusted:
                self.trusted.append(addon)

    def insertAddon(self, index, addon, trusted=False, **params):
        if addon in self.addons:
            raise BaseException("Addon already added.")
        with self.lock:
            self.event("onAddonAdd", [addon], exceptions=True, **params)
            self.addons.insert(index, addon)
            if trusted:
                self.trusted.append(addon)

    def rmAddon(self, addon, **params):
        with self.lock:
            self.addons.remove(addon)
            self.event("onAddonRem", [addon], exceptions=True, **params)
            if addon in self.trusted:
                self.trusted.remove(addon)

    def run(self):
        privmodeeventnames = dict(q=("Owner", "Deowner"), a=("Admin", "Deadmin"), o=("Op", "Deop"), h=("Halfop", "Dehalfop"), v=("Voice", "Devoice"))
        maskmodeeventnames = dict(b=("Ban", "Unban"), e=(
            "BanExcept", "UnbanExcept"), I=("Invite", "Uninvite"))
        self.quitexpected = False
        whoisstarted = False
        nameslist = []
        wholist = []
        lists = {}
        nameschan = None
        server = self.server
        if self.ipv6 and ":" in server:
            server = "[%s]"%server
        port = self.port
        try:
            with self.lock:
                self.event("onSessionOpen", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []))

            self.logwrite("### Log session started")

            attempt = 1
            while True:  # An entire connection lives within this while loop. When the connection fails, will try to reestablish, unless self.autoreconnect is set to False.
                while True:  # Enter retry loop
                    self.logwrite("*** Attempting connection to %(server)s:%(port)s." % vars())

                    with self.lock:
                        self.event("onConnectAttempt", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []))

                        try:
                            if self.ssl:
                                s = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(self.timeout)
                                self.connection = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
                            else:
                                self.connection = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
                            self.connection.connect((self.server, self.port, 0, 0) if self.ipv6 else (self.server, self.port))
                        except socket.error:
                            exc, excmsg, tb = sys.exc_info()
                            self.event("onConnectFail", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), exc=exc, excmsg=excmsg, tb=tb)
                            self.logwrite("*** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars())
                        else:
                            self.connected = True
                            self.connection.settimeout(self.timeout)

                            ### Setting up thread responsible for sending data back to IRC server.
                            self.outgoing._interrupted = False
                            self.outgoingthread = Outgoing(self)
                            self.outgoingthread.daemon = True
                            self.outgoingthread.start()

                            ### Run onConnect on all addons to signal connection was established.
                            self.event("onConnect", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []))
                            self.logwrite("*** Connection to %(server)s:%(port)s established." % vars())
                            break

                    if self.quitexpected:
                        sys.exit()
                    if attempt < self.maxretries or self.maxretries == -1:
                        time.sleep(self.retrysleep)
                        if self.quitexpected:
                            sys.exit()
                        attempt += 1
                    else:
                        self.logwrite("*** Maximum number of attempts reached. Giving up. (%(server)s:%(port)s)" % vars())
                        sys.exit()

                ### Connection succeeded
                try:
                    ### Attempt initial registration.
                    nick = self.nick[0]
                    trynick = 0
                    if self.passwd:
                        self.raw("PASS :%s" % self.passwd.split(
                            "\n")[0].rstrip())
                    self.raw("NICK :%s" % nick.split("\n")[0].rstrip())
                    self.raw("USER %s * * :%s" % (self.username.split("\n")[0].rstrip(), self.realname.split("\n")[0].rstrip()))

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

                        self.logwrite("<<< %(line)s" % vars())

                        ### Attempts to match against pattern ":src cmd target params :extinfo"
                        matches = re.findall(r"^:(.+?)(?:!(.+?)@(.+?))?\s+(.+?)(?:\s+(.+?)(?:\s+(.+?))??)??(?:\s+:(.*))?$", line)

                        ### We have a match!
                        if len(matches):
                            parsed = (origin, username, host, cmd, target, params, extinfo) = matches[0]
                            unhandled = []

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
                                        self.event("onRegistered", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []))

                                elif cmd == 433 and target == "*":  # Server reports nick taken, so we need to try another.
                                    trynick += 1
                                    (q, s) = divmod(trynick, len(self.nick))
                                    nick = self.nick[s]
                                    if q > 0:
                                        nick += str(q)
                                    self.raw("NICK :%s" % nick.split("\n")[0].rstrip())
                                if not self.registered:  # Registration is not yet complete
                                    continue

                            if username and host:
                                nickname = origin
                                origin = self.user(origin)
                                if origin.nick != nickname:
                                    ### Origin nickname has changed
                                    origin.user = nickname
                                if origin.username != username:
                                    ### Origin username has changed
                                    origin.username = username
                                if origin.host != host:
                                    ### Origin host has changed
                                    origin.host = host

                            chanmatch = re.findall(r"([%s]?)([%s]\S*)"%(re.escape(self.supports.get("PREFIX", ("ohv", "@%+"))[1]), re.escape(self.supports.get("CHANTYPES", "#"))), target)
                            if chanmatch:
                                targetprefix, channame = chanmatch[0]
                                target = self.channel(channame)
                                if target.name != channame:
                                    ### Target channel name has changed
                                    target.name = channame
                            elif len(target) and target[0] != "$" and cmd != "NICK":
                                targetprefix = ""
                                target = self.user(target)

                            data = dict(origin=origin, cmd=cmd, target=target, targetprefix=targetprefix, params=params, extinfo=extinfo)

                            ### Major codeblock here! Track IRC state.
                            ### Send line to addons first
                            with self.lock:
                                self.event("onRecv", self.addons, line=line,
                                           **data)
                                if cmd == 1:
                                    (handled, unhandled, exceptions) = self.event("onWelcome", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), origin=origin, msg=extinfo)
                                    self.welcome = extinfo  # Welcome message
                                elif cmd == 2:
                                    (handled, unhandled, exceptions) = self.event("onYourHost", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), origin=origin, msg=extinfo)
                                    self.hostinfo = extinfo  # Your Host
                                elif cmd == 3:
                                    (handled, unhandled, exceptions) = self.event("onServerCreated", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), origin=origin, msg=extinfo)
                                    self.servcreated = extinfo  # Server Created
                                elif cmd == 4:
                                    (handled, unhandled, exceptions) = self.event("onServInfo", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), origin=origin, servinfo=params)
                                    self.servinfo = params  # What is this code?
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
                                    (handled, unhandled, exceptions) = self.event("onSupports", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), origin=origin, supports=support)
                                    self.supports.update(support)
                                    if "serv005" in dir(self) and type(self.serv005) == list:
                                        self.serv005.append(params)
                                    else:
                                        self.serv005 = [params]
                                elif cmd == 8:  # Snomask
                                    snomask = params.lstrip("+")
                                    (handled, unhandled, exceptions) = self.event("onSnoMask", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), origin=origin, snomask=snomask)
                                    self.identity.snomask = snomask
                                    if "s" not in self.identity.modes:
                                        self.snomask = ""
                                elif cmd == 221:  # User Modes
                                    modes = (params if params else extinfo).lstrip("+")
                                    (handled, unhandled, exceptions) = self.event("onUserModes", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), origin=origin, snomask=modes)
                                    self.identity.modes = modes
                                    if "s" not in self.identity.modes:
                                        self.snomask = ""
                                elif cmd == 251:  # Net Stats
                                    (handled, unhandled, exceptions) = self.event("onNetStats", self.addons, origin=origin, netstats=extinfo)
                                    self.netstats = extinfo
                                elif cmd == 252:
                                    opcount = int(params)
                                    (handled, unhandled, exceptions) = self.event("onOpCount", self.addons, origin=origin, opcount=opcount)
                                    self.opcount = opcount
                                elif cmd == 254:
                                    chancount = int(params)
                                    (handled, unhandled, exceptions) = self.event("onChanCount", self.addons, origin=origin, chancount=chancount)
                                    self.chancount = chancount

                                elif cmd == 305:  # Returned from away status
                                    (handled, unhandled, exceptions) = self.event("onReturn", self.addons, origin=origin, msg=extinfo)
                                    self.identity.away = False

                                elif cmd == 306:  # Entered away status
                                    (handled, unhandled, exceptions) = self.event("onAway", self.addons, origin=origin, msg=extinfo)
                                    self.identity.away = True

                                elif cmd == 311:  # Start of WHOIS data
                                    nickname, username, host, star = params.split()
                                    user = self.user(nickname)
                                    (handled, unhandled, exceptions) = self.event("onWhoisStart", self.addons, origin=origin, user=user, nickname=nickname, username=username, host=host, realname=extinfo)
                                    user.nick = nickname
                                    user.username = username
                                    user.host = host

                                elif cmd == 301:  # Away Message
                                    user = self.user(params)
                                    (handled, unhandled, exceptions) = self.event("onWhoisAway", self.addons, origin=origin, user=user, nickname=params, awaymsg=extinfo)
                                    user.away = True
                                    user.awaymsg = extinfo

                                elif cmd == 303:  # ISON Reply
                                    users = [self.user(user) for user in extinfo.split(" ")]
                                    (handled, unhandled, exceptions) = self.event("onIsonReply", self.addons, origin=origin, isonusers=users)

                                elif cmd == 307:  # Is a registered nick
                                    (handled, unhandled, exceptions) = self.event("onWhoisRegisteredNick", self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                                elif cmd == 378:  # Connecting From
                                    (handled, unhandled, exceptions) = self.event("onWhoisConnectingFrom", self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                                elif cmd == 319:  # Channels
                                    (handled, unhandled, exceptions) = self.event("onWhoisChannels", self.addons, origin=origin, user=self.user(params), nickname=params, chanlist=extinfo.split(" "))
                                elif cmd == 310:  # Availability
                                    (handled, unhandled, exceptions) = self.event("onWhoisAvailability", self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                                elif cmd == 312:  # Server
                                    nickname, server = params.split(" ")
                                    user = self.user(nickname)
                                    (handled, unhandled, exceptions) = self.event("onWhoisServer", self.addons, origin=origin, user=user, nickname=nickname, server=server, servername=extinfo)
                                    user.server = server
                                elif cmd == 313:  # IRC Op
                                    user = self.user(params)
                                    (handled, unhandled, exceptions) = self.event("onWhoisOp", self.addons, origin=origin, user=user, nickname=params, msg=extinfo)
                                    user.ircop = True
                                    user.ircopmsg = extinfo
                                elif cmd == 317:  # Idle and Signon times
                                    nickname, idletime, signontime = params.split(" ")
                                    user = self.user(nickname)
                                    (handled, unhandled, exceptions) = self.event("onWhoisTimes", self.addons, origin=origin, user=user, nickname=nickname, idletime=int(idletime), signontime=int(signontime), msg=extinfo)
                                    user.idlesince = int(time.time())-int(idletime)
                                    user.signontime = int(signontime)
                                elif cmd == 671:  # SSL
                                    user = self.user(params)
                                    (handled, unhandled, exceptions) = self.event("onWhoisSSL", self.addons, origin=origin, user=user, nickname=params, msg=extinfo)
                                    user.ssl = True
                                elif cmd == 379:  # User modes
                                    (handled, unhandled, exceptions) = self.event("onWhoisModes", self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                                elif cmd == 330:  # Logged in as
                                    nickname, loggedinas = params.split(" ")
                                    user = self.user(nickname)
                                    (handled, unhandled, exceptions) = self.event("onWhoisLoggedInAs", self.addons, origin=origin, user=user, nickname=nickname, loggedinas=loggedinas, msg=extinfo)
                                    user.loggedinas = loggedinas
                                elif cmd == 318:  # End of WHOIS
                                    (handled, unhandled, exceptions) = self.event("onWhoisEnd", self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)

                                elif cmd == 321:  # Start LIST
                                    (handled, unhandled, exceptions) = self.event("onListStart", self.addons, origin=origin, params=params, extinfo=extinfo)
                                elif cmd == 322:  # LIST item
                                    (chan, pop) = params.split(" ", 1)
                                    (handled, unhandled, exceptions) = self.event("onListEntry", self.addons, origin=origin, channel=self.channel(chan), population=int(pop), extinfo=extinfo)
                                elif cmd == 323:  # End of LIST
                                    (handled, unhandled, exceptions) = self.event("onListEnd", self.addons, origin=origin, endmsg=extinfo)

                                elif cmd == 324:  # Channel Modes
                                    modeparams = params.split()
                                    channame = modeparams.pop(0)
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    if channel.name != channame:
                                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                                    setmodes = modeparams.pop(0)
                                    modedelta = []
                                    for mode in setmodes:
                                        if mode == "+":
                                            continue
                                        elif mode in self.supports["CHANMODES"][2]:
                                            param = modeparams.pop(0)
                                            modedelta.append(("+%s"%mode, param))
                                        elif mode in self.supports["CHANMODES"][3]:
                                            modedelta.append(("+%s"%mode, None))
                                    (handled, unhandled, exceptions) = self.event("onChannelModes", self.addons+channel.addons, channel=channel, modedelta=modedelta)
                                    for ((modeset, mode), param) in modedelta:
                                        if mode in self.supports["CHANMODES"][2]:
                                            channel.modes[mode] = param
                                        elif mode in self.supports["CHANMODES"][3]:
                                            channel.modes[mode] = True

                                elif cmd == 329:  # Channel created
                                    channame, created = params.split()
                                    created = int(created)
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onChanCreated", self.addons+channel.addons, channel=channel, created=created)
                                    channel.created = int(created)

                                elif cmd == 332:  # Channel Topic
                                    channame = params
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onTopic", self.addons+channel.addons, origin=origin, channel=channel, topic=extinfo)
                                    channel.topic = extinfo

                                elif cmd == 333:  # Channel Topic info
                                    (channame, nick, dt) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onTopicInfo", self.addons+channel.addons, origin=origin, channel=channel, topicsetby=nick, topictime=int(dt))
                                    channel.topicsetby = nick
                                    channel.topictime = int(dt)

                                elif cmd == 352:  # WHO reply
                                    (channame, username, host, serv, nick, flags) = params.split()
                                    try:
                                        (hops, realname) = extinfo.split(" ", 1)
                                    except ValueError:
                                        hops = extinfo
                                        realname = None

                                    if channame[0] in self.supports.get("CHANTYPES", "#"):
                                        channel = self.channel(channame)
                                    else:
                                        channel = None

                                    user = self.user(nick)

                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onWhoEntry", self.addons+channel.addons, origin=origin, channel=channel, user=user, channame=channame, username=username, host=host, serv=serv, nick=nick, flags=flags, hops=int(hops), realname=realname)
                                    user.hops = hops
                                    user.realname = realname
                                    user.username = username
                                    user.host = host
                                    user.server = serv
                                    user.away = "G" in flags
                                    user.ircop = "*" in flags
                                    if type(channel) == Channel:
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

                                elif cmd == 315:  # End of WHO reply
                                    (handled, unhandled, exceptions) = self.event("onWhoEnd", self.addons+channel.addons, origin=origin, param=params, endmsg=extinfo)

                                elif cmd == 353:  # NAMES reply
                                    (flag, channame) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)

                                    if "PREFIX" in self.supports:
                                        names = re.findall(r"([%s]*)([^@!\s]+)(?:!(\S+)@(\S+))?"%re.escape(self.supports["PREFIX"][1]), extinfo)
                                    else:
                                        names = re.findall(r"()([^@!\s]+)(?:!(\S+)@(\S+))?", extinfo)  # Still put it into tuple form for compatibility in the next structure
                                    (handled, unhandled, exceptions) = self.event("onNames", self.addons+channel.addons, origin=origin, channel=channel, flag=flag, channame=channame, nameslist=names)

                                    for (symbs, nick, username, host) in names:
                                        user = self.user(nick)
                                        if user.nick != nick:
                                            user.nick = nick
                                        if username and user.username != username:
                                            user.username = username
                                        if host and user.host != host:
                                            user.host = host
                                        with channel.lock:
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

                                elif cmd == 366:  # End of NAMES reply
                                    channel = self.channel(params)
                                    (handled, unhandled, exceptions) = self.event("onNamesEnd", self.addons+channel.addons, origin=origin, channel=channel, channame=params, endmsg=extinfo)

                                elif cmd == 372:  # MOTD line
                                    (handled, unhandled, exceptions) = self.event("onMOTDLine", self.addons, origin=origin, motdline=extinfo)
                                    self.motd.append(extinfo)
                                elif cmd == 375:  # Begin MOTD
                                    (handled, unhandled, exceptions) = self.event("onMOTDStart", self.addons, origin=origin, motdgreet=extinfo)
                                    self.motdgreet = extinfo
                                    self.motd = []
                                elif cmd == 376:
                                    (handled, unhandled, exceptions) = self.event("onMOTDEnd", self.addons, origin=origin, motdend=extinfo)
                                    self.motdend = extinfo  # End of MOTD

                                elif cmd == 386 and "q" in self.supports["PREFIX"][0]:  # Channel Owner (Unreal)
                                    (channame, owner) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
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
                                    self.event("onRecv", channel.addons, line=line, **data)
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
                                    newnick = extinfo if len(extinfo) else target

                                    addons = reduce(lambda x, y: x+y, [chan.addons for chan in origin.channels], [])
                                    self.event("onRecv", addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onNickChange", self.addons+addons, user=origin, newnick=newnick)
                                    if origin == self.identity:
                                        (handled, unhandled, exceptions) = self.event("onMeNickChange", self.addons+addons, newnick=newnick)

                                    for u in self.users:
                                        if u.nick.lower() == newnick.lower():
                                            self.users.remove(u)  # Nick collision, safe to assume this orphaned user is offline, so we shall remove the old instance.
                                            for channel in self.channels:
                                                ### If for some odd reason, the old user still appears common channels, then we will remove the user anyway.
                                                if u in channel.users:
                                                    channel.users.remove(u)
                                    origin.nick = newnick

                                elif cmd == "JOIN":
                                    channel = target if type(target) == Channel else self.channel(extinfo)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onJoin", self.addons+channel.addons, user=origin, channel=channel)

                                    if origin == self.identity:  # This means the bot is entering the room,
                                        # and will reset all the channel data, on the assumption that such data may have changed.
                                        # Also, the bot must request modes
                                        channel.topic = ""
                                        channel.topicmod = ""
                                        channel.modes = {}
                                        channel.users = []
                                        self.event("onMeJoin", self.addons+channel.addons, channel=channel)
                                        self.raw("MODE %s" % channel.name)
                                        self.raw("WHO %s" % channel.name)
                                        if "CHANMODES" in self.supports.keys():
                                            self.raw("MODE %s :%s" % (channel.name, self.supports["CHANMODES"][0]))

                                    if channel not in origin.channels:
                                        origin.channels.append(channel)
                                    if origin not in channel.users:
                                        channel.users.append(origin)

                                elif cmd == "KICK":
                                    kicked = self.user(params)
                                    if kicked.nick != params:
                                        kicked.nick = params

                                    self.event("onRecv", target.addons, line=line, **data)
                                    if origin == self.identity:
                                        self.event("onMeKick", self.addons+target.addons, channel=target, kicked=kicked, kickmsg=extinfo)
                                    if kicked == self.identity:
                                        self.event("onMeKicked", self.addons+target.addons, kicker=origin, channel=target, kickmsg=extinfo)
                                    (handled, unhandled, exceptions) = self.event("onKick", self.addons+target.addons, kicker=origin, channel=target, kicked=kicked, kickmsg=extinfo)

                                    if target in kicked.channels:
                                        kicked.channels.remove(target)
                                    if kicked in target.users:
                                        target.users.remove(kicked)
                                    if "PREFIX" in self.supports:
                                        for mode in self.supports["PREFIX"][0]:
                                            if mode in target.modes and kicked in target.modes[mode]:
                                                target.modes[mode].remove(kicked)

                                elif cmd == "PART":
                                    self.event("onRecv", target.addons, line=line, **data)
                                    if origin == self.identity:
                                        self.event("onMePart", self.addons+target.addons, channel=target, partmsg=extinfo)
                                    (handled, unhandled, exceptions) = self.event("onPart", self.addons+target.addons, user=origin, channel=target, partmsg=extinfo)

                                    if target in origin.channels:
                                        origin.channels.remove(target)
                                    if origin in target.users:
                                        target.users.remove(origin)
                                    if "PREFIX" in self.supports:
                                        for mode in self.supports["PREFIX"][0]:
                                            if mode in target.modes and origin in target.modes[mode]:
                                                target.modes[mode].remove(origin)

                                elif cmd == "QUIT":
                                    channels = list(origin.channels)
                                    addons = reduce(lambda x, y: x+y, [chan.addons for chan in origin.channels], [])
                                    self.event("onRecv", addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onQuit", self.addons+addons, user=origin, quitmsg=extinfo)
                                    for channel in origin.channels:
                                        with channel.lock:
                                            if origin in channel.users:
                                                channel.users.remove(origin)
                                            if "PREFIX" in self.supports:
                                                for mode in self.supports["PREFIX"][0]:
                                                    if mode in channel.modes and origin in channel.modes[mode]:
                                                        channel.modes[mode].remove(origin)
                                    origin.channels = []

                                elif cmd == "MODE":
                                    if type(target) == Channel:
                                        self.event("onRecv", target.addons, line=line, **data)
                                        modedelta = []
                                        modeparams = params.split()
                                        setmodes = modeparams.pop(0)
                                        modeset = "+"
                                        for mode in setmodes:
                                            if mode in "+-":
                                                modeset = mode
                                            else:
                                                if mode in self.supports["CHANMODES"][0]+self.supports["CHANMODES"][1]:
                                                    param = modeparams.pop(0)
                                                    modedelta.append(("%s%s"%(modeset, mode), param))
                                                    if mode in maskmodeeventnames.keys():
                                                        if modeset == "+":
                                                            eventname = maskmodeeventnames[mode][0]
                                                        if modeset == "-":
                                                            eventname = maskmodeeventnames[mode][1]
                                                        matchesbot = glob.fnmatch.fnmatch("%s!%s@%s".lower()%(self.identity.nick, self.identity.username, self.identity.host), param.lower())
                                                        self.event("on%s"%eventname, self.addons+target.addons, user=origin, channel=target, banmask=param)
                                                        if matchesbot:
                                                            self.event("onMe%s"%eventname, self.addons+target.addons, user=origin, channel=target, banmask=param)
                                                elif mode in self.supports["CHANMODES"][2]:
                                                    if modeset == "+":
                                                        param = modeparams.pop(0)
                                                        modedelta.append(("%s%s"%(modeset, mode), param))
                                                    else:
                                                        modedelta.append(("%s%s"%(modeset, mode), None))
                                                elif mode in self.supports["CHANMODES"][3]:
                                                    modedelta.append(("%s%s"%(modeset, mode), None))
                                                elif "PREFIX" in self.supports and mode in self.supports["PREFIX"][0]:
                                                    modenick = modeparams.pop(0)
                                                    modeuser = self.user(modenick)
                                                    if mode in privmodeeventnames.keys():
                                                        if modeset == "+":
                                                            eventname = privmodeeventnames[mode][0]
                                                        if modeset == "-":
                                                            eventname = privmodeeventnames[mode][1]
                                                        self.event("on%s"%eventname, self.addons+target.addons, user=origin, channel=target, modeuser=modeuser)
                                                        if modeuser == self.identity:
                                                            self.event("onMe%s"%eventname, self.addons+target.addons, user=origin, channel=target)
                                                    modedelta.append(("%s%s"%(modeset, mode), modeuser))
                                        (handled, unhandled, exceptions) = self.event("onChanModeSet", self.addons+target.addons, user=origin, channel=target, modedelta=modedelta)
                                        with target.lock:
                                            for ((modeset, mode), param) in modedelta:
                                                if mode in self.supports["CHANMODES"][0]:
                                                    if modeset == "+":
                                                        if mode in target.modes:
                                                            if param.lower() not in [mask.lower() for (mask, setby, settime) in target.modes[mode]]:
                                                                target.modes[mode].append((param, origin, int(time.time())))
                                                        else:
                                                            target.modes[mode] = [(param, origin, int(time.time()))]
                                                    else:
                                                        if mode in target.modes.keys():
                                                            if mode == "b":  # Inspircd mode is case insentive when unsetting the mode
                                                                masks = [mask.lower() for (mask, setby, settime) in target.modes[mode]]
                                                                if param.lower() in masks:
                                                                    index = masks.index(param.lower())
                                                                    #print "Index: %d"%index
                                                                    del target.modes[mode][index]
                                                            else:
                                                                masks = [mask for (mask, setby, settime) in target.modes[mode]]
                                                                if param in masks:
                                                                    index = masks.index(param)
                                                                    del target.modes[mode][index]
                                                elif mode in self.supports["CHANMODES"][1]:
                                                    if modeset == "+":
                                                        target.modes[mode] = param
                                                    else:
                                                        target.modes[mode] = None
                                                elif mode in self.supports["CHANMODES"][2]:
                                                    if modeset == "+":
                                                        target.modes[mode] = param
                                                    else:
                                                        target.modes[mode] = None
                                                elif mode in self.supports["CHANMODES"][3]:
                                                    if modeset == "+":
                                                        target.modes[mode] = True
                                                    else:
                                                        target.modes[mode] = False
                                                elif "PREFIX" in self.supports and mode in self.supports["PREFIX"][0]:
                                                    if modeset == "+":
                                                        if mode in target.modes and param not in target.modes[mode]:
                                                            target.modes[mode].append(param)
                                                        if mode not in target.modes:
                                                            target.modes[mode] = [param]
                                                    elif mode in target.modes and param in target.modes[mode]:
                                                        target.modes[mode].remove(param)
                                    elif type(target) == User:
                                        modeparams = (params if params else extinfo).split()
                                        setmodes = modeparams.pop(0)
                                        modeset = "+"
                                        for mode in setmodes:
                                            if mode in "+-":
                                                modeset = mode
                                                continue
                                            if modeset == "+":
                                                if mode not in target.modes:
                                                    target.modes += mode
                                                if mode == "s" and len(modeparams):
                                                    snomask = modeparams.pop(0)
                                                    for snomode in snomask:
                                                        if snomode in "+-":
                                                            snomodeset = snomode
                                                            continue
                                                        if snomodeset == "+" and snomode not in target.snomask:
                                                            target.snomask += snomode
                                                        if snomodeset == "-" and snomode in target.snomask:
                                                            target.snomask = target.snomask.replace(snomode, "")
                                            if modeset == "-":
                                                if mode in target.modes:
                                                    target.modes = target.modes.replace(mode, "")
                                                if mode == "s":
                                                    target.snomask = ""

                                elif cmd == "TOPIC":
                                    self.event("onRecv", target.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onTopicSet", self.addons+target.addons, user=origin, channel=target, topic=extinfo)

                                    with target.lock:
                                        target.topic = extinfo
                                        target.topicsetby = origin
                                        target.topictime = int(time.time())

                                elif cmd == "INVITE":
                                    channel = self.channel(extinfo if extinfo else params)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onInvite", self.addons+channel.addons, user=origin, channel=channel)

                                elif cmd == "PRIVMSG":
                                    if type(target) == Channel:
                                        self.event("onRecv", target.addons, line=line, **data)

                                    ### CTCP handling
                                    ctcp = re.findall("^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$", extinfo)
                                    if ctcp:
                                        (ctcptype, ext) = ctcp[0]
                                        if ctcptype.upper() == "ACTION":
                                            if type(target) == Channel:
                                                (handled, unhandled, exceptions) = self.event("onChanAction", self.addons+target.addons, user=origin, channel=target, targetprefix=targetprefix, action=ext)
                                            elif target == self.identity:
                                                (handled, unhandled, exceptions) = self.event("onPrivAction", self.addons, user=origin, action=ext)
                                        else:
                                            if type(target) == Channel:
                                                (handled, unhandled, exceptions) = self.event("onChanCTCP", self.addons+target.addons, user=origin, channel=target, targetprefix=targetprefix, ctcptype=ctcptype, params=ext)
                                            elif target == self.identity:
                                                (handled, unhandled, exceptions) = self.event("onPrivCTCP", self.addons, user=origin, ctcptype=ctcptype, params=ext)
                                        if ctcptype.upper() == "VERSION":
                                            origin.ctcpreply("VERSION", self.ctcpversion())
                                        if ctcptype.upper() == "TIME":
                                            tformat = time.ctime()
                                            tz = time.tzname[0]
                                            origin.ctcpreply("TIME", "%(tformat)s %(tz)s" % vars())
                                        if ctcptype.upper() == "PING":
                                            origin.ctcpreply("PING", "%(ext)s" % vars())
                                        if ctcptype.upper() == "FINGER":
                                            origin.ctcpreply("FINGER", "%(ext)s" % vars())
                                    else:
                                        if type(target) == Channel:
                                            (handled, unhandled, exceptions) = self.event("onChanMsg", self.addons+target.addons, user=origin, channel=target, targetprefix=targetprefix, msg=extinfo)
                                        elif target == self.identity:
                                            (handled, unhandled, exceptions) = self.event("onPrivMsg", self.addons, user=origin, msg=extinfo)

                                elif cmd == "NOTICE":
                                    if type(target) == Channel:
                                        self.event("onRecv", target.addons, line=line, **data)

                                    ### CTCP handling
                                    ctcp = re.findall("^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$", extinfo)
                                    if ctcp and target == self.identity:
                                        (ctcptype, ext) = ctcp[0]
                                        (handled, unhandled, exceptions) = self.event("onCTCPReply", self.addons, origin=origin, ctcptype=ctcptype, params=ext)
                                    else:
                                        if type(target) == Channel:
                                            (handled, unhandled, exceptions) = self.event("onChanNotice", self.addons+target.addons, origin=origin, channel=target, targetprefix=targetprefix, msg=extinfo)
                                        elif target == self.identity:
                                            (handled, unhandled, exceptions) = self.event("onPrivNotice", self.addons, origin=origin, msg=extinfo)

                                elif cmd == 367:  # Channel Ban list
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onBanListEntry", self.addons+channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                                    if "b" in channel.modes.keys():
                                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["b"]]:
                                            channel.modes["b"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["b"] = [(mask, setby, int(settime))]
                                elif cmd == 368:
                                    channel = self.channel(params)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onBanListEnd", self.addons+channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                                elif cmd == 346:  # Channel Invite list
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onInviteListEntry", self.addons+channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                                    if "I" in channel.modes.keys():
                                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["I"]]:
                                            channel.modes["I"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["I"] = [(mask, setby, int(settime))]
                                elif cmd == 347:
                                    channel = self.channel(params)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onInviteListEnd", self.addons+channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                                elif cmd == 348:  # Channel Ban Exception list
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onBanExceptListEntry", self.addons+channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                                    if "e" in channel.modes.keys():
                                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["e"]]:
                                            channel.modes["e"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["e"] = [(mask, setby, int(settime))]
                                elif cmd == 349:
                                    channel = self.channel(params)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onBanExceptListEnd", self.addons+channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                                elif cmd == 910:  # Channel Access List
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onAccessListEntry", self.addons+channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                                    if "w" in channel.modes.keys():
                                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["b"]]:
                                            channel.modes["w"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["w"] = [(mask, setby, int(settime))]
                                elif cmd == 911:
                                    channel = self.channel(params)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onAccessListEnd", self.addons+channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                                elif cmd == 941:  # Spam Filter list
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onSpamfilterListEntry", self.addons+channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                                    if "g" in channel.modes.keys():
                                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["g"]]:
                                            channel.modes["g"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["g"] = [(mask, setby, int(settime))]
                                elif cmd == 940:
                                    channel = self.channel(params)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onSpamfilterListEnd", self.addons+channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                                elif cmd == 954:  # Channel exemptchanops list
                                    (channame, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onExemptChanOpsListEntry", self.addons+channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                                    if "X" in channel.modes.keys():
                                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["X"]]:
                                            channel.modes["X"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["X"] = [(mask, setby, int(settime))]
                                elif cmd == 953:
                                    channel = self.channel(params)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onExemptChanOpsListEnd", self.addons+channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                                elif cmd == 728:  # Channel quiet list
                                    (channame, modechar, mask, setby, settime) = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onQuietListEntry", self.addons+channel.addons, origin=origin, channel=channel, modechar=modechar, mask=mask, setby=setby, settime=int(settime))
                                    if "q" in channel.modes.keys():
                                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["q"]]:
                                            channel.modes["q"].append((mask, setby, int(settime)))
                                    else:
                                        channel.modes["q"] = [(mask, setby, int(settime))]
                                elif cmd == 729:
                                    channame, modechar = params.split()
                                    channel = self.channel(channame)
                                    self.event("onRecv", channel.addons, line=line, **data)
                                    (handled, unhandled, exceptions) = self.event("onQuietListEnd", self.addons+channel.addons, channel=channel, endmsg=extinfo)

                                elif cmd in (495, 384, 385, 386, 468, 470, 366, 315, 482, 484, 953, 368, 482, 349, 940, 911, 489, 490, 492, 520, 530):  # Channels which appear in params
                                    for param in params.split():
                                        if len(param) and param[0] in self.supports["CHANTYPES"]:
                                            channel = self.channel(param)
                                            self.event("onRecv", channel.addons, line=line, **data)

                                elif type(cmd) == int:
                                    (handled, unhandled, exceptions) = self.event("on%03d"%cmd, self.addons, line=line, origin=origin, target=target, params=params, extinfo=extinfo)
                                else:
                                    (handled, unhandled, exceptions) = self.event("on%s"%cmd, self.addons, line=line, origin=origin, cmd=cmd, target=target, params=params, extinfo=extinfo)

                                self.event("onUnhandled", unhandled, line=line, origin=origin, cmd=cmd, target=target, params=params, extinfo=extinfo)

                        else:  # Line does NOT match ":origin cmd target params :extinfo"
                            self.event("onRecv", self.addons, line=line)
                except SystemExit:  # Connection lost normally.
                    pass
                except socket.error:  # Connection lost due to either ping timeout or connection reset by peer. Not a fatal error.
                    exc, excmsg, tb = sys.exc_info()
                    self.logwrite("*** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars())
                except:  # Unknown exception, treated as FATAL. Try to quit IRC and terminate thread with exception.
                    ### Quit with a (hopefully) useful quit message, or die trying.
                    self.quitexpected = True
                    try:
                        self.quit("%s" % traceback.format_exc()
                            .rstrip().split("\n")[-1])
                    except:
                        pass
                    raise
                finally:  # Post-connection operations after connection is lost, and must be executed, even if exception occurred.
                    with self.lock:
                        (handled, unhandled, exceptions) = self.event("onDisconnect", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []), expected=self.quitexpected)
                        self.connected = False
                        self.registered = False
                        self.identity = None

                    ### Tell outgoing thread to quit.
                    self.outgoing.interrupt()

                    ### Wait until the outgoing thread dies.
                    if self.outgoingthread and self.outgoingthread.isAlive():
                        self.outgoingthread.join()
                        self.outgoingthread = None

                    try:
                        self.connection.close()
                    except:
                        pass

                    self.logwrite("*** Connection Terminated.")

                if self.quitexpected or not self.autoreconnect:
                    sys.exit()

                ### If we make it to this point, then it is because connection was lost unexpectedly, and will attempt to reconnect if self.autoreconnect is True.
                time.sleep(self.retrysleep)

        except SystemExit:
            pass

        except:  # Print exception to log file
            self.logwrite(*["!!! FATAL Exception"]+["!!! %s"%line for line in traceback.format_exc().split("\n")])
            print >>sys.stderr, "FATAL Exception" % vars()
            print >>sys.stderr, traceback.format_exc()
            sys.exit()

        finally:
            self.logwrite("### Log session ended")
            (handled, unhandled, exceptions) = self.event("onSessionClose", self.addons+reduce(lambda x, y: x+y, [chan.addons for chan in self.channels], []))
            Thread.__init__(self)  # Makes thread restartable

    def __repr__(self):
        server = self.server
        if self.ipv6 and ":" in server:
            server = "[%s]"%server
        port = self.port
        if self.identity:
            nick = self.identity.nick
            user = self.identity.username if self.identity.username else "*"
            host = self.identity.host if self.identity.host else "*"
        else:
            nick = "*"
            user = "*"
            host = "*"
        if self.ssl and self.ipv6:
            protocol = "ircs6"
        elif self.ssl:
            protocol = "ircs"
        elif self.ipv6:
            protocol = "irc6"
        else:
            protocol = "irc"
        return "<IRC Context: %(nick)s!%(user)s@%(host)s on %(protocol)s://%(server)s:%(port)s>" % locals()
        #else: return "<IRC Context: irc%(ssl)s://%(server)s:%(port)s>" % locals()

    def oper(self, name, passwd, origin=None):
        self.raw("OPER %s %s" % (re.findall("^([^\r\n\\s]*)", name)[0],
                                 re.findall("^([^\r\n\\s]*)", passwd)[0]), origin=origin)

    def list(self, params="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", params)[0]):
            self.raw("LIST %s" % (re.findall(
                "^([^\r\n\\s]*)", params)[0]), origin=origin)
        else:
            self.raw("LIST", origin=origin)

    def getmotd(self, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self.raw("MOTD %s" % (re.findall(
                "^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self.raw("MOTD", origin=origin)

    def version(self, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self.raw("VERSION %s" % (re.findall(
                "^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self.raw("VERSION", origin=origin)

    def stats(self, query, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self.raw("STATS %s %s" % (query, re.findall(
                "^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self.raw("STATS %s"%query, origin=origin)

    def quit(self, msg="", origin=None):
        with self.lock:
            if self.connected:
                if len(re.findall("^([^\r\n]*)", msg)[0]):
                    self.raw("QUIT :%s" % re.findall("^([^\r\n]*)",
                                                     msg)[0], origin=origin)
                else:
                    self.raw("QUIT", origin=origin)

    def ctcpversion(self):
        reply = []
        ### Prepare reply for addon
        reply.append("%(__name__)s %(__version__)s, %(__author__)s" %
                     vars(self))

        ### Prepare reply for Python and OS versions
        pyver = sys.version.split("\n")
        pyver[0] = "Python "+pyver[0]
        reply.extend(pyver)
        reply.extend(platform.platform().split("\n"))
        ### Prepare reply for extension addons
        for addon in self.addons:
            try:
                r = "%(__name__)s %(__version__)s" % vars(addon)
                if "__extinfo__" in vars(addon):
                    r += ", %(__extinfo__)s" % vars()
                reply.append(r)
            except:
                pass
        return reduce(lambda x, y: "%s; %s" % (x, y), reply)

    def raw(self, line, origin=None):
        if "\r" in line or "\n" in line:
            raise InvalidCharacter
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
            return chan


class Channel(object):
    def __init__(self, name, context):
        if not re.match(r"^[%s]\S*$" % context.supports.get("CHANTYPES", "#"), name):
            raise InvalidName(repr(name))
        self.name = name
        self.context = context
        self.addons = []
        self.topic = ""
        self.topicsetby = ""
        self.topictime = ()
        self.topicmod = ""
        self.modes = {}
        self.users = []
        self.created = None
        self.lock = Lock()

    def msg(self, msg, target="", origin=None):
        if target and target not in self.context.supports.get("PREFIX", ("ohv", "@%+"))[1]:
            raise InvalidPrefix
        for line in re.findall("([^\r\n]+)", msg):
            self.context.raw("PRIVMSG %s%s :%s" % (target,
                                                   self.name, line), origin=origin)

    def who(self, origin=None):
        self.context.raw("WHO %s" % (self.name), origin=origin)

    def names(self, origin=None):
        self.context.raw("NAMES %s" % (self.name), origin=origin)

    def notice(self, msg, target="", origin=None):
        if target and target not in self.context.supports.get("PREFIX", ("ohv", "@%+"))[1]:
            raise InvalidPrefix
        for line in re.findall("([^\r\n]+)", msg):
            self.context.raw("NOTICE %s%s :%s" % (target,
                                                  self.name, line), origin=origin)

    def settopic(self, msg, origin=None):
        self.context.raw("TOPIC %s :%s" % (self.name, re.findall(
            "^([^\r\n]*)", msg)[0]), origin=origin)

    def ctcp(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.msg("\01%s %s\01" % (act.upper(), re.findall(
                "^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.msg("\01%s\01" % act.upper())

    def ctcpreply(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.notice("\01%s %(msg)s\01" % (act.upper(),
                                              re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.notice("\01%s\01" % act.upper(), origin=origin)

    def me(self, msg="", origin=None):
        self.ctcp("ACTION", msg, origin=origin)

    def part(self, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.context.raw("PART %s :%s" % (self.name,
                                              re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.context.raw("PART %s" % self.name, origin=origin)

    def invite(self, user, origin=None):
        nickname = user.nick if type(
            user) == User else re.findall("^([^\r\n\\s]*)", user)[0]
        if nickname == "":
            raise InvalidName
        self.context.raw("INVITE %s %s" % (nickname, self.name), origin=origin)

    def join(self, key="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", key)[0]):
            self.context.raw("JOIN %s %s" % (self.name, re.findall(
                "^([^\r\n\\s]*)", key)[0]), origin=origin)
        else:
            self.context.raw("JOIN %s" % self.name, origin=origin)

    def kick(self, user, msg="", origin=None):
        nickname = user.nick if type(
            user) == User else re.findall("^([^\r\n\\s]*)", user)[0]
        if nickname == "":
            raise InvalidName
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.context.raw("KICK %s %s :%s" % (self.name, nickname,
                                                 re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.context.raw("KICK %s %s" % (self.name,
                                             nickname), origin=origin)

    def __repr__(self):
        return "<Channel: "+self.name+"@"+self.context.server+"/"+str(self.context.port)+">"


class User(object):
    def __init__(self, nick, context):
        if not re.match(r"^\S+$", nick):
            raise InvalidName
        self.nick = nick
        self.username = ""
        self.host = ""
        self.channels = []
        self.context = context
        self.modes = ""
        self.snomask = ""
        self.server = None
        self.hops = None
        self.ircop = False
        self.ircopmsg = ""
        self.idlesince = None
        self.signontime = None
        self.ssl = None
        self.away = None

    def __repr__(self):
        return "<User: %(nick)s!%(username)s@%(host)s>" % vars(self)

    def msg(self, msg, origin=None):
        for line in re.findall("([^\r\n]+)", msg):
            self.context.raw("PRIVMSG %s :%s" % (self.nick,
                                                 line), origin=origin)

    def notice(self, msg, origin=None):
        for line in re.findall("([^\r\n]+)", msg):
            self.context.raw("NOTICE %s :%s" % (self.nick,
                                                line), origin=origin)

    def ctcp(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.msg("\01%s %s\01" % (act.upper(), re.findall(
                "^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.msg("\01%s\01" % act.upper())

    def ctcpreply(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.notice("\01%s %s\01" % (act.upper(),
                                         re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.notice("\01%s\01" % act.upper(), origin=origin)

    def me(self, msg="", origin=None):
        self.ctcp("ACTION", msg, origin=origin)


class Outgoing(Thread):
    def __init__(self, IRC, throttle=0.25, lines=10, t=5):
        self.IRC = IRC
        self.throttle = throttle
        self.lines = lines
        self.time = t
        #self.queue=Queue()
        Thread.__init__(self)

    def run(self):
        try:
            throttled = False
            timestamps = []
            while True:
                try:
                    q = self.IRC.outgoing.get()
                except Queue.Interrupted:
                    break
                if q == "quit" or not self.IRC.connected:
                    break
                line, origin = q
                match = re.findall("^(.+?)(?:\\s+(.+?)(?:\\s+(.+?))??)??(?:\\s+:(.*))?$", line, re.I)
                (cmd, target, params, extinfo) = match[0]
                timestamp = reduce(lambda x, y: x+":"+y, [str(t).rjust(
                    2, "0") for t in time.localtime()[0:6]])
                with self.IRC.lock:
                    try:
                        self.IRC.connection.send("%(line)s\n" % vars())
                    except socket.error:
                        try:
                            self.IRC.connection.shutdown(0)
                        except:
                            pass
                        raise

                    ### Modify line if it contains a password so that the password is not logged or sent to any potentially untrustworthy addons
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

                        chanmatch = re.findall("([%s]?)([%s].+)"%(re.escape(self.IRC.supports.get("PREFIX", ("ohv", "@%+"))[1]), re.escape(self.IRC.supports.get("CHANTYPES", "#"))), target)
                        if chanmatch:
                            targetprefix, channame = chanmatch[0]
                            target = self.IRC.channel(channame)
                            if target.name != channame:
                                ### Target channel name has changed
                                target.name = channame
                        elif len(target) and target[0] != "$" and cmd != "NICK":
                            targetprefix = ""
                            target = self.IRC.user(target)

                        ctcp = re.findall("^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$",
                                          extinfo)
                        if ctcp:
                            (ctcptype, ext) = ctcp[0]
                            if ctcptype.upper() == "ACTION":
                                if type(target) == Channel:
                                    self.IRC.event("onSendChanAction", self.IRC.addons+target.addons, origin=origin, channel=target, targetprefix=targetprefix, action=ext)
                                elif type(target) == User:
                                    self.IRC.event("onSendPrivAction", self.IRC.addons, origin=origin, user=target, action=ext)
                            else:
                                if type(target) == Channel:
                                    self.IRC.event("onSendChanCTCP", self.IRC.addons+target.addons, origin=origin, channel=target, targetprefix=targetprefix, ctcptype=ctcptype, params=ext)
                                elif type(target) == User:
                                    self.IRC.event("onSendPrivCTCP", self.IRC.addons, origin=origin, user=target, ctcptype=ctcptype, params=ext)
                        else:
                            if type(target) == Channel:
                                self.IRC.event("onSendChanMsg", self.IRC.addons+target.addons, origin=origin, channel=target, targetprefix=targetprefix, msg=extinfo)
                            elif type(target) == User:
                                self.IRC.event("onSendPrivMsg", self.IRC.addons, origin=origin, user=target, msg=extinfo)

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
                    self.IRC.event("onSend", self.IRC.addons, origin=origin, line=line, cmd=cmd, target=target, params=params, extinfo=extinfo)
                self.IRC.logwrite(">>> %(line)s" % vars())
                if cmd.upper() == "QUIT":
                    self.IRC.quitexpected = True
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
                    time.sleep(max(timestamps[-1] +
                                   self.throttle-time.time(), 0))
        except:
            self.IRC.connection.send("QUIT :%s\n" %
                                     traceback.format_exc().rstrip().split("\n")[-1])
            self.IRC.connection.close()
            self.IRC.connection.shutdown(0)


class Pinger(Thread):
    def __init__(self, connection, lock=None):
        self.connection = connection
        self.lock = lock
        self.daemon = True
        Thread.__init__(self)

    def run(self):
        pass
