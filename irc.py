#!/usr/bin/python
from threading import Thread, Condition, Lock, currentThread
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
from collections import deque
import iqueue as Queue


class InvalidName(BaseException):
    pass


class InvalidPrefix(BaseException):
    pass


class InvalidCharacter(BaseException):
    pass


class ConnectionTimedOut(BaseException):
    pass


class ConnectionClosed(BaseException):
    pass


class RequestTimedOut(BaseException):
    pass


class NotConnected(BaseException):
    pass


class BannedFromChannel(BaseException):
    pass


class RedirectedJoin(BaseException):
    pass


class ChannelFull(BaseException):
    pass


class InviteOnly(BaseException):
    pass


class NotOnChannel(BaseException):
    pass


class NoSuchChannel(BaseException):
    pass


class BadChannelKey(BaseException):
    pass


class BadChannelMask(BaseException):
    pass


class TooManyChannels(BaseException):
    pass


class Unavailable(BaseException):
    pass


class Cbaned(BaseException):
    pass


class ActionAlreadyRequested(BaseException):
    pass


class OpersOnly(BaseException):
    pass


class OperCreateOnly(BaseException):
    pass


class SSLOnly(BaseException):
    pass


class AlreadyJoined(BaseException):
    pass


class AlreadyConnected(BaseException):
    pass


class RegistrationRequired(BaseException):
    pass


class RejoinDelay(BaseException):
    pass

_rfc1459casemapping = string.maketrans(string.ascii_uppercase + r'\[]~',
                                       string.ascii_lowercase + r'|{}^')

# The IRC RFC does not permit the first character in a nickname to be a
# numeral. However, this is not always adhered to.
_nickmatch = r"^[A-Za-z0-9\-\^\`\\\|\_\{\}\[\]]+$"

_intmatch = r"^\d+$"
_chanmatch = r"^[%%s][^%s\s\n]*$" % re.escape("\x07,")
_targchanmatch = r"^([%%s]?)([%%s][^%s\s\n]*)$" % re.escape("\x07,")
_usermatch = r"^[A-Za-z0-9\-\^\`\\\|\_\{\}\[\]]+$"
_realnamematch = r"^[^\n]*$"
_ircrecvmatch = r"^:(.+?)(?:!(.+?)@(.+?))?\s+(.+?)(?:\s+(.+?)(?:\s+(.+?))??)??(?:\s+:(.*))?$"
_ircsendmatch = r"^(.+?)(?:\s+(.+?)(?:\s+(.+?))??)??(?:\s+:(.*))?$"
_ctcpmatch = "^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$"
_prefixmatch = r"\((.*)\)(.*)"

_privmodeeventnames = dict(q=("Owner", "Deowner"), a=("Admin", "Deadmin"), o=(
    "Op", "Deop"), h=("Halfop", "Dehalfop"), v=("Voice", "Devoice"))
_maskmodeeventnames = dict(b=("Ban", "Unban"), e=(
    "BanExcept", "UnbanExcept"), I=("Invite", "Uninvite"))

exceptcodes = {489: SSLOnly, 384: Cbaned, 403: NoSuchChannel, 405: TooManyChannels, 442: NotOnChannel, 470: RedirectedJoin, 471: ChannelFull, 473: InviteOnly, 474:
               BannedFromChannel, 475: BadChannelKey, 476: BadChannelMask, 520: OpersOnly, 437: Unavailable, 477: RegistrationRequired, 495: RejoinDelay, 530: OperCreateOnly}


def timestamp():
    t = time.time()
    ms = 1000 * t % 1000
    ymdhms = time.localtime(t)
    tz = time.altzone if ymdhms.tm_isdst else time.timezone
    sgn = "-" if tz >= 0 else "+"
    return "%04d-%02d-%02d %02d:%02d:%02d.%03d%s%02d:%02d" % (ymdhms[:6] + (1000 * t % 1000, sgn, abs(tz) / 3600, abs(tz) / 60 % 60))


class Connection(object):

    def __init__(self, server, nick="ircbot", username="python", realname="Python IRC Library", passwd=None, port=None, ipv6=False, ssl=False, autoreconnect=True, log=sys.stderr, timeout=300, retrysleep=5, maxretries=15, onlogin=None):
        self.__name__ = "pyIRC"
        self.__version__ = "1.2"
        self.__author__ = "Brian Sherson"
        self.__date__ = "December 28, 2013"

        if port == None:
            self.port = 6667 if not ssl else 6697
        else:
            self.port = port

        if type(nick) in (str, unicode):
            if re.match(_nickmatch, nick):
                self.nick = [nick]
            else:
                raise InvalidCharacter
        elif type(nick) in (list, tuple):
            if all([re.match(_nickmatch, n) for n in nick]):
                self.nick = nick
            else:
                raise InvalidCharacter

        if re.match(_realnamematch, realname):
            self.realname = realname
        else:
            raise InvalidCharacter

        if re.match(_usermatch, username):
            self.username = username
        else:
            raise InvalidCharacter

        if passwd == None or "\n" not in passwd:
            self.passwd = passwd
        else:
            raise InvalidCharacter

        self.server = server
        self.ssl = ssl
        self.ipv6 = ipv6

        self.autoreconnect = autoreconnect
        self.maxretries = maxretries
        self.timeout = timeout
        self.retrysleep = retrysleep

        self._quitexpected = False
        self.log = log

        self.addons = []
        self.trusted = []  # To be implemented later

        self.lock = Lock()

        self._loglock = Lock()
        self._outlock = Lock()
        self._sendline = Condition(self._outlock)
        self._outgoing = deque()

        self._sendhandlerthread = None
        self._recvhandlerthread = None

        # Initialize IRC environment variables
        self._init()

    def _init(self):
        self._connected = False
        self._registered = False
        self._connection = None
        self.trynick = 0

        self.identity = None
        self.users = []
        self.channels = []

        self.motdgreet = None
        self.motd = None
        self.motdend = None

        self.serv = None
        self.welcome = None
        self.hostinfo = None
        self.servcreated = None
        self.servinfo = None
        self.serv005 = None
        self.supports = {}
        self.throttledata = []
        self.throttled = False

    @property
    def connected(self):
        return self._connected

    @property
    def registered(self):
        return self._registered

    def logwrite(self, *lines):
        with self._loglock:
            ts = timestamp()
            for line in lines:
                print >>self.log, "%s %s" % (ts, line)
            self.log.flush()

    def logopen(self, filename):
        with self._loglock:
            ts = timestamp()
            newlog = open(filename, "a")
            if type(self.log) == file and not self.log.closed:
                if self.log not in (sys.stdout, sys.stderr):
                    print >>self.log, "%s ### Log file closed" % (ts)
                    self.log.close()
            self.log = newlog
            print >>self.log, "%s ### Log file opened" % (ts)
            self.log.flush()

    def _event(self, method, modlist, exceptions=False, **params):
        # Used to call event handlers on all attached addons, when applicable.
        handled = []
        unhandled = []
        errors = []
        for k, addon in enumerate(modlist):
            if modlist.index(addon) < k:
                # Duplicate
                continue
            if method in dir(addon) and callable(getattr(addon, method)):
                try:
                    getattr(addon, method)(self, **params)
                except:
                    exc, excmsg, tb = sys.exc_info()
                    errors.append((addon, exc, excmsg, tb))

                    # Print to log AND stderr
                    self.logwrite(*["!!! Exception in addon %(addon)s" % vars()] + [
                                  "!!! %s" % line for line in traceback.format_exc().split("\n")])
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
            raise BaseException, "Addon already added."
        with self.lock:
            self._event("onAddonAdd", [addon], exceptions=True, **params)
            self.addons.append(addon)
            self.logwrite("*** Addon %s added." % repr(addon))
            if trusted:
                self.trusted.append(addon)

    def insertAddon(self, index, addon, trusted=False, **params):
        if addon in self.addons:
            raise BaseException, "Addon already added."
        with self.lock:
            self._event("onAddonAdd", [addon], exceptions=True, **params)
            self.addons.insert(index, addon)
            self.logwrite("*** Addon %s inserted into index %d." %
                          (repr(addon), index))
            if trusted:
                self.trusted.append(addon)

    def rmAddon(self, addon, **params):
        with self.lock:
            self.addons.remove(addon)
            self.logwrite("*** Addon %s removed." % repr(addon))
            self._event("onAddonRem", [addon], exceptions=True, **params)
            if addon in self.trusted:
                self.trusted.remove(addon)

    def connect(self):
        if self.isAlive():
            raise AlreadyConnected
        with self.lock:
            self._recvhandlerthread = Thread(target=self._recvhandler)
            self._sendhandlerthread = Thread(target=self._sendhandler)
            self._recvhandlerthread.start()
            self._sendhandlerthread.start()

    def _connect(self):
        with self.lock:
            if self._connected:
                raise AlreadyConnected
        server = self.server
        if self.ipv6 and ":" in server:
            server = "[%s]" % server
        port = self.port

        with self.lock:
            self.logwrite(
                "*** Attempting connection to %(server)s:%(port)s." % vars())
            self._event("onConnectAttempt", self.addons + reduce(
                lambda x, y: x + y, [chan.addons for chan in self.channels], []))
        try:
            if self.ssl:
                connection = socket.socket(
                    socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
                connection.settimeout(self.timeout)
                self._connection = ssl.wrap_socket(
                    connection, cert_reqs=ssl.CERT_NONE)
            else:
                self._connection = socket.socket(
                    socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
                self._connection.settimeout(self.timeout)
            self._connection.connect(
                (self.server, self.port, 0, 0) if self.ipv6 else (self.server, self.port))
        except socket.error:
            exc, excmsg, tb = sys.exc_info()
            with self.lock:
                self.logwrite(
                    "*** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars())
                self._event("onConnectFail", self.addons + reduce(
                    lambda x, y: x + y, [chan.addons for chan in self.channels], []), exc=exc, excmsg=excmsg, tb=tb)
            raise

        with self.lock:
            # Run onConnect on all addons to signal connection was established.
            self._event("onConnect", self.addons + reduce(
                lambda x, y: x + y, [chan.addons for chan in self.channels], []))
            self.logwrite(
                "*** Connection to %(server)s:%(port)s established." % vars())
            self._connected = True

    def _procrecvline(self, line):
        # If received PING, then just pong back transparently, bypassing
        # _outgoingthread.
        ping = re.findall("^PING :?(.*)$", line)
        if len(ping):
            with self.lock:
                self._connection.send("PONG :%s\n" % ping[0])
            return

        self.logwrite("<<< %s" % line)

        # Attempts to match against pattern ":src cmd target params :extinfo"
        matches = re.findall(_ircrecvmatch, line)

        # We have a match!
        if len(matches):
            parsed = (origin, username, host, cmd,
                      target, params, extinfo) = matches[0]
            unhandled = []

            if re.match(_intmatch, cmd):
                cmd = int(cmd)  # Code is a numerical response
            else:
                cmd = cmd.upper()

            with self.lock:
                if not self._registered:
                    if type(cmd) == int and cmd != 451 and target != "*":  # Registration complete!
                        self.identity = self.user(target)
                        self.serv = origin
                        self._event("onRegistered", self.addons + reduce(
                            lambda x, y: x + y, [chan.addons for chan in self.channels], []))
                        self._registered = True

                    elif cmd == 433 and target == "*":  # Server reports nick taken, so we need to try another.
                        self._trynick()
                    if not self._registered:  # Registration is not yet complete
                        return

                if username and host:
                    nickname = origin
                    origin = self.user(origin)
                    if origin.nick != nickname:
                        # Origin nickname has changed
                        origin.user = nickname
                    if origin.username != username:
                        # Origin username has changed
                        origin.username = username
                    if origin.host != host:
                        # Origin host has changed
                        origin.host = host

                chanmatch = re.findall(
                    _targchanmatch % (re.escape(self.supports.get("PREFIX", ("ohv", "@%+"))[1]), re.escape(self.supports.get("CHANTYPES", "#"))), target)
                if chanmatch:
                    targetprefix, channame = chanmatch[0]
                    target = self.channel(channame)
                    if target.name != channame:
                        # Target channel name has changed
                        target.name = channame
                elif re.match(_nickmatch, target) and cmd != "NICK":
                    targetprefix = ""
                    target = self.user(target)
                else:
                    targetprefix = ""

                data = dict(origin=origin, cmd=cmd, target=target,
                            targetprefix=targetprefix, params=params, extinfo=extinfo)

                # Major codeblock here! Track IRC state.
                # Send line to addons having onRecv method first
                self._event("onRecv", self.addons, line=line, **data)

                # Support for further addon events is taken care of here. Each invocation of self._event will return (handled, unhandled, exceptions),
                # where handled is the list of addons that have an event handler, and was executed without error, unhandled gives the list of addons
                # not having the event handler, and exeptions giving the list of addons having an event handler, but an exception occurred.
                # WARNING: When writing an addon, never, EVER attempt to aquire self.lock (IRC.lock from inside the method), or you will have a
                # deadlock.

                if cmd == 1:
                    (handled, unhandled, exceptions) = self._event("onWelcome", self.addons + reduce(
                        lambda x, y: x + y, [chan.addons for chan in self.channels], []), origin=origin, msg=extinfo)
                    self.welcome = extinfo  # Welcome message
                elif cmd == 2:
                    (handled, unhandled, exceptions) = self._event("onYourHost", self.addons + reduce(
                        lambda x, y: x + y, [chan.addons for chan in self.channels], []), origin=origin, msg=extinfo)
                    self.hostinfo = extinfo  # Your Host
                elif cmd == 3:
                    (handled, unhandled, exceptions) = self._event("onServerCreated", self.addons + reduce(
                        lambda x, y: x + y, [chan.addons for chan in self.channels], []), origin=origin, msg=extinfo)
                    self.servcreated = extinfo  # Server Created
                elif cmd == 4:
                    (handled, unhandled, exceptions) = self._event("onServInfo", self.addons + reduce(
                        lambda x, y: x + y, [chan.addons for chan in self.channels], []), origin=origin, servinfo=params)
                    self.servinfo = params  # What is this code?
                elif cmd == 5:  # Server Supports
                    support = dict(
                        re.findall("([A-Za-z0-9]+)(?:=(\\S*))?", params))
                    if support.has_key("CHANMODES"):
                        support["CHANMODES"] = support["CHANMODES"].split(",")
                    if support.has_key("PREFIX"):
                        matches = re.findall(_prefixmatch, support["PREFIX"])
                        if matches:
                            support["PREFIX"] = matches[0]
                        else:
                            del support[
                                "PREFIX"]  # Might as well delete the info if it doesn't match expected pattern
                    (handled, unhandled, exceptions) = self._event("onSupports", self.addons + reduce(
                        lambda x, y: x + y, [chan.addons for chan in self.channels], []), origin=origin, supports=support)
                    self.supports.update(support)
                    if "serv005" in dir(self) and type(self.serv005) == list:
                        self.serv005.append(params)
                    else:
                        self.serv005 = [params]
                elif cmd == 8:  # Snomask
                    snomask = params.lstrip("+")
                    (handled, unhandled, exceptions) = self._event("onSnoMask", self.addons + reduce(
                        lambda x, y: x + y, [chan.addons for chan in self.channels], []), origin=origin, snomask=snomask)
                    self.identity.snomask = snomask
                    if "s" not in self.identity.modes:
                        self.snomask = ""
                elif cmd == 221:  # User Modes
                    modes = (params if params else extinfo).lstrip("+")
                    (handled, unhandled, exceptions) = self._event("onUserModes", self.addons + reduce(
                        lambda x, y: x + y, [chan.addons for chan in self.channels], []), origin=origin, snomask=modes)
                    self.identity.modes = modes
                    if "s" not in self.identity.modes:
                        self.snomask = ""
                elif cmd == 251:  # Net Stats
                    (handled, unhandled, exceptions) = self._event(
                        "onNetStats", self.addons, origin=origin, netstats=extinfo)
                    self.netstats = extinfo
                elif cmd == 252:
                    opcount = int(params)
                    (handled, unhandled, exceptions) = self._event(
                        "onOpCount", self.addons, origin=origin, opcount=opcount)
                    self.opcount = opcount
                elif cmd == 254:
                    chancount = int(params)
                    (handled, unhandled, exceptions) = self._event(
                        "onChanCount", self.addons, origin=origin, chancount=chancount)
                    self.chancount = chancount

                elif cmd == 305:  # Returned from away status
                    (handled, unhandled, exceptions) = self._event(
                        "onReturn", self.addons, origin=origin, msg=extinfo)
                    self.identity.away = False

                elif cmd == 306:  # Entered away status
                    (handled, unhandled, exceptions) = self._event(
                        "onAway", self.addons, origin=origin, msg=extinfo)
                    self.identity.away = True

                elif cmd == 311:  # Start of WHOIS data
                    nickname, username, host, star = params.split()
                    user = self.user(nickname)
                    (handled, unhandled, exceptions) = self._event("onWhoisStart", self.addons, origin=origin,
                                                                   user=user, nickname=nickname, username=username, host=host, realname=extinfo)
                    user.nick = nickname
                    user.username = username
                    user.host = host

                elif cmd == 301:  # Away Message
                    user = self.user(params)
                    (handled, unhandled, exceptions) = self._event(
                        "onWhoisAway", self.addons, origin=origin, user=user, nickname=params, awaymsg=extinfo)
                    user.away = True
                    user.awaymsg = extinfo

                elif cmd == 303:  # ISON Reply
                    users = [self.user(user) for user in extinfo.split(" ")]
                    (handled, unhandled, exceptions) = self._event(
                        "onIsonReply", self.addons, origin=origin, isonusers=users)

                elif cmd == 307:  # Is a registered nick
                    (handled, unhandled, exceptions) = self._event("onWhoisRegisteredNick",
                                                                   self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                elif cmd == 378:  # Connecting From
                    (handled, unhandled, exceptions) = self._event("onWhoisConnectingFrom",
                                                                   self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                elif cmd == 319:  # Channels
                    (handled, unhandled, exceptions) = self._event("onWhoisChannels", self.addons,
                                                                   origin=origin, user=self.user(params), nickname=params, chanlist=extinfo.split(" "))
                elif cmd == 310:  # Availability
                    (handled, unhandled, exceptions) = self._event("onWhoisAvailability",
                                                                   self.addons, origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                elif cmd == 312:  # Server
                    nickname, server = params.split(" ")
                    user = self.user(nickname)
                    (handled, unhandled, exceptions) = self._event("onWhoisServer", self.addons,
                                                                   origin=origin, user=user, nickname=nickname, server=server, servername=extinfo)
                    user.server = server
                elif cmd == 313:  # IRC Op
                    user = self.user(params)
                    (handled, unhandled, exceptions) = self._event(
                        "onWhoisOp", self.addons, origin=origin, user=user, nickname=params, msg=extinfo)
                    user.ircop = True
                    user.ircopmsg = extinfo
                elif cmd == 317:  # Idle and Signon times
                    nickname, idletime, signontime = params.split(" ")
                    user = self.user(nickname)
                    (handled, unhandled, exceptions) = self._event("onWhoisTimes", self.addons, origin=origin,
                                                                   user=user, nickname=nickname, idletime=int(idletime), signontime=int(signontime), msg=extinfo)
                    user.idlesince = int(time.time()) - int(idletime)
                    user.signontime = int(signontime)
                elif cmd == 671:  # SSL
                    user = self.user(params)
                    (handled, unhandled, exceptions) = self._event(
                        "onWhoisSSL", self.addons, origin=origin, user=user, nickname=params, msg=extinfo)
                    user.ssl = True
                elif cmd == 379:  # User modes
                    (handled, unhandled, exceptions) = self._event("onWhoisModes", self.addons,
                                                                   origin=origin, user=self.user(params), nickname=params, msg=extinfo)
                elif cmd == 330:  # Logged in as
                    nickname, loggedinas = params.split(" ")
                    user = self.user(nickname)
                    (handled, unhandled, exceptions) = self._event("onWhoisLoggedInAs", self.addons,
                                                                   origin=origin, user=user, nickname=nickname, loggedinas=loggedinas, msg=extinfo)
                    user.loggedinas = loggedinas
                elif cmd == 318:  # End of WHOIS
                    (handled, unhandled, exceptions) = self._event("onWhoisEnd", self.addons,
                                                                   origin=origin, user=self.user(params), nickname=params, msg=extinfo)

                elif cmd == 321:  # Start LIST
                    (handled, unhandled, exceptions) = self._event(
                        "onListStart", self.addons, origin=origin, params=params, extinfo=extinfo)
                elif cmd == 322:  # LIST item
                    (chan, pop) = params.split(" ", 1)
                    (handled, unhandled, exceptions) = self._event("onListEntry", self.addons,
                                                                   origin=origin, channel=self.channel(chan), population=int(pop), extinfo=extinfo)
                elif cmd == 323:  # End of LIST
                    (handled, unhandled, exceptions) = self._event(
                        "onListEnd", self.addons, origin=origin, endmsg=extinfo)

                elif cmd == 324:  # Channel Modes
                    modeparams = params.split()
                    channame = modeparams.pop(0)
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    if channel.name != channame:
                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                    setmodes = modeparams.pop(0)
                    modedelta = []
                    for mode in setmodes:
                        if mode == "+":
                            continue
                        elif mode in self.supports["CHANMODES"][2]:
                            param = modeparams.pop(0)
                            modedelta.append(("+%s" % mode, param))
                        elif mode in self.supports["CHANMODES"][3]:
                            modedelta.append(("+%s" % mode, None))
                    (handled, unhandled, exceptions) = self._event(
                        "onChannelModes", self.addons + channel.addons, channel=channel, modedelta=modedelta)
                    for ((modeset, mode), param) in modedelta:
                        if mode in self.supports["CHANMODES"][2]:
                            channel.modes[mode] = param
                        elif mode in self.supports["CHANMODES"][3]:
                            channel.modes[mode] = True

                elif cmd == 329:  # Channel created
                    channame, created = params.split()
                    created = int(created)
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onChanCreated", self.addons + channel.addons, channel=channel, created=created)
                    channel.created = int(created)

                elif cmd == 332:  # Channel Topic
                    channame = params
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onTopic", self.addons + channel.addons, origin=origin, channel=channel, topic=extinfo)
                    channel.topic = extinfo

                elif cmd == 333:  # Channel Topic info
                    (channame, nick, dt) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onTopicInfo", self.addons +
                                                                   channel.addons, origin=origin, channel=channel, topicsetby=nick, topictime=int(dt))
                    channel.topicsetby = nick
                    channel.topictime = int(dt)

                elif cmd == 352:  # WHO reply
                    (channame, username, host, serv,
                     nick, flags) = params.split()
                    try:
                        (hops, realname) = extinfo.split(" ", 1)
                    except ValueError:
                        hops = extinfo
                        realname = None

                    chantypes = self.supports.get("CHANTYPES", "&#+!")
                    if re.match(_chanmatch % re.escape(chantypes), channame):
                        channel = self.channel(channame)
                    else:
                        channel = None

                    user = self.user(nick)

                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onWhoEntry", self.addons + channel.addons, origin=origin, channel=channel,
                                                                   user=user, channame=channame, username=username, host=host, serv=serv, nick=nick, flags=flags, hops=int(hops), realname=realname)
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
                    chantypes = self.supports.get("CHANTYPES", "&#+!")
                    if re.match(_chanmatch % re.escape(chantypes), params):
                        channel = self.channel(params)
                        (handled, unhandled, exceptions) = self._event(
                            "onWhoEnd", self.addons + channel.addons, origin=origin, param=params, endmsg=extinfo)
                    else:
                        (handled, unhandled, exceptions) = self._event(
                            "onWhoEnd", self.addons, origin=origin, param=params, endmsg=extinfo)

                elif cmd == 353:  # NAMES reply
                    (flag, channame) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)

                    if self.supports.has_key("PREFIX"):
                        names = re.findall(
                            r"([%s]*)([^@!\s]+)(?:!(\S+)@(\S+))?" %
                            re.escape(self.supports["PREFIX"][1]), extinfo)
                    else:
                        names = re.findall(
                            r"()([^@!\s]+)(?:!(\S+)@(\S+))?", extinfo)
                                           # Still put it into tuple form for
                                           # compatibility in the next
                                           # structure
                    (handled, unhandled, exceptions) = self._event("onNames", self.addons + channel.addons,
                                                                   origin=origin, channel=channel, flag=flag, channame=channame, nameslist=names)

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
                            if self.supports.has_key("PREFIX"):
                                for symb in symbs:
                                    mode = self.supports["PREFIX"][0][
                                        self.supports["PREFIX"][1].index(symb)]
                                    if not channel.modes.has_key(mode):
                                        channel.modes[mode] = [user]
                                    elif user not in channel.modes[mode]:
                                        channel.modes[mode].append(user)

                elif cmd == 366:  # End of NAMES reply
                    channel = self.channel(params)
                    (handled, unhandled, exceptions) = self._event("onNamesEnd", self.addons +
                                                                   channel.addons, origin=origin, channel=channel, channame=params, endmsg=extinfo)

                elif cmd == 372:  # MOTD line
                    (handled, unhandled, exceptions) = self._event(
                        "onMOTDLine", self.addons, origin=origin, motdline=extinfo)
                    self.motd.append(extinfo)
                elif cmd == 375:  # Begin MOTD
                    (handled, unhandled, exceptions) = self._event(
                        "onMOTDStart", self.addons, origin=origin, motdgreet=extinfo)
                    self.motdgreet = extinfo
                    self.motd = []
                elif cmd == 376:
                    (handled, unhandled, exceptions) = self._event(
                        "onMOTDEnd", self.addons, origin=origin, motdend=extinfo)
                    self.motdend = extinfo  # End of MOTD

                elif cmd == 386 and "q" in self.supports["PREFIX"][0]:  # Channel Owner (Unreal)
                    (channame, owner) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    if channel.name != channame:
                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                    user = self.user(owner)
                    if user.nick != owner:
                        user.nick = owner
                    if channel.modes.has_key("q"):
                        if user not in channel.modes["q"]:
                            channel.modes["q"].append(user)
                    else:
                        channel.modes["q"] = [user]

                elif cmd == 388 and "a" in self.supports["PREFIX"][0]:  # Channel Admin (Unreal)
                    (channame, admin) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    if channel.name != channame:
                        channel.name = channame  # Server seems to have changed the idea of the case of the channel name
                    user = self.user(admin)
                    if user.nick != admin:
                        user.nick = admin
                    if channel.modes.has_key("a"):
                        if user not in channel.modes["a"]:
                            channel.modes["a"].append(user)
                    else:
                        channel.modes["a"] = [user]

                elif cmd == "NICK":
                    newnick = extinfo if len(extinfo) else target

                    addons = reduce(
                        lambda x, y: x + y, [chan.addons for chan in origin.channels], [])
                    self._event("onRecv", addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onNickChange", self.addons + addons, user=origin, newnick=newnick)
                    if origin == self.identity:
                        (handled, unhandled, exceptions) = self._event(
                            "onMeNickChange", self.addons + addons, newnick=newnick)

                    for u in self.users:
                        if u.nick.lower() == newnick.lower():
                            self.users.remove(
                                u)  # Nick collision, safe to assume this orphaned user is offline, so we shall remove the old instance.
                            for channel in self.channels:
                                # If for some odd reason, the old user still
                                # appears common channels, then we will remove
                                # the user anyway.
                                if u in channel.users:
                                    channel.users.remove(u)
                    origin.nick = newnick

                elif cmd == "JOIN":
                    channel = target if type(
                        target) == Channel else self.channel(extinfo)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onJoin", self.addons + channel.addons, user=origin, channel=channel)

                    if origin == self.identity:  # This means the bot is entering the room,
                        # and will reset all the channel data, on the assumption that such data may have changed.
                        # Also, the bot must request modes
                        with channel._joining:
                            if channel._joinrequested:
                                channel._joinreply = cmd
                                channel._joining.notify()
                        channel.topic = ""
                        channel.topicmod = ""
                        channel.modes = {}
                        channel.users = []
                        self._event(
                            "onMeJoin", self.addons + channel.addons, channel=channel)
                        self.raw("MODE %s" % channel.name)
                        self.raw("WHO %s" % channel.name)
                        if "CHANMODES" in self.supports.keys():
                            self.raw(
                                "MODE %s :%s" % (channel.name, self.supports["CHANMODES"][0]))

                    if channel not in origin.channels:
                        origin.channels.append(channel)
                    if origin not in channel.users:
                        channel.users.append(origin)

                elif cmd == "KICK":
                    kicked = self.user(params)
                    if kicked.nick != params:
                        kicked.nick = params

                    self._event("onRecv", target.addons, line=line, **data)
                    if origin == self.identity:
                        self._event(
                            "onMeKick", self.addons + target.addons, channel=target, kicked=kicked, kickmsg=extinfo)
                    if kicked == self.identity:
                        self._event("onMeKicked", self.addons + target.addons,
                                    kicker=origin, channel=target, kickmsg=extinfo)
                    (handled, unhandled, exceptions) = self._event("onKick", self.addons +
                                                                   target.addons, kicker=origin, channel=target, kicked=kicked, kickmsg=extinfo)

                    if target in kicked.channels:
                        kicked.channels.remove(target)
                    if kicked in target.users:
                        target.users.remove(kicked)
                    if self.supports.has_key("PREFIX"):
                        for mode in self.supports["PREFIX"][0]:
                            if target.modes.has_key(mode) and kicked in target.modes[mode]:
                                target.modes[mode].remove(kicked)

                elif cmd == "PART":
                    try:
                        self._event("onRecv", target.addons, line=line, **data)
                        if origin == self.identity:
                            with target	._parting:
                                if target._partrequested:
                                    target._partreply = cmd
                                    target._parting.notify()
                            self._event(
                                "onMePart", self.addons + target.addons, channel=target, partmsg=extinfo)
                        (handled, unhandled, exceptions) = self._event(
                            "onPart", self.addons + target.addons, user=origin, channel=target, partmsg=extinfo)

                        if target in origin.channels:
                            origin.channels.remove(target)
                        if origin in target.users:
                            target.users.remove(origin)
                        if self.supports.has_key("PREFIX"):
                            for mode in self.supports["PREFIX"][0]:
                                if target.modes.has_key(mode) and origin in target.modes[mode]:
                                    target.modes[mode].remove(origin)
                    except:
                        print target
                        raise
                elif cmd == "QUIT":
                    channels = list(origin.channels)
                    addons = reduce(
                        lambda x, y: x + y, [chan.addons for chan in origin.channels], [])
                    self._event("onRecv", addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onQuit", self.addons + addons, user=origin, quitmsg=extinfo)
                    for channel in origin.channels:
                        with channel.lock:
                            if origin in channel.users:
                                channel.users.remove(origin)
                            if self.supports.has_key("PREFIX"):
                                for mode in self.supports["PREFIX"][0]:
                                    if channel.modes.has_key(mode) and origin in channel.modes[mode]:
                                        channel.modes[mode].remove(origin)
                    origin.channels = []

                elif cmd == "MODE":
                    if type(target) == Channel:
                        self._event("onRecv", target.addons, line=line, **data)
                        modedelta = []
                        modeparams = params.split()
                        setmodes = modeparams.pop(0)
                        modeset = "+"
                        for mode in setmodes:
                            if mode in "+-":
                                modeset = mode
                            else:
                                if mode in self.supports["CHANMODES"][0] + self.supports["CHANMODES"][1]:
                                    param = modeparams.pop(0)
                                    modedelta.append(
                                        ("%s%s" % (modeset, mode), param))
                                    if mode in _maskmodeeventnames.keys():
                                        if modeset == "+":
                                            eventname = _maskmodeeventnames[
                                                mode][0]
                                        if modeset == "-":
                                            eventname = _maskmodeeventnames[
                                                mode][1]
                                        matchesbot = glob.fnmatch.fnmatch(
                                            "%s!%s@%s".lower() % (self.identity.nick, self.identity.username, self.identity.host), param.lower())
                                        self._event(
                                            "on%s" % eventname, self.addons + target.addons, user=origin, channel=target, banmask=param)
                                        if matchesbot:
                                            self._event(
                                                "onMe%s" % eventname, self.addons + target.addons, user=origin, channel=target, banmask=param)
                                elif mode in self.supports["CHANMODES"][2]:
                                    if modeset == "+":
                                        param = modeparams.pop(0)
                                        modedelta.append(
                                            ("%s%s" % (modeset, mode), param))
                                    else:
                                        modedelta.append(
                                            ("%s%s" % (modeset, mode), None))
                                elif mode in self.supports["CHANMODES"][3]:
                                    modedelta.append(
                                        ("%s%s" % (modeset, mode), None))
                                elif self.supports.has_key("PREFIX") and mode in self.supports["PREFIX"][0]:
                                    modenick = modeparams.pop(0)
                                    modeuser = self.user(modenick)
                                    if mode in _privmodeeventnames.keys():
                                        if modeset == "+":
                                            eventname = _privmodeeventnames[
                                                mode][0]
                                        if modeset == "-":
                                            eventname = _privmodeeventnames[
                                                mode][1]
                                        self._event(
                                            "on%s" % eventname, self.addons + target.addons, user=origin, channel=target, modeuser=modeuser)
                                        if modeuser == self.identity:
                                            self._event(
                                                "onMe%s" % eventname, self.addons + target.addons, user=origin, channel=target)
                                    modedelta.append(
                                        ("%s%s" % (modeset, mode), modeuser))
                        (handled, unhandled, exceptions) = self._event(
                            "onChanModeSet", self.addons + target.addons, user=origin, channel=target, modedelta=modedelta)
                        with target.lock:
                            for ((modeset, mode), param) in modedelta:
                                if mode in self.supports["CHANMODES"][0]:
                                    if modeset == "+":
                                        if target.modes.has_key(mode):
                                            if param.lower() not in [mask.lower() for (mask, setby, settime) in target.modes[mode]]:
                                                target.modes[mode].append(
                                                    (param, origin, int(time.time())))
                                        else:
                                            target.modes[mode] = [
                                                (param, origin, int(time.time()))]
                                    else:
                                        if mode in target.modes.keys():
                                            if mode == "b":  # Inspircd mode is case insentive when unsetting the mode
                                                masks = [
                                                    mask.lower() for (mask, setby, settime) in target.modes[mode]]
                                                if param.lower() in masks:
                                                    index = masks.index(
                                                        param.lower())
                                                    # print "Index: %d"%index
                                                    del target.modes[
                                                        mode][index]
                                            else:
                                                masks = [
                                                    mask for (mask, setby, settime) in target.modes[mode]]
                                                if param in masks:
                                                    index = masks.index(param)
                                                    del target.modes[
                                                        mode][index]
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
                                elif self.supports.has_key("PREFIX") and mode in self.supports["PREFIX"][0]:
                                    if modeset == "+":
                                        if target.modes.has_key(mode) and param not in target.modes[mode]:
                                            target.modes[mode].append(param)
                                        if not target.modes.has_key(mode):
                                            target.modes[mode] = [param]
                                    elif target.modes.has_key(mode) and param in target.modes[mode]:
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
                                            target.snomask = target.snomask.replace(
                                                snomode, "")
                            if modeset == "-":
                                if mode in target.modes:
                                    target.modes = target.modes.replace(
                                        mode, "")
                                if mode == "s":
                                    target.snomask = ""

                elif cmd == "TOPIC":
                    self._event("onRecv", target.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onTopicSet", self.addons + target.addons, user=origin, channel=target, topic=extinfo)

                    with target.lock:
                        target.topic = extinfo
                        target.topicsetby = origin
                        target.topictime = int(time.time())

                elif cmd == "INVITE":
                    channel = self.channel(extinfo if extinfo else params)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onInvite", self.addons + channel.addons, user=origin, channel=channel)

                elif cmd == "PRIVMSG":
                    if type(target) == Channel:
                        self._event("onRecv", target.addons, line=line, **data)

                    # CTCP handling
                    ctcp = re.findall(_ctcpmatch, extinfo)
                    if ctcp:
                        (ctcptype, ext) = ctcp[0]
                        if ctcptype.upper() == "ACTION":
                            if type(target) == Channel:
                                (handled, unhandled, exceptions) = self._event(
                                    "onChanAction", self.addons + target.addons, user=origin, channel=target, targetprefix=targetprefix, action=ext)
                            elif target == self.identity:
                                (handled, unhandled, exceptions) = self._event(
                                    "onPrivAction", self.addons, user=origin, action=ext)
                        else:
                            if type(target) == Channel:
                                (handled, unhandled, exceptions) = self._event("onChanCTCP", self.addons + target.addons,
                                                                               user=origin, channel=target, targetprefix=targetprefix, ctcptype=ctcptype, params=ext)
                            elif target == self.identity:
                                (handled, unhandled, exceptions) = self._event(
                                    "onPrivCTCP", self.addons, user=origin, ctcptype=ctcptype, params=ext)
                        if ctcptype.upper() == "VERSION":
                            origin.ctcpreply("VERSION", self.ctcpversion())
                        if ctcptype.upper() == "TIME":
                            tformat = time.ctime()
                            tz = time.tzname[0]
                            origin.ctcpreply(
                                "TIME", "%(tformat)s %(tz)s" % vars())
                        if ctcptype.upper() == "PING":
                            origin.ctcpreply("PING", "%(ext)s" % vars())
                        if ctcptype.upper() == "FINGER":
                            origin.ctcpreply("FINGER", "%(ext)s" % vars())
                    else:
                        if type(target) == Channel:
                            (handled, unhandled, exceptions) = self._event(
                                "onChanMsg", self.addons + target.addons, user=origin, channel=target, targetprefix=targetprefix, msg=extinfo)
                        elif target == self.identity:
                            (handled, unhandled, exceptions) = self._event(
                                "onPrivMsg", self.addons, user=origin, msg=extinfo)

                elif cmd == "NOTICE":
                    if type(target) == Channel:
                        self._event("onRecv", target.addons, line=line, **data)

                    # CTCP handling
                    ctcp = re.findall(_ctcpmatch, extinfo)
                    if ctcp and target == self.identity:
                        (ctcptype, ext) = ctcp[0]
                        (handled, unhandled, exceptions) = self._event(
                            "onCTCPReply", self.addons, origin=origin, ctcptype=ctcptype, params=ext)
                    else:
                        if type(target) == Channel:
                            (handled, unhandled, exceptions) = self._event(
                                "onChanNotice", self.addons + target.addons, origin=origin, channel=target, targetprefix=targetprefix, msg=extinfo)
                        elif target == self.identity:
                            (handled, unhandled, exceptions) = self._event(
                                "onPrivNotice", self.addons, origin=origin, msg=extinfo)

                elif cmd == 367:  # Channel Ban list
                    (channame, mask, setby, settime) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onBanListEntry", self.addons + channel.addons,
                                                                   origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                    if "b" in channel.modes.keys():
                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["b"]]:
                            channel.modes["b"].append(
                                (mask, setby, int(settime)))
                    else:
                        channel.modes["b"] = [(mask, setby, int(settime))]
                elif cmd == 368:
                    channel = self.channel(params)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onBanListEnd", self.addons + channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                elif cmd == 346:  # Channel Invite list
                    (channame, mask, setby, settime) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onInviteListEntry", self.addons +
                                                                   channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                    if "I" in channel.modes.keys():
                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["I"]]:
                            channel.modes["I"].append(
                                (mask, setby, int(settime)))
                    else:
                        channel.modes["I"] = [(mask, setby, int(settime))]
                elif cmd == 347:
                    channel = self.channel(params)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onInviteListEnd", self.addons + channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                elif cmd == 348:  # Channel Ban Exception list
                    (channame, mask, setby, settime) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onBanExceptListEntry", self.addons +
                                                                   channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                    if "e" in channel.modes.keys():
                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["e"]]:
                            channel.modes["e"].append(
                                (mask, setby, int(settime)))
                    else:
                        channel.modes["e"] = [(mask, setby, int(settime))]
                elif cmd == 349:
                    channel = self.channel(params)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onBanExceptListEnd",
                                                                   self.addons + channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                elif cmd == 910:  # Channel Access List
                    (channame, mask, setby, settime) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onAccessListEntry", self.addons +
                                                                   channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                    if "w" in channel.modes.keys():
                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["b"]]:
                            channel.modes["w"].append(
                                (mask, setby, int(settime)))
                    else:
                        channel.modes["w"] = [(mask, setby, int(settime))]
                elif cmd == 911:
                    channel = self.channel(params)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onAccessListEnd", self.addons + channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                elif cmd == 941:  # Spam Filter list
                    (channame, mask, setby, settime) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onSpamfilterListEntry", self.addons +
                                                                   channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                    if "g" in channel.modes.keys():
                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["g"]]:
                            channel.modes["g"].append(
                                (mask, setby, int(settime)))
                    else:
                        channel.modes["g"] = [(mask, setby, int(settime))]
                elif cmd == 940:
                    channel = self.channel(params)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onSpamfilterListEnd",
                                                                   self.addons + channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                elif cmd == 954:  # Channel exemptchanops list
                    (channame, mask, setby, settime) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onExemptChanOpsListEntry", self.addons +
                                                                   channel.addons, origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime))
                    if "X" in channel.modes.keys():
                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["X"]]:
                            channel.modes["X"].append(
                                (mask, setby, int(settime)))
                    else:
                        channel.modes["X"] = [(mask, setby, int(settime))]
                elif cmd == 953:
                    channel = self.channel(params)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onExemptChanOpsListEnd",
                                                                   self.addons + channel.addons, origin=origin, channel=channel, endmsg=extinfo)

                elif cmd == 728:  # Channel quiet list
                    (channame, modechar, mask, setby, settime) = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event("onQuietListEntry", self.addons + channel.addons,
                                                                   origin=origin, channel=channel, modechar=modechar, mask=mask, setby=setby, settime=int(settime))
                    if "q" in channel.modes.keys():
                        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["q"]]:
                            channel.modes["q"].append(
                                (mask, setby, int(settime)))
                    else:
                        channel.modes["q"] = [(mask, setby, int(settime))]
                elif cmd == 729:
                    channame, modechar = params.split()
                    channel = self.channel(channame)
                    self._event("onRecv", channel.addons, line=line, **data)
                    (handled, unhandled, exceptions) = self._event(
                        "onQuietListEnd", self.addons + channel.addons, channel=channel, endmsg=extinfo)

                elif cmd in (495, 384, 385, 386, 468, 470, 366, 315, 482, 484, 953, 368, 482, 349, 940, 911, 489, 490, 492, 520, 530):  # Channels which appear in params
                    for param in params.split():
                        if len(param) and param[0] in self.supports["CHANTYPES"]:
                            channel = self.channel(param)
                            self._event(
                                "onRecv", channel.addons, line=line, **data)

                elif type(cmd) == int:
                    (handled, unhandled, exceptions) = self._event("on%03d" %
                                                                   cmd, self.addons, line=line, origin=origin, target=target, params=params, extinfo=extinfo)
                else:
                    (handled, unhandled, exceptions) = self._event("on%s" %
                                                                   cmd, self.addons, line=line, origin=origin, cmd=cmd, target=target, params=params, extinfo=extinfo)

                if cmd in (384, 403, 405, 471, 473, 474, 475, 476, 520, 477, 489, 495):  # Channel Join denied
                    try:
                        channel = self.channel(params)
                    except InvalidName:
                        pass
                    else:
                        with channel._joining:
                            if channel._joinrequested:
                                channel._joinreply = (cmd, extinfo)
                                channel._joining.notify()

                elif cmd == 470:  # Channel Join denied due to redirect
                    channelname, redirect = params.split()
                    try:
                        channel = self.channel(channelname)
                    except InvalidName:
                        pass
                    else:
                        with channel._joining:
                            if channel._joinrequested:
                                channel._joinreply = (
                                    cmd, "%s (%s)" % (extinfo, redirect))
                                channel._joining.notify()

                # Handle events that were not handled.
                self._event("onUnhandled", unhandled, line=line, origin=origin,
                            cmd=cmd, target=target, params=params, extinfo=extinfo)

    def _trynick(self):
        (q, s) = divmod(self.trynick, len(self.nick))
        nick = self.nick[s]
        if q > 0:
            nick = "%s%d" % (nick, q)
        self._send("NICK %s" % nick)
        self.trynick += 1

    def _recvhandler(self):
        # Enforce that this function must only be run from within
        # self._sendhandlerthread.
        if currentThread() != self._recvhandlerthread:
            raise RuntimeError, "This function is designed to run in its own thread."
        server = self.server
        if self.ipv6 and ":" in server:
            server = "[%s]" % server
        port = self.port

        try:
            with self.lock:
                self._event("onSessionOpen", self.addons + reduce(
                    lambda x, y: x + y, [chan.addons for chan in self.channels], []))

            self.logwrite("### Log session started")
            while True:  # Autoreconnect loop
                attempt = 1
                while True:  # Autoretry loop
                    try:
                        self._connect()
                        break
                    except socket.error:
                        if self._quitexpected:
                            sys.exit()
                        if attempt < self.maxretries or self.maxretries < 0:
                            if self.retrysleep > 0:
                                time.sleep(self.retrysleep)
                            if self._quitexpected:
                                sys.exit()
                            attempt += 1
                        else:
                            self.logwrite(
                                "*** Maximum number of attempts reached. Giving up. (%(server)s:%(port)s)" % vars())
                            sys.exit()

                # Connection succeeded
                try:
                    with self._sendline:
                        self._sendline.notify()

                    # Attempt initial registration.
                    nick = self.nick[0]
                    if self.passwd:
                        self._send("PASS %s" % self.passwd)
                    self._trynick()
                    self._send("USER %s * * :%s" %
                               (self.username.split("\n")[0].rstrip(), self.realname.split("\n")[0].rstrip()))

                    # Initialize buffers
                    linebuf = []
                    readbuf = ""

                    while True:  # Main loop of IRC connection.
                        while len(linebuf) == 0:  # Need Moar Data
                            read = self._connection.recv(512)

                            # If read was empty, connection is terminated.
                            if read == "":
                                sys.exit()

                            # If read was successful, parse away!
                            readbuf += read
                            lastlf = readbuf.rfind("\n")
                            if lastlf >= 0:
                                linebuf.extend(
                                    string.split(readbuf[0:lastlf], "\n"))
                                readbuf = readbuf[lastlf + 1:]

                        line = string.rstrip(linebuf.pop(0))
                        self._procrecvline(line)

                except SystemExit:  # Connection lost normally.
                    pass

                except socket.error:  # Connection lost due to either ping timeout or connection reset by peer. Not a fatal error.
                    exc, excmsg, tb = sys.exc_info()
                    with self.lock:
                        self.logwrite(
                            "*** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars())
                        self._event("onConnectFail", self.addons + reduce(
                            lambda x, y: x + y, [chan.addons for chan in self.channels], []), exc=exc, excmsg=excmsg, tb=tb)

                except:  # Unknown exception, treated as FATAL. Try to quit IRC and terminate thread with exception.
                    # Quit with a (hopefully) useful quit message, or die
                    # trying.
                    self._quitexpected = True
                    try:
                        self.quit(
                            "%s" % traceback.format_exc().rstrip().split("\n")[-1])
                    except:
                        pass
                    raise

                finally:  # Post-connection operations after connection is lost, and must be executed, even if exception occurred.
                    with self._sendline:
                        self._outgoing.clear()
                        self._sendline.notify()
                    with self.lock:
                        (handled, unhandled, exceptions) = self._event("onDisconnect", self.addons + reduce(
                            lambda x, y: x + y, [chan.addons for chan in self.channels], []), expected=self._quitexpected)
                        self._init()

                    # Notify _outgoingthread that the connection has been
                    # terminated.
                    with self._sendline:
                        self._sendline.notify()

                    try:
                        self._connection.close()
                    except:
                        pass

                    self.logwrite("*** Connection Terminated.")

                if self._quitexpected or not self.autoreconnect:
                    self._quitexpected = False
                    sys.exit()

        except SystemExit:
            pass

        except:  # Print exception to log file
            self.logwrite(*["!!! FATAL Exception"] + ["!!! %s" %
                          line for line in traceback.format_exc().split("\n")])
            print >>sys.stderr, "FATAL Exception"
            print >>sys.stderr, traceback.format_exc()
            sys.exit()

        finally:
            self.logwrite("### Log session ended")
            (handled, unhandled, exceptions) = self._event("onSessionClose", self.addons +
                                                           reduce(lambda x, y: x + y, [chan.addons for chan in self.channels], []))

            # Tell _sendhandler to quit
            with self._sendline:
                self._outgoing.append("quit")
                self._sendline.notify()

    def _send(self, line, origin=None):
        if "\r" in line or "\n" in line:
            raise InvalidCharacter
        cmd = line.split(" ")[0].upper()

        T = time.time()
        if cmd == "PRIVMSG":
            # Hard-coding a throttling mechanism for PRIVMSGs only here. Will later build support for custom throttlers.
            # The throttle will be triggered when it attempts to send a sixth PRIVMSG in a four-second interval.
            # When the throttle is active, PRIVMSGs will be sent in at least one-second intervals.
            # The throttle is deactivated when three seconds elapse without
            # sending a PRIVMSG.
            while len(self.throttledata) and self.throttledata[0] < T - 4:
                del self.throttledata[0]
            if not self.throttled:
                if len(self.throttledata) >= 5:
                    self.throttled = True
                    T = self.throttledata[-1] + 1
            else:
                if len(self.throttledata) == 0 or self.throttledata[-1] < T - 2:
                    self.throttled = False
                else:
                    T = max(T, self.throttledata[-1] + 1)
            self.throttledata.append(T)
        with self._sendline:
            self._outgoing.append((T, line, origin))
            self._sendline.notify()

    def _procsendline(self, line, origin=None):
        match = re.findall(_ircsendmatch, line)
        if len(match) == 0:
            return
        (cmd, target, params, extinfo) = match[0]
        cmd = cmd.upper()
        with self.lock:
            if cmd == "QUIT":
                self._quitexpected = True
            self._connection.send("%s\n" % line)

            # Modify line if it contains a password so that the password is not
            # logged or sent to any potentially untrustworthy addons
            if cmd == "PRIVMSG":
                if target.upper() == "NICKSERV":
                    nscmd = re.findall(
                        r"^\s*(\S+)\s+(\S+)(?:\s*(\S+)(?:\s*(.+))?)?$", extinfo, re.I)
                    if nscmd:
                        nscmd = nscmd[0]
                        if nscmd[0].upper() in ("IDENTIFY", "REGISTER"):
                            extinfo = "%s ********" % nscmd[0]
                            line = "%s %s :%s" % (cmd, target, extinfo)
                        elif nscmd[0].upper() in ("GROUP", "GHOST", "RECOVER", "RELEASE"):
                            extinfo = "%s %s ********" % nscmd[:2]
                            line = "%s %s :%s" % (cmd, target, extinfo)
                        elif nscmd[0].upper() == "SET":
                            if nscmd[1].upper() == "PASSWORD":
                                extinfo = "%s %s ********" % nscmd[:2]
                                line = "%s %s :%s" % (cmd, target, extinfo)
                        elif nscmd[0].upper() not in ("GLIST", "ACCESS", "SASET", "DROP", "SENDPASS", "ALIST", "INFO", "LIST", "LOGOUT", "STATUS", "UPDATE", "GETPASS", "FORBID", "SUSPEND", "UNSUSPEND", "OINFO"):
                            extinfo = "********"
                            line = "%s %s :%s" % (cmd, target, extinfo)
                if target.upper() == "CHANSERV":
                    cscmd = re.findall(
                        r"^\s*(\S+)\s+(\S+)\s+(\S+)(?:\s*(\S+)(?:\s*(.+))?)?$", extinfo, re.I)
                    if cscmd:
                        cscmd = cscmd[0]
                        if cscmd[0].upper() in ("IDENTIFY", "REGISTER"):
                            extinfo = "%s %s ********" % cscmd[:2]
                            line = "%s %s :%s" % (cmd, target, extinfo)
                        elif cscmd[0].upper() in ("GROUP", "GHOST", "RECOVER", "RELEASE"):
                            extinfo = "%s %s %s ********" % cscmd[:3]
                            line = "%s %s :%s" % (cmd, target, extinfo)
                        elif cscmd[0].upper() == "SET":
                            if cscmd[2].upper() == "PASSWORD":
                                extinfo = "%s %s %s ********" % cscmd[:3]
                                line = "%s %s :%s" % (cmd, target, extinfo)
                        elif cscmd[0].upper() not in ("GLIST", "ACCESS", "SASET", "DROP", "SENDPASS", "ALIST", "INFO", "LIST", "LOGOUT", "STATUS", "UPDATE", "GETPASS", "FORBID", "SUSPEND", "UNSUSPEND", "OINFO"):
                            extinfo = "********"
                            line = "%s %s :%s" % (cmd, target, extinfo)

                chanmatch = re.findall(
                    _targchanmatch % (re.escape(self.supports.get("PREFIX", ("ohv", "@%+"))[1]), re.escape(self.supports.get("CHANTYPES", "#"))), target)
                if chanmatch:
                    targetprefix, channame = chanmatch[0]
                    target = self.channel(channame)
                    if target.name != channame:
                        # Target channel name has changed
                        target.name = channame
                elif re.match(_nickmatch, target) and cmd != "NICK":
                    targetprefix = ""
                    target = self.user(target)

                ctcp = re.findall(_ctcpmatch, extinfo)
                if ctcp:
                    (ctcptype, ext) = ctcp[0]
                    if ctcptype.upper() == "ACTION":
                        if type(target) == Channel:
                            self._event(
                                "onSendChanAction", self.addons +
                                target.addons,
                                origin=origin, channel=target, targetprefix=targetprefix, action=ext)
                        elif type(target) == User:
                            self._event(
                                "onSendPrivAction", self.addons, origin=origin, user=target, action=ext)
                    else:
                        if type(target) == Channel:
                            self._event(
                                "onSendChanCTCP", self.addons + target.addons, origin=origin,
                                channel=target, targetprefix=targetprefix, ctcptype=ctcptype, params=ext)
                        elif type(target) == User:
                            self._event(
                                "onSendPrivCTCP", self.addons, origin=origin, user=target, ctcptype=ctcptype, params=ext)
                else:
                    if type(target) == Channel:
                        self._event(
                            "onSendChanMsg", self.addons + target.addons, origin=origin,
                            channel=target, targetprefix=targetprefix, msg=extinfo)
                    elif type(target) == User:
                        self._event(
                            "onSendPrivMsg", self.addons, origin=origin, user=target, msg=extinfo)

                # elif target.upper()=="CHANSERV":
                    #msg=extinfo.split(" ")
                    # if msg[0].upper() in ("IDENTIFY", "REGISTER") and len(msg)>2:
                        # msg[2]="********"
                        #extinfo=" ".join(msg)
                        #line="%s %s :%s"%(cmd, target, extinfo)
            elif cmd.upper() in ("NS", "NICKSERV"):
                if target.upper() in ("IDENTIFY", "REGISTER"):
                    params = params.split(" ")
                    while "" in params:
                        params.remove("")
                    if len(params):
                        params[0] = "********"
                    params = " ".join(params)
                    line = "%s %s %s" % (cmd, target, params)
                elif target.upper() in ("GROUP", "GHOST", "RECOVER", "RELEASE"):
                    params = params.split(" ")
                    while "" in params:
                        params.remove("")
                    if len(params) > 1:
                        params[1] = "********"
                    params = " ".join(params)
                    line = "%s %s %s" % (cmd, target, params)
                elif target.upper() not in ("GLIST", "ACCESS", "SASET", "DROP", "SENDPASS", "ALIST", "INFO", "LIST", "LOGOUT", "STATUS", "UPDATE", "GETPASS", "FORBID", "SUSPEND", "UNSUSPEND", "OINFO"):
                    params = ""
                    target = "********"
                    line = "%s %s" % (cmd, target)
            elif cmd.upper() == "OPER":
                params = "********"
                line = "%s %s %s" % (cmd, target, params)
            elif cmd.upper() == "PASS":
                extinfo = "********"
                target = ""
                line = "%s :%s" % (cmd, extinfo)
            elif cmd.upper() == "IDENTIFY":
                target = "********"
                line = "%s %s" % (cmd, target)
            self._event("onSend", self.addons, origin=origin, line=line,
                        cmd=cmd, target=target, params=params, extinfo=extinfo)
        self.logwrite(">>> %s" % line)

    def _sendhandler(self):
        # Enforce that this function must only be run from within
        # self._sendhandlerthread.
        if currentThread() != self._sendhandlerthread:
            raise RuntimeError, "This function is designed to run in its own thread."

        try:
            while True:
                # Wait for one of the following:
                # (1) An item placed into _outgoing
                # (2) Connection is lost
                # (3) self._recvhandlerthread is set to None

                with self._sendline:
                    if "quit" in self._outgoing:
                        sys.exit()
                    S = time.time()
                    if len(self._outgoing):
                        T, line, origin = min(self._outgoing)
                        if T > S:
                            self._sendline.wait(T - S)
                            continue
                        else:
                            self._outgoing.remove((T, line, origin))
                    else:
                        self._sendline.wait()
                        continue

                try:
                    self._procsendline(line, origin=origin)
                except socket.error:
                    exc, excmsg, tb = sys.exc_info()
                    with self.lock:
                        self.logwrite(
                            "*** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars())
                        self._event("onConnectFail", self.addons + reduce(
                            lambda x, y: x + y, [chan.addons for chan in self.channels], []), exc=exc, excmsg=excmsg, tb=tb)
                    with self._sendline:
                        self._outgoing.clear()
                    try:
                        self._connection.close()
                    except:
                        pass

        except SystemExit:
            pass

        except:
            tb = traceback.format_exc()
            self._quitexpected = True
            self.logwrite(*["!!! FATAL Exception"] + [
                          "!!! %s" % line for line in tb.split("\n")])
            print >>sys.stderr, "FATAL Exception"
            print >>sys.stderr, tb
            with self._sendline:
                try:
                    self._connection.send(
                        "QUIT :%s\n" % tb.rstrip().split("\n")[-1])
                    self._connection.shutdown(socket.SHUT_WR)
                except:
                    pass
        finally:
            with self._sendline:
                self._outgoing.clear()  # Clear out _outgoing.

    # For compatibility, when modules still expect irc.Connection to be a
    # subclass of threading.Thread
    def isAlive(self):
        return type(self._recvhandlerthread) == Thread and self._recvhandlerthread.isAlive() and type(self._sendhandlerthread) == Thread and self._sendhandlerthread.isAlive()

    # For compatibility, when modules still expect irc.Connection to be a
    # subclass of threading.Thread
    def start(self):
        return self.connect()

    def __repr__(self):
        server = self.server
        if self.ipv6 and ":" in server:
            server = "[%s]" % server
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
        # else: return "<IRC Context: irc%(ssl)s://%(server)s:%(port)s>" %
        # locals()

    def oper(self, name, passwd, origin=None):
        self.raw("OPER %s %s" %
                 (re.findall("^([^\r\n\\s]*)", name)[0], re.findall("^([^\r\n\\s]*)", passwd)[0]), origin=origin)

    def list(self, params="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", params)[0]):
            self.raw("LIST %s" %
                     (re.findall("^([^\r\n\\s]*)", params)[0]), origin=origin)
        else:
            self.raw("LIST", origin=origin)

    def getmotd(self, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self.raw("MOTD %s" %
                     (re.findall("^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self.raw("MOTD", origin=origin)

    def version(self, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self.raw("VERSION %s" %
                     (re.findall("^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self.raw("VERSION", origin=origin)

    def stats(self, query, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self.raw("STATS %s %s" %
                     (query, re.findall("^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self.raw("STATS %s" % query, origin=origin)

    def quit(self, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self._send("QUIT :%s" %
                       re.findall("^([^\r\n]*)", msg)[0], origin=origin)
        else:
            self._send("QUIT", origin=origin)

    def ctcpversion(self):
        reply = []
        # Prepare reply for addon
        reply.append(
            "%(__name__)s %(__version__)s, %(__author__)s" % vars(self))

        # Prepare reply for Python and OS versions
        pyver = sys.version.split("\n")
        pyver[0] = "Python " + pyver[0]
        reply.extend(pyver)
        reply.extend(platform.platform().split("\n"))
        # Prepare reply for extension addons
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
        self._send(line, origin=origin)

    def user(self, nick):
        if self.supports.get("CASEMAPPING", "rfc1459") == "ascii":
            users = [
                user for user in self.users if user.nick.lower() == nick.lower()]
        else:
            users = [user for user in self.users if user.nick.translate(
                _rfc1459casemapping) == nick.translate(_rfc1459casemapping)]
        if len(users):
            return users[0]
        else:
            user = User(nick, self)
            self.users.append(user)
            timestamp = reduce(lambda x, y: x + ":" + y, [
                               str(t).rjust(2, "0") for t in time.localtime()[0:6]])
            return user

    def channel(self, name):
        if self.supports.get("CASEMAPPING", "rfc1459") == "ascii":
            channels = [
                chan for chan in self.channels if chan.name.lower() == name.lower()]
        else:
            channels = [chan for chan in self.channels if chan.name.translate(
                _rfc1459casemapping) == name.translate(_rfc1459casemapping)]
        if len(channels):
            return channels[0]
        else:
            timestamp = reduce(lambda x, y: x + ":" + y, [
                               str(t).rjust(2, "0") for t in time.localtime()[0:6]])
            chan = Channel(name, self)
            self.channels.append(chan)
            return chan


class Channel(object):

    def __init__(self, name, context):
        chantypes = context.supports.get("CHANTYPES", "&#+!")
        if not re.match(_chanmatch % re.escape(chantypes), name):
            raise InvalidName, repr(name)
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
        self._joinrequested = False
        self._joinreply = None
        self._joining = Condition(self.lock)
        self._partrequested = False
        self._partreply = None
        self._parting = Condition(self.lock)

    def msg(self, msg, target="", origin=None):
        if target and target not in self.context.supports.get("PREFIX", ("ohv", "@%+"))[1]:
            raise InvalidPrefix
        for line in re.findall("([^\r\n]+)", msg):
            self.context._send("PRIVMSG %s%s :%s" %
                               (target, self.name, line), origin=origin)

    def who(self, origin=None):
        self.context._send("WHO %s" % (self.name), origin=origin)

    def names(self, origin=None):
        self.context._send("NAMES %s" % (self.name), origin=origin)

    def notice(self, msg, target="", origin=None):
        if target and target not in self.context.supports.get("PREFIX", ("ohv", "@%+"))[1]:
            raise InvalidPrefix
        for line in re.findall("([^\r\n]+)", msg):
            self.context._send("NOTICE %s%s :%s" %
                               (target, self.name, line), origin=origin)

    def settopic(self, msg, origin=None):
        self.context._send("TOPIC %s :%s" %
                           (self.name, re.findall("^([^\r\n]*)", msg)[0]), origin=origin)

    def ctcp(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.msg("\01%s %s\01" %
                     (act.upper(), re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.msg("\01%s\01" % act.upper())

    def ctcpreply(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.notice("\01%s %(msg)s\01" %
                        (act.upper(), re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.notice("\01%s\01" % act.upper(), origin=origin)

    def me(self, msg="", origin=None):
        self.ctcp("ACTION", msg, origin=origin)

    def part(self, msg="", blocking=False, timeout=30, origin=None):
        with self.context.lock:
            if self.context.identity not in self.users:
                # Bot is not on the channel
                raise NotOnChannel
        with self._parting:
            try:
                if self._partrequested:
                    raise ActionAlreadyRequested
                self._partrequested = True
                if len(re.findall("^([^\r\n]*)", msg)[0]):
                    self.context._send(
                        "PART %s :%s" % (self.name, re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
                else:
                    self.context._send("PART %s" % self.name, origin=origin)

                # Anticipated Numeric Replies:

                # ERR_NEEDMOREPARAMS ERR_NOSUCHCHANNEL
                # ERR_NOTONCHANNEL

                if blocking:
                    endtime = time.time() + timeout
                    while True:
                        self._parting.wait(max(0, endtime - time.time()))
                        t = time.time()
                        if not self.context.connected:
                            raise NotConnected
                        elif self._partreply == "PART":
                            return
                        elif type(self._partreply) == tuple and len(self._partreply) == 2:
                            cmd, extinfo = self._partreply
                            raise exceptcodes[cmd], extinfo
                        if t > endtime:
                            raise RequestTimedOut
            finally:
                self._partrequested = False
                self._partreply = None

    def invite(self, user, origin=None):
        nickname = user.nick if type(
            user) == User else re.findall("^([^\r\n\\s]*)", user)[0]
        if nickname == "":
            raise InvalidName
        self.context._send("INVITE %s %s" %
                           (nickname, self.name), origin=origin)

    def join(self, key="", blocking=False, timeout=30, origin=None):
        with self.context.lock:
            if self.context.identity in self.users:
                # Bot is already on the channel
                raise AlreadyJoined
        with self._joining:
            try:
                if self._joinrequested:
                    raise ActionAlreadyRequested
                self._joinrequested = True
                if len(re.findall("^([^\r\n\\s]*)", key)[0]):
                    self.context._send(
                        "JOIN %s %s" % (self.name, re.findall("^([^\r\n\\s]*)", key)[0]), origin=origin)
                else:
                    self.context._send("JOIN %s" % self.name, origin=origin)

                # Anticipated Numeric Replies:

                # ERR_NEEDMOREPARAMS ERR_BANNEDFROMCHAN
                # ERR_INVITEONLYCHAN ERR_BADCHANNELKEY
                # ERR_CHANNELISFULL ERR_BADCHANMASK
                # ERR_NOSUCHCHANNEL ERR_TOOMANYCHANNELS
                # ERR_TOOMANYTARGETS ERR_UNAVAILRESOURCE

                if blocking:
                    endtime = time.time() + timeout
                    while True:
                        self._joining.wait(max(0, endtime - time.time()))
                        t = time.time()
                        if not self.context.connected:
                            raise NotConnected
                        elif self._joinreply == "JOIN":
                            return
                        elif type(self._joinreply) == tuple and len(self._joinreply) == 2:
                            cmd, extinfo = self._joinreply
                            raise exceptcodes[cmd], extinfo
                        if t > endtime:
                            raise RequestTimedOut
            finally:
                self._joinrequested = False
                self._joinreply = None

    def kick(self, user, msg="", origin=None):
        nickname = user.nick if type(
            user) == User else re.findall("^([^\r\n\\s]*)", user)[0]
        if nickname == "":
            raise InvalidName
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.context._send("KICK %s %s :%s" %
                               (self.name, nickname, re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.context._send("KICK %s %s" %
                               (self.name, nickname), origin=origin)

    def __repr__(self):
        return "<Channel: " + self.name + "@" + self.context.server + "/" + str(self.context.port) + ">"


class User(object):

    def __init__(self, nick, context):
        if not re.match(_nickmatch, nick):
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
            self.context._send("PRIVMSG %s :%s" %
                               (self.nick, line), origin=origin)

    def notice(self, msg, origin=None):
        for line in re.findall("([^\r\n]+)", msg):
            self.context._send("NOTICE %s :%s" %
                               (self.nick, line), origin=origin)

    def ctcp(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.msg("\01%s %s\01" %
                     (act.upper(), re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.msg("\01%s\01" % act.upper())

    def ctcpreply(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.notice("\01%s %s\01" %
                        (act.upper(), re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.notice("\01%s\01" % act.upper(), origin=origin)

    def me(self, msg="", origin=None):
        self.ctcp("ACTION", msg, origin=origin)
