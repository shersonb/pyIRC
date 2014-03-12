#!/usr/bin/python
from threading import Thread, Condition, currentThread
from threading import RLock as Lock
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
from collections import deque, OrderedDict
import chardet
import codecs
import new
import inspect
import warnings
import random


def autodecode(s):
    try:
        return s.decode("utf8")
    except UnicodeDecodeError:
        # Attempt to figure encoding
        detected = chardet.detect(s)
        try:
            return s.decode(detected['encoding'])
        except UnicodeDecodeError:
            return s.decode("utf8", "replace")


class AddonWarning(Warning):
    pass


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
                                       string.ascii_lowercase + r'|{}^').decode("ISO-8859-2")

# The IRC RFC does not permit the first character in a nickname to be a
# numeral. However, this is not always adhered to.
_nickmatch = r"^[A-Za-z0-9\-\^\`\\\|\_\{\}\[\]]+$"

_intmatch = r"^\d+$"
_chanmatch = r"^[%%s][^%s\s\n]*$" % re.escape("\x07,")
_targchanmatch = r"^([%%s]?)([%%s][^%s\s\n]*)$" % re.escape("\x07,")
_usermatch = r"^[A-Za-z0-9\-\^\`\\\|\_\{\}\[\]]+$"
_realnamematch = r"^[^\n]*$"
_ircmatch = r"^(?::(.+?)(?:!(.+?)@(.+?))?\s+)?([A-Za-z0-9]+?)\s*(?:\s+(.+?)(?:\s+(.+?))??)??(?:\s+:(.*))?$"
_ctcpmatch = "^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$"
_prefixmatch = r"\((.*)\)(.*)"
_defaultchanmodes = u"b,k,l,imnpst".split(",")
_defaultprefix = ("ov", "@+")
_defaultchantypes = "&#+!"

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
    __name__ = "pyIRC"
    __version__ = "2.0"
    __author__ = "Brian Sherson"
    __date__ = "February 21, 2014"

    def __init__(self, server, nick="ircbot", username="python", realname="Python IRC Library", passwd=None, port=None, ipvers=(socket.AF_INET6, socket.AF_INET), secure=False, autoreconnect=True, timeout=300, retrysleep=5, maxretries=15, protoctl=("UHNAMES", "NAMESX"), quietpingpong=True, pinginterval=60, addons=None, autostart=False):
        if port is None or (type(port) == int and 0 < port < 65536):
            self.port = port
        else:
            raise ValueError, "Invalid value for 'port'"

        if re.match(_nickmatch, nick) if (type(nick) in (str, unicode)) else all([re.match(_nickmatch, n) for n in nick]) if (type(nick) in (list, tuple)) else False:
            self.nick = nick
        else:
            raise ValueError, "Invalid value for 'nick'"

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
        self.secure = secure
        self.ipvers = ipvers if type(ipvers) == tuple else (ipvers,)

        self.protoctl = protoctl

        if type(autoreconnect) == bool:
            self.autoreconnect = autoreconnect
        else:
            raise ValueError, "Invalid value for 'autoreconnect'"

        if type(maxretries) in (int, long):
            self.maxretries = maxretries
        else:
            raise ValueError, "Invalid value for 'maxretries'"

        if type(timeout) in (int, long):
            self.timeout = timeout
        else:
            raise ValueError, "Invalid value for 'timeout'"

        if type(retrysleep) in (int, long):
            self.retrysleep = retrysleep
        else:
            raise ValueError, "Invalid value for 'retrysleep'"

        if type(quietpingpong) == bool:
            self.quietpingpong = quietpingpong
        else:
            raise ValueError, "Invalid value for 'quietpingpong'"

        if type(pinginterval) in (int, long):
            self.pinginterval = pinginterval
        else:
            raise ValueError, "Invalid value for 'pinginterval'"

        self._quitexpected = False
        self.log = sys.stdout

        self.lock = Lock()

        self._loglock = Lock()
        self._outlock = Lock()
        self._sendline = Condition(self._outlock)
        self._connecting = Condition(self.lock)
        self._disconnecting = Condition(self.lock)
        self._outgoing = deque()

        self._sendhandlerthread = None
        self._recvhandlerthread = None

        # Initialize IRC environment variables
        self.users = UserList(context=self)
        self.channels = ChanList(context=self)
        self.addons = []

        self.trusted = []  # To be implemented later
        self._init()
        if type(addons) == list:
            for addon in addons:
                if type(addon) == dict:
                    self.addAddon(**addon)
                else:
                    self.addAddon(addon)
        if autostart:
            self.connect()

    def _init(self):
        self.ipver = None
        self.addr = None
        self._connected = False
        self._registered = False
        self._connection = None
        self.trynick = 0

        self.identity = None

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
                try:
                    print >>self.log, u"%s %s" % (ts, line)
                except:
                    print line
                    raise
            self.log.flush()

    def logopen(self, filename, encoding="utf8"):
        with self._loglock:
            ts = timestamp()
            newlog = codecs.open(filename, "a", encoding=encoding)
            if isinstance(self.log, codecs.StreamReaderWriter) and not self.log.closed:
                if self.log not in (sys.stdout, sys.stderr):
                    print >>self.log, "%s ### Log file closed" % (ts)
                    self.log.close()
            self.log = newlog
            print >>self.log, "%s ### Log file opened" % (ts)
            self.log.flush()

    # Used to call event handlers on all attached addons, when applicable.
    def _event(self, addons, events, line=None, data=None, exceptions=False):
        handled = []
        unhandled = []
        errors = []
        for k, addon in enumerate(addons):
            if addons.index(addon) < k:
                # Duplicate
                continue

            if type(addon) == Config:
                addon = addon.addon

            fellback = False  # Switch this to True when a fallback is used so that we only call onOther once.

            # Iterate through all events.
            for (method, args, fallback) in events:
                if method in dir(addon) and callable(getattr(addon, method)):
                    f = getattr(addon, method)
                elif fallback and not fellback:
                    if "onOther" in dir(addon) and callable(addon.onOther) and data:
                        f = addon.onOther
                        args = dict(line=line, **data)
                        fellback = True
                    elif "onUnhandled" in dir(addon) and callable(addon.onUnhandled) and data:
                        # Backwards compatability for addons that still use
                        # onUnhandled. Use onOther in future development.
                        f = addon.onUnhandled
                        args = dict(line=line, **data)
                        fellback = True
                    else:
                        unhandled.append(addon)
                        continue
                else:
                    unhandled.append(addon)
                    continue

                if type(f) == new.instancemethod:
                    argspec = inspect.getargspec(f.im_func)
                else:
                    argspec = inspect.getargspec(f)
                if argspec.keywords == None:
                    args = {
                        arg: val for arg, val in args.items() if arg in argspec.args}
                try:
                    f(self, **args)
                except:
                    # print f, args
                    exc, excmsg, tb = sys.exc_info()
                    errors.append((addon, exc, excmsg, tb))

                    # Print to log AND stderr
                    tblines = [u"!!! Exception in addon %(addon)s" % vars()]
                    tblines.append(u"!!! Function: %s" % f)
                    tblines.append(u"!!! Arguments: %s" % args)
                    for line in traceback.format_exc().split("\n"):
                        tblines.append(u"!!! %s" % autodecode(line))
                    self.logwrite(*tblines)
                    print >>sys.stderr, "Exception in addon %(addon)s" % vars()
                    print >>sys.stderr, u"Function: %s" % f
                    print >>sys.stderr, u"Arguments: %s" % args
                    print >>sys.stderr, traceback.format_exc()
                    if exceptions:  # If set to true, we raise the exception.
                        raise
                else:
                    handled.append(addon)
        return (handled, unhandled, errors)

    # TODO: Build method validation into the next two addons, Complain when a method is not callable or does not take in the expected arguments.
    # Inspects the methods of addon to make sure
    def validateAddon(self, addon):
        supported = self.eventsupports()
        keys = supported.keys()
        for fname in dir(addon):
            if fname in keys:
                supportedargs = supported[fname]
            elif re.match(r"^on(?:Send)?[A-Z]+$", fname):
                supportedargs = (
                    "line", "origin", "target", "targetprefix", "params", "extinfo")
            elif re.match(r"^on\d{3}$", fname):
                supportedargs = (
                    "line", "origin", "target", "params", "extinfo")
            else:
                continue
            func = getattr(addon, fname)
            argspec = inspect.getargspec(func)
            if type(func) == new.instancemethod:
                funcargs = argspec.args[1:]
            if argspec.defaults:
                requiredargs = funcargs[:-len(argspec.defaults)]
            else:
                requiredargs = funcargs
            contextarg = funcargs[0]
            unsupported = [
                arg for arg in requiredargs[1:] if arg not in supportedargs]
            if len(unsupported):
                warnings.warn(
                    "Function '%s' requires unsupported arguments: %s" %
                    (func.__name__, ", ".join(unsupported)), AddonWarning)
                self.logwrite(
                    "!!! AddonWarning: Function '%s' requires unsupported arguments: %s" %
                    (func.__name__, ", ".join(unsupported)))
            if argspec.keywords == None:
                unsupported = [
                    arg for arg in supportedargs if arg not in funcargs[1:]]
                if len(unsupported):
                    warnings.warn(
                        "Function '%s' does not accept supported arguments: %s" %
                        (func.__name__, ", ".join(unsupported)), AddonWarning)
                    self.logwrite(
                        "!!! AddonWarning: Function '%s' does not accept supported arguments: %s" %
                        (func.__name__, ", ".join(unsupported)))

    def addAddon(self, addon, trusted=False, **params):
        self.validateAddon(addon)
        for a in self.addons:
            if (type(a) == Config and a.addon is addon) or a is addon:
                raise BaseException, "Addon already added."
        with self.lock:
            if params:
                defconf = Config(addon, **params)
            else:
                defconf = addon
            if hasattr(addon, "onAddonAdd") and callable(addon.onAddonAdd):
                conf = addon.onAddonAdd(self, **params)
                if conf is not None:
                    self.addons.append(conf)
                else:
                    self.addons.append(defconf)
            else:
                self.addons.append(defconf)
            self.logwrite("*** Addon %s added." % repr(addon))
            if trusted:
                self.trusted.append(addon)

    def insertAddon(self, index, addon, trusted=False, **params):
        self.validateAddon(addon)
        for a in self.addons:
            if (type(a) == Config and a.addon is addon) or a is addon:
                raise BaseException, "Addon already added."
        with self.lock:
            if params:
                defconf = Config(addon, **params)
            else:
                defconf = addon
            if hasattr(addon, "onAddonAdd") and callable(addon.onAddonAdd):
                conf = addon.onAddonAdd(self, **params)
                if conf is not None:
                    self.addons.insert(index, conf)
                else:
                    self.addons.insert(index, defconf)
            else:
                self.addons.insert(index, defconf)
            self.logwrite("*** Addon %s inserted into index %d." %
                          (repr(addon), index))
            if trusted:
                self.trusted.append(addon)

    def rmAddon(self, addon):
        with self.lock:
            self.addons.remove(addon)
            self.logwrite("*** Addon %s removed." % repr(addon))
            if addon in self.trusted:
                self.trusted.remove(addon)
            if hasattr(addon, "onAddonRem") and callable(addon.onAddonAdd):
                addon.onAddonRem(self)

    def connect(self, server=None, port=None, secure=None, ipvers=None, forcereconnect=False, blocking=False):
        if ipvers != None:
            ipvers = ipvers if type(ipvers) == tuple else (ipvers,)
        else:
            ipvers = self.ipvers

        server = server if server else self.server
        port = port if port else self.port
        secure = secure if secure != None else self.secure

        with self._connecting:
            if self.isAlive():
                if forcereconnect:
                    self.quit("Changing server...", blocking=True)
                else:
                    raise AlreadyConnected
            with self._sendline:
                self._outgoing.clear()
            self._recvhandlerthread = Thread(target=self._recvhandler, name="Receive Handler", kwargs=dict(
                server=server, port=port, secure=secure, ipvers=ipvers))
            self._sendhandlerthread = Thread(
                target=self._sendhandler, name="Send Handler")
            self._recvhandlerthread.start()
            self._sendhandlerthread.start()
            if blocking:
                self._connecting.wait()
                if not self.connected:
                    raise NotConnected

    def _connect(self, addr, ipver, secure, hostname=None):
        with self.lock:
            if self._connected:
                raise AlreadyConnected

            if hostname:
                if ipver == socket.AF_INET6:
                    addrstr = "{hostname} ([{addr[0]}]:{addr[1]})".format(
                        **vars())
                else:
                    addrstr = "{hostname} ({addr[0]}:{addr[1]})".format(
                        **vars())
            else:
                if ipver == socket.AF_INET6:
                    addrstr = "[{addr[0]}]:{addr[1]}".format(**vars())
                else:
                    addrstr = "{addr[0]}:{addr[1]}".format(**vars())
            self.logwrite(
                "*** Attempting connection to {addrstr}.".format(**vars()))
            self._event(self.getalladdons(), [
                        ("onConnectAttempt", dict(), False)])

        try:
            connection = socket.socket(ipver, socket.SOCK_STREAM)
            if secure:
                connection.settimeout(self.timeout)
                self._connection = ssl.wrap_socket(
                    connection, cert_reqs=ssl.CERT_NONE)
            else:
                self._connection = connection
                self._connection.settimeout(self.timeout)
            self._connection.connect(addr)
        except socket.error:
            exc, excmsg, tb = sys.exc_info()
            self.logwrite(
                "*** Connection to {addrstr} failed: {excmsg}.".format(**vars()))
            with self.lock:
                self._event(self.getalladdons(), [
                            ("onConnectFail", dict(exc=exc, excmsg=excmsg, tb=tb), False)])
            raise
        else:
            # Run onConnect on all addons to signal connection was established.
            with self.lock:
                self._event(
                    self.getalladdons(), [("onConnect", dict(), False)])
            self.logwrite(
                "*** Connection to {addrstr} established.".format(**vars()))
            self.addr = addr
            self._connected = True
            with self._connecting:
                self._connecting.notifyAll()

    def _tryaddrs(self, server, addrs, ipver, secure):
        for addr in addrs:
            try:
                if server == addr[0]:
                    self._connect(addr=addr, secure=secure, ipver=ipver)
                else:
                    self._connect(
                        hostname=server, addr=addr, secure=secure, ipver=ipver)
            except socket.error, msg:
                if self._quitexpected:
                    sys.exit()
                if msg.errno == 101:  # Network is unreachable, will pass the exception on.
                    raise
                if self.retrysleep > 0:
                    time.sleep(self.retrysleep)
                if self._quitexpected:
                    sys.exit()
            else:
                return True
        return False

    def _tryipver(self, server, port, ipver, secure):
        if ipver == socket.AF_INET6:
            self.logwrite(
                "*** Attempting to resolve {server} to an IPv6 address...".format(**vars()))
        else:
            self.logwrite(
                "*** Attempting to resolve {server}...".format(**vars()))

        try:
            addrs = socket.getaddrinfo(
                server, port if port is not None else 6697 if self.secure else 6667, ipver)
        except socket.gaierror, msg:
            self.logwrite("*** Resolution failed: {msg}.".format(**vars()))
            raise

        # Weed out duplicates
        addrs = list(
            set([sockaddr for family, socktype, proto, canonname, sockaddr in addrs if family == ipver]))

        n = len(addrs)
        if n == 1:
            addr = addrs[0]
            self.logwrite(
                "*** Name {server} resolves to {addr[0]}.".format(**vars()))
        else:
            self.logwrite(
                "*** Name {server} resolves to {n} addresses, choosing one at random until success.".format(**vars()))
            random.shuffle(addrs)

        return self._tryaddrs(server, addrs, ipver, secure)

    def _tryipvers(self, server, port, ipvers, secure):
        for ipver in ipvers:
            try:
                ret = self._tryipver(server, port, ipver, secure)
            except socket.gaierror, msg:
                if msg.errno == -2:  # Name or service not known. Again, just try next ipver.
                    continue
                else:
                    raise
            except socket.error, msg:
                if msg.errno == 101:  # Don't err out, just try next ipver.
                    continue
                else:
                    raise
            else:
                if ret:
                    self.ipver = ipver
                    return True
        return False

    def _procrecvline(self, line):
        matches = re.findall(_ircmatch, line)

        # We have a match!
        if len(matches):
            (origin, username, host, cmd, target, params, extinfo) = matches[0]
            unhandled = []

            if re.match(_intmatch, cmd):
                cmd = int(cmd)  # Code is a numerical response
            else:
                cmd = cmd.upper()

            if cmd not in ("PING", "PONG") or not self.quietpingpong:
                self.logwrite("<<< %s" % line)

            if origin == "" and cmd == "PING":
                self._send(u"PONG :%s" % extinfo)

            with self.lock:
                data = dict(origin=origin, cmd=cmd, target=target,
                            targetprefix=None, params=params, extinfo=extinfo)

                if not self._registered:
                    if type(cmd) == int and cmd != 451 and target != "*":  # Registration complete!
                        self.identity = self.user(target, init=True)
                        self.serv = origin
                        self._event(self.getalladdons(), [
                                    ("onRegistered", dict(), False)], line, data)
                        self._registered = True

                    elif cmd == 433 and target == "*":  # Server reports nick taken, so we need to try another.
                        self._trynick()
                    if not self._registered:  # Registration is not yet complete
                        return

                if username and host:
                    nickname = origin
                    origin = self.user(origin)
                    if origin.nick != nickname:
                        # Origin nickname case has changed
                        origin.user = nickname
                    if origin.username != username:
                        # Origin username has changed
                        origin.username = username
                    if origin.host != host:
                        # Origin host has changed
                        origin.host = host

                # Check to see if target matches a channel (optionally with
                # prefix)
                prefix = self.supports.get("PREFIX", _defaultprefix)
                chantypes = self.supports.get("CHANTYPES", _defaultchantypes)
                chanmatch = re.findall(
                    _targchanmatch % (re.escape(prefix[1]), re.escape(chantypes)), target)

                if chanmatch:
                    targetprefix, channame = chanmatch[0]
                    target = self.channel(channame)
                    if target.name != channame:
                        # Target channel name has changed case
                        target.name = channame

                # Check to see if target matches a valid nickname. Do NOT
                # convert target to User instance if cmd is NICK.
                elif re.match(_nickmatch, target) and cmd != "NICK":
                    targetprefix = ""
                    target = self.user(target)

                # Otherwise, target is just left as a string
                else:
                    targetprefix = ""

                data = dict(origin=origin, cmd=cmd, target=target,
                            targetprefix=targetprefix, params=params, extinfo=extinfo)

                # Parse

                # Takes the given data and runs it through a parse method to determine what addon methods should be called later, and prepares the arguments
                # to be passed to each of these methods.
                # This part does not update the IRC state.
                parsename = (
                    "parse%03d" if type(cmd) == int else "parse%s") % cmd

                # This is the case that there is a parse method specific to the
                # given cmd.
                if hasattr(self, parsename) and callable(getattr(self, parsename)):
                    parsemethod = getattr(self, parsename)
                    try:
                        addons, events = parsemethod(
                            origin, target, targetprefix, params, extinfo)
                    except:
                        exc, excmsg, tb = sys.exc_info()

                        # Print to log AND stderr
                        tblines = [
                            u"!!! There was an error in parsing the following line:", u"!!! %s" % line]
                        for tbline in traceback.format_exc().split("\n"):
                            tblines.append(u"!!! %s" % autodecode(tbline))
                        self.logwrite(*tblines)
                        print >>sys.stderr, u"There was an error in parsing the following line:"
                        print >>sys.stderr, u"%s" % line
                        print >>sys.stderr, traceback.format_exc()
                        return
                else:
                    addons = self.addons
                    if type(cmd) == int:
                        events = [
                            ("on%03d" % cmd, dict(line=line, origin=origin, target=target, params=params, extinfo=extinfo), True)]
                    else:
                        events = [
                            ("on%s" % cmd.upper(), dict(line=line, origin=origin, target=target, targetprefix=targetprefix, params=params, extinfo=extinfo), True)]

                # Supress pings and pongs if self.quietpingpong is set to True
                if cmd in ("PING", "PONG") and self.quietpingpong:
                    return

                # Send parsed data to addons having onRecv method first
                self._event(
                    addons + [self], [("onRecv", dict(line=line, **data), False)], line, data)

                # Support for further addon events is taken care of here. We also treat the irc.Connection instance itself as an addon for the purpose of
                # tracking the IRC state, and should be invoked *last*.
                self._event(addons + [self], events, line, data)

    def _recvhandler(self, server, port, ipvers, secure):
        if currentThread() != self._recvhandlerthread:  # Enforce that this function must only be run from within self._sendhandlerthread.
            raise RuntimeError, "This function is designed to run in its own thread."

        try:
            with self.lock:
                self._event(self.getalladdons(), [
                            ("onSessionOpen", dict(), False)])

            self.logwrite("### Session started")

            ipvers = ipvers if type(ipvers) == tuple else (ipvers,)

            # Autoreconnect loop
            while True:
                attempt = 1

                # Autoretry loop
                while True:
                    servisip = False
                    for ipver in ipvers:  # Check to see if address is a valid ip address instead of host name
                        try:
                            socket.inet_pton(ipver, server)
                        except socket.error:
                            continue  # Not a valid ip address under this ipver.
                        # Is a valid ip address under this ipver.
                        if ipver == socket.AF_INET6:
                            self._tryaddrs(
                                server, [(server, port, 0, 0)], ipver, secure)
                        else:
                            ret = self._tryaddrs(
                                server, [(server, port)], ipver, secure)
                        servisip = True
                        break
                    # Otherwise, we assume server is a hostname
                    if not servisip:
                        ret = self._tryipvers(server, port, ipvers, secure)
                    if ret:
                        self.server = server
                        self.port = port
                        self.ipvers = ipvers
                        self.secure = secure
                        break
                    if self._quitexpected:
                        sys.exit()
                    if self.retrysleep > 0:
                        time.sleep(self.retrysleep)
                    if self._quitexpected:
                        sys.exit()
                    if attempt < self.maxretries or self.maxretries < 0:
                        if self._quitexpected:
                            sys.exit()
                        attempt += 1
                    else:
                        self.logwrite(
                            "*** Maximum number of attempts reached. Giving up. (%(server)s:%(port)s)" % vars())
                        with self._connecting:
                            self._connecting.notifyAll()
                        sys.exit()

                # Connection succeeded
                try:
                    pingreq = None
                    with self._sendline:
                        self._sendline.notify()

                    # Attempt initial registration.
                    nick = self.nick[0]
                    if self.passwd:
                        self._send(u"PASS %s" % self.passwd)
                    self._trynick()
                    self._send(u"USER %s * * :%s" %
                               (self.username.split("\n")[0].rstrip(), self.realname.split("\n")[0].rstrip()))

                    # Initialize buffers
                    linebuf = []
                    readbuf = ""

                    while True:  # Main loop of IRC connection.
                        while len(linebuf) == 0:  # Need Moar Data
                            read = self._connection.recv(512)
                            with self._sendline:
                                if pingreq and pingreq in self._outgoing:
                                    self._outgoing.remove(pingreq)
                                pingreq = (time.time() + self.pinginterval, u"PING %s %s" % (
                                    self.identity.nick if self.identity else "*", self.serv), self)
                                self._outgoing.append(pingreq)
                                self._sendline.notify()

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

                        line = linebuf.pop(0).rstrip("\r")
                        line = autodecode(line)
                        self._procrecvline(line)

                except SystemExit:  # Connection lost normally.
                    pass

                except socket.error:  # Connection lost due to either ping timeout or connection reset by peer. Not a fatal error.
                    exc, excmsg, tb = sys.exc_info()
                    with self.lock:
                        self.logwrite(
                            "*** Connection to %(server)s:%(port)s failed: %(excmsg)s." % vars())
                        self._event(self.getalladdons(), [
                                    ("onConnectFail", dict(exc=exc, excmsg=excmsg, tb=tb), False)])

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
                    with self._sendline:  # Notify _outgoingthread that the connection has been terminated.
                        self._outgoing.clear()
                        self._sendline.notify()
                    with self._disconnecting:
                        self._disconnecting.notifyAll()
                        self._event(self.getalladdons(), [
                                    ("onDisconnect", dict(expected=self._quitexpected), False)])

                        self._init()

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
            self.logwrite("### Session ended")
            self._event(self.getalladdons(), [
                        ("onSessionClose", dict(), False)])

            # Tell _sendhandler to quit
            with self._sendline:
                self._outgoing.append("quit")
                self._sendline.notify()

    # Gets a list of *all* addons, including channel-specific addons.
    def getalladdons(self):
        return self.addons + reduce(lambda x, y: x + y, [chan.addons for chan in self.channels], [])

    # The following methods matching parse* are used to determine what addon methods will be called, and prepares the arguments to be passed.
    # These methods can also be used to determine event support by invoking
    # them with no parameters. This allows for addition of event supports.
    # Each is expected to return a tuple (addons, [(method, args, fallback), ...]).
    # 'addons' refers to the list of addons whose methods should be called.
    # [(method, args, fallback), ...] is a list of methods and parameters to be called, as well as a flag to determine when a fallback is permitted.
    # 'method' refers to the name of the method to be invoked in the addons
    # 'args' is a dict of arguments that should be passed as parameters to event.
    # 'fallback' is a flag to determine when a fallback to 'onOther' is permitted.
    # Each of these functions should allow passing None to all arguments, in
    # which case, should report back *all* supported methods.
    def parse001(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        return (self.getalladdons(), [("onWelcome", dict(origin=origin, msg=extinfo), True)])

    def parse002(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        return (self.getalladdons(), [("onYourHost", dict(origin=origin, msg=extinfo), True)])

    def parse003(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        return (self.getalladdons(), [("onServerCreated", dict(origin=origin, msg=extinfo), True)])

    def parse004(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        return (self.getalladdons(), [("onServInfo", dict(origin=origin, servinfo=params), True)])

    def parse005(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Server Supports
        if origin == None:
            return (None, [("onSupports", dict(origin=None, supports=None, msg=None), True)])
        support = dict(re.findall("([A-Za-z0-9]+)(?:=(\\S*))?", params))
        if support.has_key("CHANMODES"):
            support["CHANMODES"] = support["CHANMODES"].split(",")
        if support.has_key("PREFIX"):
            matches = re.findall(_prefixmatch, support["PREFIX"])
            if matches:
                support["PREFIX"] = matches[0]
            else:
                del support["PREFIX"]
                    # Might as well delete the info if it doesn't match
                    # expected pattern
        return (self.getalladdons(), [("onSupports", dict(origin=origin, supports=support, msg=extinfo), True)])

    def parse008(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Snomask
        if origin == None:
            return (None, [("onSnoMask", dict(origin=None, snomask=None), True)])
        snomask = params.lstrip("+")
        return (self.getalladdons(), [("onSnoMask", dict(origin=origin, snomask=snomask), True)])

    def parse221(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # User Modes
        if origin == None:
            return (self.getalladdons(), [("onUserModes", dict(origin=None, modes=None), True)])
        modes = (params if params else extinfo).lstrip("+")
        return (self.getalladdons(), [("onUserModes", dict(origin=origin, modes=modes), True)])

    def parse251(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Net Stats
        return (self.addons, [("onNetStats", dict(origin=origin, netstats=extinfo), True)])

    def parse252(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Operator count
        if origin == None:
            return (None, [("onOpCount", dict(origin=None, opcount=None), True)])
        opcount = int(params)
        return (self.addons, [("onOpCount", dict(origin=origin, opcount=opcount), True)])

    def parse254(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Count
        if origin == None:
            return (self.addons, [("onChanCount", dict(origin=None, chancount=None), True)])
        chancount = int(params)
        return (self.addons, [("onChanCount", dict(origin=origin, chancount=chancount), True)])

    def parse305(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Returned from away status
        return (self.getalladdons(), [("onReturn", dict(origin=origin, msg=extinfo), True)])

    def parse306(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Entered away status
        return (self.getalladdons(), [("onAway", dict(origin=origin, msg=extinfo), True)])

    def parse311(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Start of WHOIS data
        if origin == None:
            return (None, [("onWhoisStart", dict(origin=None, user=None, nickname=None, username=None, host=None, realname=None), True)])
        nickname, username, host, star = params.split()
        user = self.user(nickname)
        return (self.addons, [("onWhoisStart", dict(origin=origin, user=user, nickname=nickname, username=username, host=host, realname=extinfo), True)])

    def parse301(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Away Message
        if origin == None:
            return (None, [("onWhoisAway", dict(origin=None, user=None, nickname=None, awaymsg=None), True)])
        user = self.user(params)
        return (self.addons, [("onWhoisAway", dict(origin=origin, user=user, nickname=params, awaymsg=extinfo), True)])

    def parse303(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # ISON Reply
        if origin == None:
            return (None, [("onIsonReply", dict(origin=None, isonusers=None), True)])
        users = [self.user(user) for user in extinfo.split(" ")]
        return (self.addons, [("onIsonReply", dict(origin=origin, isonusers=users), True)])

    def parse307(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Is a registered nick
        if origin == None:
            return (None, [("onWhoisRegisteredNick", dict(origin=None, user=None, nickname=None, msg=None), True)])
        return (self.addons, [("onWhoisRegisteredNick", dict(origin=origin, user=self.user(params), nickname=params, msg=extinfo), True)])

    def parse378(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Connecting From
        if origin == None:
            return (None, [("onWhoisConnectingFrom", dict(origin=None, user=None, nickname=None, msg=None), True)])
        return (self.addons, [("onWhoisConnectingFrom", dict(origin=origin, user=self.user(params), nickname=params, msg=extinfo), True)])

    def parse319(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channels
        if origin == None:
            return (None, [("onWhoisChannels", dict(origin=None, user=None, nickname=None, chanlist=None), True)])
        return (self.addons, [("onWhoisChannels", dict(origin=origin, user=self.user(params), nickname=params, chanlist=extinfo.split(" ")), True)])

    def parse310(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Availability
        if origin == None:
            return (None, [("onWhoisAvailability", dict(origin=None, user=None, nickname=None, msg=None), True)])
        return (self.addons, [("onWhoisAvailability", dict(origin=origin, user=self.user(params), nickname=params, msg=extinfo), True)])

    def parse312(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Server
        if origin == None:
            return (None, [("onWhoisServer", dict(origin=None, user=None, nickname=None, server=None, servername=None), True)])
        nickname, server = params.split(" ")
        user = self.user(nickname)
        return (self.addons, [("onWhoisServer", dict(origin=origin, user=user, nickname=nickname, server=server, servername=extinfo), True)])

    def parse313(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # IRC Op
        if origin == None:
            return (None, [("onWhoisOp", dict(origin=None, user=None, nickname=None, msg=None), True)])
        user = self.user(params)
        return (self.addons, [("onWhoisOp", dict(origin=origin, user=user, nickname=params, msg=extinfo), True)])

    def parse317(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Idle and Signon times
        if origin == None:
            return (None, [("onWhoisTimes", dict(origin=None, user=None, nickname=None, idletime=None, signontime=None, msg=None), True)])
        nickname, idletime, signontime = params.split(" ")
        user = self.user(nickname)
        return (self.addons, [("onWhoisTimes", dict(origin=origin, user=user, nickname=nickname, idletime=int(idletime), signontime=int(signontime), msg=extinfo), True)])

    def parse671(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # SSL
        if origin == None:
            return (None, [("onWhoisSSL", dict(origin=None, user=None, nickname=None, msg=None), True)])
        user = self.user(params)
        return (self.addons, [("onWhoisSSL", dict(origin=origin, user=user, nickname=params, msg=extinfo), True)])

    def parse379(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # User modes
        if origin == None:
            return (None, [("onWhoisModes", dict(origin=None, user=None, nickname=None, msg=None), True)])
        return (self.addons, [("onWhoisModes", dict(origin=origin, user=self.user(params), nickname=params, msg=extinfo), True)])

    def parse330(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Logged in as
        if origin == None:
            return (None, [("onWhoisLoggedInAs", dict(origin=None, user=None, nickname=None, loggedinas=None, msg=None), True)])
        nickname, loggedinas = params.split(" ")
        user = self.user(nickname)
        return (self.addons, [("onWhoisLoggedInAs", dict(origin=origin, user=user, nickname=nickname, loggedinas=loggedinas, msg=extinfo), True)])

    def parse318(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # End of WHOIS
        if origin == None:
            return (None, [("onWhoisEnd", dict(origin=None, user=None, nickname=None, msg=None), True)])
        try:
            user = self.user(params)
        except InvalidName:
            user = params
        return (self.addons, [("onWhoisEnd", dict(origin=origin, user=user, nickname=params, msg=extinfo), True)])

    def parse321(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Start LIST
        return (None, [("onListStart", dict(origin=origin, params=params, extinfo=extinfo), True)])

    def parse322(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # LIST item
        if origin == None:
            return (None, [("onListEntry", dict(origin=None, channel=None, population=None, extinfo=None), True)])
        (chan, pop) = params.split(" ", 1)
        try:
            return (self.addons, [("onListEntry", dict(origin=origin, channel=self.channel(chan), population=int(pop), extinfo=extinfo), True)])
        except:
            return (self.addons, [("onListEntry", dict(origin=origin, channel=chan, population=int(pop), extinfo=extinfo), True)])

    def parse323(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # End of LIST
        return (None, [("onListEnd", dict(origin=None, endmsg=None), True)])

    def parse324(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Modes
        if origin == None:
            return (None, [("onChannelModes", dict(origin=None, channel=None, modedelta=None), True)])
        modeparams = params.split()
        channame = modeparams.pop(0)
        channel = self.channel(channame)

        chanmodes = self.supports.get("CHANMODES", _defaultchanmodes)
        setmodes = modeparams.pop(0)
        modedelta = []
        for mode in setmodes:
            if mode == "+":
                continue
            elif mode in [2]:
                param = modeparams.pop(0)
                modedelta.append(("+%s" % mode, param))
            elif mode in chanmodes[3]:
                modedelta.append(("+%s" % mode, None))
        return (self.addons + channel.addons, [("onChannelModes", dict(origin=origin, channel=channel, modedelta=modedelta), True)])

    def parse329(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel created
        if origin == None:
            return (None, [("onChanCreated", dict(origin=None, channel=None, created=None), True)])
        channame, created = params.split()
        created = int(created)
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onChanCreated", dict(origin=origin, channel=channel, created=created), True)])

    def parse332(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Topic
        if origin == None:
            return (None, [("onTopic", dict(origin=None, channel=None, topic=None), True)])
        channame = params
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onTopic", dict(origin=origin, channel=channel, topic=extinfo), True)])

    def parse333(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Topic info
        if origin == None:
            return (None, [("onTopicInfo", dict(origin=None, channel=None, topicsetby=None, topictime=None), True)])
        (channame, nick, dt) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onTopicInfo", dict(origin=origin, channel=channel, topicsetby=nick, topictime=int(dt)), True)])

    def parse352(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # WHO reply
        if origin == None:
            return (None, [("onWhoEntry", dict(origin=None, channel=None, user=None, channame=None, username=None, host=None, serv=None, nick=None, flags=None, hops=None, realname=None), True)])
        (channame, username, host, serv, nick, flags) = params.split()
        try:
            (hops, realname) = extinfo.split(" ", 1)
        except ValueError:
            hops = extinfo
            realname = None

        chantypes = self.supports.get("CHANTYPES", _defaultchantypes)
        if re.match(_chanmatch % re.escape(chantypes), channame):
            channel = self.channel(channame)
        else:
            channel = None

        user = self.user(nick)

        if type(channel) == Channel:
            return (self.addons + channel.addons, [("onWhoEntry", dict(origin=origin, channel=channel, user=user, channame=channame, username=username, host=host, serv=serv, nick=nick, flags=flags, hops=int(hops), realname=realname), True)])
        else:
            return (self.addons, [("onWhoEntry", dict(origin=origin, channel=channel, user=user, channame=channame, username=username, host=host, serv=serv, nick=nick, flags=flags, hops=int(hops), realname=realname), True)])

    def parse315(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # End of WHO reply
        if origin == None:
            return (None, [("onWhoEnd", dict(origin=None, param=None, endmsg=None), True)])
        chantypes = self.supports.get("CHANTYPES", _defaultchantypes)
        if re.match(_chanmatch % re.escape(chantypes), params):
            channel = self.channel(params)
            return (self.addons + channel.addons, [("onWhoEnd", dict(origin=origin, param=params, endmsg=extinfo), True)])
        else:
            return (self.addons, [("onWhoEnd", dict(origin=origin, param=params, endmsg=extinfo), True)])

    def parse353(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # NAMES reply
        if origin == None:
            return (None, [("onNames", dict(origin=None, channel=None, flag=None, channame=None, nameslist=None), True)])
        (flag, channame) = params.split()
        channel = self.channel(channame)

        if self.supports.has_key("PREFIX"):
            names = re.findall(r"([%s]*)([^@!\s]+)(?:!(\S+)@(\S+))?" %
                               re.escape(self.supports["PREFIX"][1]), extinfo)
        else:
            names = re.findall(r"()([^@!\s]+)(?:!(\S+)@(\S+))?", extinfo)
                               # Still put it into tuple form for compatibility
                               # in the next structure
        return (self.addons + channel.addons, [("onNames", dict(origin=origin, channel=channel, flag=flag, channame=channame, nameslist=names), True)])

    def parse366(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # End of NAMES reply
        if origin == None:
            return (None, [("onNamesEnd", dict(origin=None, channel=None, channame=None, endmsg=None), True)])
        channel = self.channel(params)
        return (self.addons + channel.addons, [("onNamesEnd", dict(origin=origin, channel=channel, channame=params, endmsg=extinfo), True)])

    def parse372(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # MOTD line
        return (self.addons, [("onMOTDLine", dict(origin=origin, motdline=extinfo), True)])
        self.motd.append(extinfo)

    def parse375(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Begin MOTD
        return (self.addons, [("onMOTDStart", dict(origin=origin, motdgreet=extinfo), True)])

    def parse376(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        return (self.addons, [("onMOTDEnd", dict(origin=origin, motdend=extinfo), True)])

    def parseNICK(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])

        if origin == None:
            return (None, [
                    ("onNickChange", dict(user=None, newnick=None), True),
                    ("onMeNickChange", dict(newnick=None), False)
                    ])

        newnick = extinfo if len(extinfo) else target

        addons = reduce(
            lambda x, y: x + y, [channel.addons for channel in origin.channels if self.identity in channel.users], [])

        if origin == self.identity:
            return (self.addons + addons, [
                    ("onNickChange", dict(user=origin, newnick=newnick), True),
                    ("onMeNickChange", dict(newnick=newnick), False)
                    ])
        return (self.addons + addons, [("onNickChange", dict(user=origin, newnick=newnick), True)])

    def parseJOIN(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])

        if origin == None:
            return (None, [
                    ("onMeJoin", dict(channel=None), False),
                    ("onJoin", dict(user=None, channel=None), True)
                    ])

        if type(target) == Channel:
            channel = target
        else:
            channel = self.channel(extinfo)
            channel.name = extinfo

        if origin == self.identity:
            return (self.addons + channel.addons, [
                    ("onMeJoin", dict(channel=channel), False),
                    ("onJoin", dict(user=origin, channel=channel), True),
                    ])

        return (self.addons + channel.addons, [("onJoin", dict(user=origin, channel=channel), True)])

    def parseKICK(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])
        if origin == None:
            return (None, [
                    ("onMeKick", dict(channel=None, kicked=None, kickmsg=None), True),
                    ("onMeKicked", dict(
                        kicker=None, channel=None, kickmsg=None), True),
                    ("onKick", dict(kicker=None, channel=None, kicked=None, kickmsg=None), True)
                    ])
        events = []
        if origin == self.identity:
            events.append(
                ("onMeKick", dict(channel=target, kicked=kicked, kickmsg=extinfo), False))

        kicked = self.user(params)
        if kicked.nick != params:
            kicked.nick = params

        if kicked == self.identity:
            events.append(
                ("onMeKicked", dict(kicker=origin, channel=target, kickmsg=extinfo), False))

        events.append(
            ("onKick", dict(kicker=origin, channel=target, kicked=kicked, kickmsg=extinfo), True))
        return (self.addons + target.addons, events)

        if target in kicked.channels:
            kicked.channels.remove(target)
        if kicked in target.users:
            target.users.remove(kicked)
        if self.supports.has_key("PREFIX"):
            for mode in self.supports["PREFIX"][0]:
                if target.modes.has_key(mode) and kicked in target.modes[mode]:
                    target.modes[mode].remove(kicked)

    def parsePART(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])
        if origin == None:
            return (None, [
                    ("onMePart", dict(channel=None, partmsg=None), True),
                    ("onPart", dict(user=None, channel=None, partmsg=None), True)
                    ])
        if origin == self.identity:
            return (self.addons + target.addons, [
                    ("onMePart", dict(channel=target, partmsg=extinfo), False),
                    ("onPart", dict(user=origin, channel=target, partmsg=extinfo), True)
                    ])
        else:
            return (self.addons + target.addons, [("onPart", dict(user=origin, channel=target, partmsg=extinfo), True)])

    def parseQUIT(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])
        if origin == None:
            return (None, [("onQuit", dict(user=None, quitmsg=None), True)])

        # Include addons for channels that both user and bot are in
        # simultaneously.
        addons = reduce(
            lambda x, y: x + y, [channel.addons for channel in origin.channels if self.identity in channel.users], [])
        return (self.addons + addons, [("onQuit", dict(user=origin, quitmsg=extinfo), True)])

    def parseMODE(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])
        if origin == None:
            events = [
                ("onChanModeSet", dict(
                    user=None, channel=None, modedelta=None), True),
                ("onUserModeSet", dict(origin=None, modedelta=None), True)
            ]
            for (mode, (setname, unsetname)) in _maskmodeeventnames.items():
                events.append(
                    ("on%s" % setname, dict(user=None, channel=None, banmask=None), False))
                events.append(
                    ("onMe%s" % setname, dict(user=None, channel=None, banmask=None), False))
                events.append(
                    ("on%s" % unsetname, dict(user=None, channel=None, banmask=None), False))
                events.append(
                    ("onMe%s" % unsetname, dict(user=None, channel=None, banmask=None), False))
            for (mode, (setname, unsetname)) in _privmodeeventnames.items():
                events.append(
                    ("on%s" % setname, dict(user=None, channel=None, modeuser=None), False))
                events.append(
                    ("onMe%s" % setname, dict(user=None, channel=None), False))
                events.append(
                    ("on%s" % unsetname, dict(user=None, channel=None, banmask=None), False))
                events.append(
                    ("onMe%s" % unsetname, dict(user=None, channel=None), False))
            return (None, events)
        if type(target) == Channel:
            events = []
            modedelta = []
            modeparams = params.split()
            setmodes = modeparams.pop(0)
            modeset = "+"
            chanmodes = self.supports.get("CHANMODES", _defaultchanmodes)
            prefix = self.supports.get("PREFIX", _defaultprefix)
            for mode in setmodes:
                if mode in "+-":
                    modeset = mode
                else:
                    if mode in chanmodes[0] + chanmodes[1]:
                        param = modeparams.pop(0)
                        modedelta.append(("%s%s" % (modeset, mode), param))
                        if mode in _maskmodeeventnames.keys():
                            if modeset == "+":
                                eventname = _maskmodeeventnames[mode][0]
                                if mode == "k":
                                    target.key = param
                            if modeset == "-":
                                eventname = _maskmodeeventnames[mode][1]
                                if mode == "k":
                                    target.key = None
                            matchesbot = glob.fnmatch.fnmatch(
                                "%s!%s@%s".lower() % (self.identity.nick, self.identity.username, self.identity.host), param.lower())
                            events.append(
                                ("on%s" % eventname, dict(user=origin, channel=target, banmask=param), False))
                            if matchesbot:
                                events.append(
                                    ("onMe%s" % eventname, dict(user=origin, channel=target, banmask=param), False))
                    elif mode in chanmodes[2]:
                        if modeset == "+":
                            param = modeparams.pop(0)
                            modedelta.append(("%s%s" % (modeset, mode), param))
                        else:
                            modedelta.append(("%s%s" % (modeset, mode), None))
                    elif mode in chanmodes[3]:
                        modedelta.append(("%s%s" % (modeset, mode), None))
                    elif mode in prefix[0]:
                        modenick = modeparams.pop(0)
                        modeuser = self.user(modenick)
                        if mode in _privmodeeventnames.keys():
                            if modeset == "+":
                                eventname = _privmodeeventnames[mode][0]
                            if modeset == "-":
                                eventname = _privmodeeventnames[mode][1]
                            events.append(
                                ("on%s" % eventname, dict(user=origin, channel=target, modeuser=modeuser), False))
                            if modeuser == self.identity:
                                events.append(
                                    ("onMe%s" % eventname, dict(user=origin, channel=target), False))
                        modedelta.append(("%s%s" % (modeset, mode), modeuser))
            events.append(
                ("onChanModeSet", dict(user=origin, channel=target, modedelta=modedelta), True))
            return (self.addons + target.addons, events)
        elif target == self.identity:
            modeparams = (params if params else extinfo).split()
            setmodes = modeparams.pop(0)
            modedelta = []
            modeset = "+"
            for mode in setmodes:
                if mode in "+-":
                    modeset = mode
                    continue
                if modeset == "+":
                    if mode == "s":
                        if len(modeparams):
                            snomask = modeparams.pop(0)
                            snomaskdelta = []
                            snomodeset = "+"
                            for snomode in snomask:
                                if snomode in "+-":
                                    snomodeset = snomode
                                    continue
                                snomaskdelta.append(
                                    "%s%s" % (snomodeset, snomode))
                            modedelta.append(("+s", snomaskdelta))
                        else:
                            modedelta.append(("+s", []))
                    else:
                        modedelta.append(("+%s" % mode, None))
                if modeset == "-":
                    modedelta.append(("-%s" % mode, None))
            return (self.addons, [("onUserModeSet", dict(origin=origin, modedelta=modedelta), True)])

    def parseTOPIC(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])
        if origin == None:
            return (None, [("onTopicSet", dict(user=None, channel=None, topic=None), True)])
        return (self.addons + target.addons, [("onTopicSet", dict(user=origin, channel=target, topic=extinfo), True)])

    def parseINVITE(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            return ([], [])
        if origin == None:
            return (None, [("onInvite", dict(user=None, channel=None), True)])
        channel = self.channel(extinfo if extinfo else params)
        return (self.addons + channel.addons, [("onInvite", dict(user=origin, channel=channel), True)])

    def parsePRIVMSG(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            ctcp = re.findall(_ctcpmatch, extinfo)
            if ctcp:
                (ctcptype, ext) = ctcp[0]
                if type(target) == User:
                    if ctcptype.upper() == "ACTION":
                        return (self.addons, [("onSendPrivAction", dict(origin=origin, user=target, action=ext), True)])
                    return (self.addons, [("onSendCTCP", dict(origin=origin, user=target, ctcptype=ctcptype, params=ext), True)])
                elif type(target) == Channel:
                    if ctcptype.upper() == "ACTION":
                        return (self.addons, [("onSendChanAction", dict(origin=origin, channel=target, targetprefix=targetprefix, action=ext), True)])
                    return (self.addons, [("onSendChanCTCP", dict(origin=origin, channel=target, targetprefix=targetprefix, ctcptype=ctcptype, params=ext), True)])
            else:
                if type(target) == User:
                    return (self.addons, [("onSendPrivMsg", dict(origin=origin, user=target, msg=extinfo), True)])
                elif type(target) == Channel:
                    return (self.addons + target.addons, [("onSendChanMsg", dict(origin=origin, channel=target, targetprefix=targetprefix, msg=extinfo), True)])
        if origin == None:
            return (None, [
                    ("onPrivMsg", dict(user=None, msg=None), True),
                    ("onChanMsg", dict(user=None, channel=None, targetprefix=None, msg=None), True),
                    ("onCTCP", dict(user=None, ctcptype=None, params=None), True),
                    ("onChanCTCP", dict(user=None, channel=None,
                     targetprefix=None, ctcptype=None, params=None), True),
                    ("onPrivAction", dict(user=None, action=None), True),
                    ("onChanAction", dict(
                        user=None, channel=None, targetprefix=None, action=None), True),
                    ("onSendPrivMsg", dict(
                        origin=None, user=None, msg=None), True),
                    ("onSendChanMsg", dict(
                        origin=None, channel=None, targetprefix=None, msg=None), True),
                    ("onSendCTCP", dict(origin=None, user=None, ctcptype=None, params=None), True),
                    ("onSendPrivAction", dict(
                        origin=None, user=None, action=None), True),
                    ("onSendChanAction", dict(
                        origin=None, channel=None, targetprefix=None, action=None), True),
                    ("onSendChanCTCP", dict(origin=None, channel=None,
                     targetprefix=None, ctcptype=None, params=None), True),
                    ])
        ctcp = re.findall(_ctcpmatch, extinfo)
        if ctcp:
            (ctcptype, ext) = ctcp[0]
            if target == self.identity:
                if ctcptype.upper() == "ACTION":
                    return (self.addons, [("onPrivAction", dict(user=origin, action=ext), True)])
                return (self.addons, [("onCTCP", dict(user=origin, ctcptype=ctcptype, params=ext), True)])
            if type(target) == Channel:
                if ctcptype.upper() == "ACTION":
                    return (self.addons, [("onChanAction", dict(user=origin, channel=target, targetprefix=targetprefix, action=ext), True)])
                return (self.addons, [("onChanCTCP", dict(user=origin, channel=target, targetprefix=targetprefix, ctcptype=ctcptype, params=ext), True)])
        else:
            if type(target) == Channel:
                return (self.addons + target.addons, [("onChanMsg", dict(user=origin, channel=target, targetprefix=targetprefix, msg=extinfo), True)])
            elif target == self.identity:
                return (self.addons, [("onPrivMsg", dict(user=origin, msg=extinfo), True)])

    def parseNOTICE(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None, outgoing=False):
        if outgoing:
            ctcp = re.findall(_ctcpmatch, extinfo)
            if ctcp:
                (ctcptype, ext) = ctcp[0]
                return (self.addons, [("onSendCTCPReply", dict(origin=origin, ctcptype=ctcptype, params=ext), True)])
            else:
                if type(target) == Channel:
                    return (self.addons + target.addons, [("onSendChanNotice", dict(origin=origin, channel=target, targetprefix=targetprefix, msg=extinfo), True)])
                elif type(target) == User:
                    return (self.addons, [("onSendPrivNotice", dict(origin=origin, user=target, msg=extinfo), True)])
        if origin == None:
            return (None, [
                    ("onPrivNotice", dict(origin=None, msg=None), True),
                    ("onChanNotice", dict(
                        origin=None, channel=None, targetprefix=None, msg=None), True),
                    ("onCTCPReply", dict(
                        origin=None, ctcptype=None, params=None), True),
                    ("onSendPrivNotice", dict(origin=None, msg=None), True),
                    ("onSendChanNotice", dict(
                        origin=None, channel=None, targetprefix=None, msg=None), True),
                    ("onSendCTCPReply", dict(
                        origin=None, ctcptype=None, params=None), True),
                    ])
        ctcp = re.findall(_ctcpmatch, extinfo)
        # print ctcp
        if ctcp and target == self.identity:
            (ctcptype, ext) = ctcp[0]
            return (self.addons, [("onCTCPReply", dict(origin=origin, ctcptype=ctcptype, params=ext), True)])
        else:
            if type(target) == Channel:
                return (self.addons + target.addons, [("onChanNotice", dict(origin=origin, channel=target, targetprefix=targetprefix, msg=extinfo), True)])
            elif target == self.identity:
                # print "onPrivNotice"
                return (self.addons, [("onPrivNotice", dict(origin=origin, msg=extinfo), True)])

    def parse367(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Ban list
        if origin == None:
            return (None, [("onBanListEntry", dict(origin=None, channel=None, mask=None, setby=None, settime=None), True)])
        (channame, mask, setby, settime) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onBanListEntry", dict(origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime)), True)])

    def parse368(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        if origin == None:
            return (None, [("onBanListEnd", dict(origin=None, channel=None, endmsg=None), True)])
        channel = self.channel(params)
        return (self.addons + channel.addons, [("onBanListEnd", dict(origin=origin, channel=channel, endmsg=extinfo), True)])

    def parse346(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Invite list
        if origin == None:
            return (None, [("onInviteListEntry", dict(origin=None, channel=None, mask=None, setby=None, settime=None), True)])
        (channame, mask, setby, settime) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onInviteListEntry", dict(origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime)), True)])

    def parse347(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        if origin == None:
            return (None, [("onInviteListEnd", dict(origin=None, channel=None, endmsg=None), True)])
        channel = self.channel(params)
        return (self.addons + channel.addons, [("onInviteListEnd", dict(origin=origin, channel=channel, endmsg=extinfo), True)])

    def parse348(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Ban Exception list
        if origin == None:
            return (None, [("onBanExceptListEntry", dict(origin=None, channel=None, mask=None, setby=None, settime=None), True)])
        (channame, mask, setby, settime) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onBanExceptListEntry", dict(origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime)), True)])

    def parse349(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        if origin == None:
            return (None, [("onBanExceptListEnd", dict(origin=None, channel=None, endmsg=None), True)])
        channel = self.channel(params)
        return (self.addons + channel.addons, [("onBanExceptListEnd", dict(origin=origin, channel=channel, endmsg=extinfo), True)])

    def parse910(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel Access List
        if origin == None:
            return (None, [("onAccessListEntry", dict(origin=None, channel=None, mask=None, setby=None, settime=None), True)])
        (channame, mask, setby, settime) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onAccessListEntry", dict(origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime)), True)])

    def parse911(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        if origin == None:
            return (None, [("onAccessListEnd", dict(origin=None, channel=None, endmsg=None), True)])
        channel = self.channel(params)
        return (self.addons + channel.addons, [("onAccessListEnd", dict(origin=origin, channel=channel, endmsg=extinfo), True)])

    def parse941(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Spam Filter list
        if origin == None:
            return (None, [("onSpamfilterListEntry", dict(origin=None, channel=None, mask=None, setby=None, settime=None), True)])
        (channame, mask, setby, settime) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onSpamfilterListEntry", dict(origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime)), True)])

    def parse940(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        if origin == None:
            return (None, [("onSpamfilterListEnd", dict(origin=None, channel=None, endmsg=None), True)])
        channel = self.channel(params)
        return (self.addons + channel.addons, [("onSpamfilterListEnd", dict(origin=origin, channel=channel, endmsg=extinfo), True)])

    def parse954(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel exemptchanops list
        if origin == None:
            return (None, [("onExemptChanOpsListEntry", dict(origin=None, channel=None, mask=None, setby=None, settime=None), True)])
        (channame, mask, setby, settime) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onExemptChanOpsListEntry", dict(origin=origin, channel=channel, mask=mask, setby=setby, settime=int(settime)), True)])

    def parse953(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        if origin == None:
            return (None, [("onExemptChanOpsListEnd", dict(origin=None, channel=None, endmsg=None), True)])
        channel = self.channel(params)
        return (self.addons + channel.addons, [("onExemptChanOpsListEnd", dict(origin=origin, channel=channel, endmsg=extinfo), True)])

    def parse728(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):  # Channel quiet list
        if origin == None:
            return (None, [("onQuietListEntry", dict(origin=None, channel=None, modechar=None, mask=None, setby=None, settime=None), True)])
        (channame, modechar, mask, setby, settime) = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onQuietListEntry", dict(origin=origin, channel=channel, modechar=modechar, mask=mask, setby=setby, settime=int(settime)), True)])

    def parse729(self, origin=None, target=None, targetprefix=None, params=None, extinfo=None):
        if origin == None:
            return (None, [("onQuietListEnd", dict(channel=None, endmsg=None), True)])
        channame, modechar = params.split()
        channel = self.channel(channame)
        return (self.addons + channel.addons, [("onQuietListEnd", dict(channel=channel, endmsg=extinfo), True)])

    def eventsupports(self):
        supports = {}
        for item in dir(self):
            if re.match(r"parse(\d{3}|[A-Z]+)", item):
                parsemethod = getattr(self, item)
                addons, events = parsemethod()
                for (event, args, fallback) in events:
                    supports[event] = tuple(args.keys())
        supports.update({"onConnect": (),
                         "onRegistered": (),
                         "onConnectAttempt": (),
                         "onConnectFail": ("exc", "excmsg", "tb"),
                         "onSessionOpen": (),
                         "onSessionClose": (),
                         "onDisconnect": ("expected",),
                         "onOther": ("line", "origin", "cmd", "target", "targetprefix", "params", "extinfo"),
                         "onUnhandled": ("line", "origin", "cmd", "target", "targetprefix", "params", "extinfo"),
                         "onRecv": ("line", "origin", "cmd", "target", "targetprefix", "params", "extinfo"),
                         "onSend": ("line", "origin", "cmd", "target", "targetprefix", "params", "extinfo"),
                         })
        return supports

    # Here are the builtin event handlers.
    def onWelcome(self, context, origin, msg):
        self.welcome = msg  # Welcome message

    def onYourHost(self, context, origin, msg):
        self.hostinfo = msg  # Your Host

    def onServerCreated(self, context, origin, msg):
        self.servcreated = msg  # Server Created

    def onServInfo(self, context, origin, servinfo):
        self.servinfo = servinfo  # What is this code?

    def onSupports(self, context, origin, supports, msg):  # Server Supports
        protos = u" ".join(
            [proto for proto in self.protoctl if proto in supports.keys()])
        if protos:
            self._send(u"PROTOCTL {protos}".format(**vars()))
        self.supports.update(supports)

    def onSnoMask(self, context, origin, snomask):  # Snomask
        self.identity.snomask = snomask
        if "s" not in self.identity.modes:
            self.identity.snomask = ""

    def onUserModes(self, context, origin, modes):  # User Modes
        self.identity.modes = modes
        if "s" not in self.identity.modes:
            self.identity.snomask = ""

    def onNetStats(self, context, origin, netstats):  # Net Stats
        self.netstats = netstats

    def onOpCount(self, context, origin, opcount):
        self.opcount = opcount

    def onChanCount(self, context, origin, chancount):
        self.chancount = chancount

    def onReturn(self, identity, origin, msg):  # Returned from away status
        self.identity.away = False
        self.identity.awaymsg = None

    def onAway(self, identity, origin, msg):  # Entered away status
        self.identity.away = True
        self.identity.awaymsg = msg

    def onWhoisStart(self, context, origin, user, nickname, username, host, realname):  # Start of WHOIS data
        user.nick = nickname
        user.username = username
        user.host = host

    def onWhoisAway(self, context, origin, user, nickname, awaymsg):  # Away Message
        user.away = True
        user.awaymsg = awaymsg

    def onWhoisServer(self, context, origin, user, nickname, server, servername):  # Server
        user.server = server

    def onWhoisOp(self, context, origin, user, nickname, msg):  # IRC Op
        user.ircop = True
        user.ircopmsg = msg

    def onWhoisTimes(self, context, origin, user, nickname, idletime, signontime, msg):  # Idle and Signon times
        user.idlesince = int(time.time()) - idletime
        user.signontime = signontime

    def onWhoisSSL(self, context, origin, user, nickname, msg):  # SSL
        user.secure = True

    def onWhoisLoggedInAs(self, context, origin, user, nickname, loggedinas, msg):  # Logged in as
        user.loggedinas = loggedinas

    def onChannelModes(self, context, origin, channel, modedelta):  # Channel Modes
        chanmodes = self.supports.get("CHANMODES", _defaultchanmodes)
        for ((modeset, mode), param) in modedelta:
            if mode in chanmodes[2]:
                channel.modes[mode] = param
            elif mode in chanmodes[3]:
                channel.modes[mode] = True

    def onChanCreated(self, context, origin, channel, created):  # Channel created
        channel.created = created

    def onTopic(self, context, origin, channel, topic):  # Channel Topic
        channel.topic = topic

    def onTopicInfo(self, context, origin, channel, topicsetby, topictime):  # Channel Topic info
        channel.topicsetby = topicsetby
        channel.topictime = topictime

    def onWhoEntry(self, context, origin, channel, user, channame, username, host, serv, nick, flags, hops, realname):  # WHO reply
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
            for (mode, prefix) in zip(*self.supports.get("PREFIX", _defaultprefix)):
                if prefix in flags:
                    if mode in channel.modes.keys() and user not in channel.modes[mode]:
                        channel.modes[mode].append(user)
                    elif mode not in channel.modes.keys():
                        channel.modes[mode] = [user]

    def onNames(self, context, origin, channel, flag, channame, nameslist):  # NAMES reply
        for (symbs, nick, username, host) in nameslist:
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
                prefix = self.supports.get("PREFIX", _defaultprefix)
                for symb in symbs:
                    mode = prefix[0][prefix[1].index(symb)]
                    if not channel.modes.has_key(mode):
                        channel.modes[mode] = [user]
                    elif user not in channel.modes[mode]:
                        channel.modes[mode].append(user)

    def onMOTDLine(self, context, origin, motdline):  # MOTD line
        self.motd.append(motdline)

    def onMOTDStart(self, context, origin, motdgreet):  # Begin MOTD
        self.motdgreet = motdgreet
        self.motd = []

    def onMOTDEnd(self, context, origin, motdend):
        self.motdend = motdend  # End of MOTD

    # elif cmd==386 and "q" in self.supports["PREFIX"][0]: # Channel Owner (Unreal)
        #(channame,owner)=params.split()
        # channel=self.channel(channame)
        #self._event("onRecv", channel.addons, **data)
        # if channel.name!=channame: channel.name=channame ### Server seems to have changed the idea of the case of the channel name
        # user=self.user(owner)
        #if user.nick!=owner: user.nick=owner
        # if channel.modes.has_key("q"):
            #if user not in channel.modes["q"]: channel.modes["q"].append(user)
        # else: channel.modes["q"]=[user]

    # elif cmd==388 and "a" in self.supports["PREFIX"][0]: # Channel Admin (Unreal)
        #(channame,admin)=params.split()
        # channel=self.channel(channame)
        #self._event("onRecv", channel.addons, **data)
        # if channel.name!=channame: channel.name=channame ### Server seems to have changed the idea of the case of the channel name
        # user=self.user(admin)
        #if user.nick!=admin: user.nick=admin
        # if channel.modes.has_key("a"):
            #if user not in channel.modes["a"]: channel.modes["a"].append(user)
        # else: channel.modes["a"]=[user]

    def onNickChange(self, context, user, newnick):
        for other in self.users:
            if self.supports.get("CASEMAPPING", "rfc1459") == "ascii":
                collision = other.nick.lower() == newnick.lower()
            else:
                collision = other.nick.translate(
                    _rfc1459casemapping) == newnick.translate(_rfc1459casemapping)
            if collision:
                self.users.remove(
                    other)  # Nick collision, safe to assume this orphaned user is offline, so we shall remove the old instance.
                for channel in self.channels:
                    # If for some odd reason, the old user still appears common
                    # channels, then we will remove the user anyway.
                    if other in channel.users:
                        channel.users.remove(other)
        user.nick = newnick

    def onJoin(self, context, user, channel):
        if channel not in user.channels:
            user.channels.append(channel)
        if user not in channel.users:
            channel.users.append(user)

    def onMeJoin(self, context, channel):
        channel._init()
        with channel._joining:
            if channel._joinrequested:
                channel._joinreply = "JOIN"
                channel._joining.notify()
        self._send(u"MODE %s" % channel.name)
        self._send(u"WHO %s" % channel.name)
        self._send(u"MODE %s :%s" %
                   (channel.name, self.supports.get("CHANMODES", _defaultchanmodes)[0]))

    def onKick(self, context, kicker, channel, kicked, kickmsg):
        if channel in kicked.channels:
            kicked.channels.remove(channel)
        if kicked in channel.users:
            channel.users.remove(kicked)
        prefix = self.supports.get("PREFIX", _defaultprefix)
        for mode in prefix[0]:
            if mode in channel.modes.keys() and kicked in channel.modes[mode]:
                channel.modes[mode].remove(kicked)

    def onPart(self, context, user, channel, partmsg):
        if channel in user.channels:
            user.channels.remove(channel)
        if user in channel.users:
            channel.users.remove(user)
        prefix = self.supports.get("PREFIX", _defaultprefix)
        for mode in prefix[0]:
            if mode in channel.modes.keys() and user in channel.modes[mode]:
                channel.modes[mode].remove(user)

    def onMePart(self, context, channel, partmsg):
        with channel._parting:
            if channel._partrequested:
                channel._partreply = "PART"
                channel._parting.notify()

    def onMeKicked(self, context, kicker, channel, kickmsg):
        with channel._parting:
            if channel._partrequested:
                channel._partreply = "KICK"
                channel._parting.notify()

    def onQuit(self, context, user, quitmsg):
        channels = list(user.channels)
        for channel in channels:
            with channel.lock:
                if user in channel.users:
                    channel.users.remove(user)
                prefix = self.supports.get("PREFIX", _defaultprefix)
                for mode in prefix[0]:
                    if mode in channel.modes.keys() and user in channel.modes[mode]:
                        channel.modes[mode].remove(user)
        user._init()

    def onChanModeSet(self, context, user, channel, modedelta):
        chanmodes = self.supports.get("CHANMODES", _defaultchanmodes)
        prefix = self.supports.get("PREFIX", _defaultprefix)
        with channel.lock:
            for ((modeset, mode), param) in modedelta:
                if mode in chanmodes[0] + prefix[0]:
                    if mode not in channel.modes.keys():
                        channel.modes[mode] = []
                if mode in chanmodes[0]:
                    if modeset == "+":
                        if param.lower() not in [mask.lower() for (mask, setby, settime) in channel.modes[mode]]:
                            channel.modes[mode].append(
                                (param, user, int(time.time())))
                    else:
                        if mode == "b":  # Inspircd mode is case insentive when unsetting the mode
                            masks = [mask.lower()
                                     for (mask, setby, settime) in channel.modes[mode]]
                            if param.lower() in masks:
                                index = masks.index(param.lower())
                                del channel.modes[mode][index]
                        else:
                            masks = [
                                mask for (mask, setby, settime) in channel.modes[mode]]
                            if param in masks:
                                index = masks.index(param)
                                del channel.modes[mode][index]
                elif mode in chanmodes[1]:
                    if modeset == "+":
                        channel.modes[mode] = param
                    else:
                        channel.modes[mode] = None
                elif mode in chanmodes[2]:
                    if modeset == "+":
                        channel.modes[mode] = param
                    else:
                        channel.modes[mode] = None
                elif mode in chanmodes[3]:
                    if modeset == "+":
                        channel.modes[mode] = True
                    else:
                        channel.modes[mode] = False
                elif mode in prefix[0]:
                    if modeset == "+":
                        if param not in channel.modes[mode]:
                            channel.modes[mode].append(param)
                    elif param in channel.modes[mode]:
                        channel.modes[mode].remove(param)

    def onUserModeSet(self, context, origin, modedelta):
        for ((modeset, mode), param) in modedelta:
            if modeset == "+":
                if mode not in self.identity.modes:
                    self.identity.modes += mode
                if mode == "s":
                    for snomodeset, snomode in param:
                        if snomodeset == "+" and snomode not in self.identity.snomask:
                            self.identity.snomask += snomode
                        if snomodeset == "-" and snomode in self.identity.snomask:
                            self.identity.snomask = self.identity.snomask.replace(
                                snomode, "")
            if modeset == "-":
                if mode in self.identity.modes:
                    self.identity.modes = self.identity.modes.replace(mode, "")
                if mode == "s":
                    self.identity.snomask = ""

    def onTopicSet(self, context, user, channel, topic):
        with channel.lock:
            channel.topic = topic
            channel.topicsetby = user
            channel.topictime = int(time.time())

    def onCTCP(self, context, user, ctcptype, params):
        if ctcptype.upper() == "VERSION":
            user.ctcpreply("VERSION", self.ctcpversion())
        elif ctcptype.upper() == "TIME":
            tformat = time.ctime()
            tz = time.tzname[0]
            user.ctcpreply("TIME", "%(tformat)s %(tz)s" % vars())
        elif ctcptype.upper() == "PING":
            user.ctcpreply("PING", params)
        elif ctcptype.upper() == "FINGER":
            user.ctcpreply("FINGER", params)

    def onChanCTCP(self, context, user, channel, targetprefix, ctcptype, params):
        self.onCTCP(context, user, ctcptype, params)

    def onBanListEntry(self, context, origin, channel, mask, setby, settime):  # Channel Ban list
        if "b" not in channel.modes.keys():
            channel.modes["b"] = []
        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["b"]]:
            channel.modes["b"].append((mask, setby, int(settime)))

    def onInviteListEntry(self, context, origin, channel, mask, setby, settime):  # Channel Invite Exception list
        if "I" not in channel.modes.keys():
            channel.modes["I"] = []
        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["I"]]:
            channel.modes["I"].append((mask, setby, int(settime)))

    def onBanExceptListEntry(self, context, origin, channel, mask, setby, settime):  # Channel Invite Exception list
        if "e" not in channel.modes.keys():
            channel.modes["e"] = []
        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["e"]]:
            channel.modes["e"].append((mask, setby, int(settime)))

    def onAccessListEntry(self, context, origin, channel, mask, setby, settime):  # Channel Invite Exception list
        if "w" not in channel.modes.keys():
            channel.modes["w"] = []
        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["w"]]:
            channel.modes["w"].append((mask, setby, int(settime)))

    def onSpamfilterListEntry(self, context, origin, channel, mask, setby, settime):  # Channel Invite Exception list
        if "g" not in channel.modes.keys():
            channel.modes["g"] = []
        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["g"]]:
            channel.modes["g"].append((mask, setby, int(settime)))

    def onExemptChanOpsListEntry(self, context, origin, channel, mask, setby, settime):  # Channel Invite Exception list
        if "X" not in channel.modes.keys():
            channel.modes["X"] = []
        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes["X"]]:
            channel.modes["X"].append((mask, setby, int(settime)))

    def onQuietListEntry(self, context, origin, channel, modechar, mask, setby, settime):  # Channel quiet list (Freenode)
        if modechar not in channel.modes.keys():
            channel.modes[modechar] = []
        if mask.lower() not in [m.lower() for (m, s, t) in channel.modes[modechar]]:
            channel.modes[modechar].append((mask, setby, int(settime)))

    def onOther(self, context, line, origin, cmd, target, targetprefix, params, extinfo):
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

    # elif cmd in (495, 384, 385, 386, 468, 470, 366, 315, 482, 484, 953, 368, 482, 349, 940, 911, 489, 490, 492, 520, 530): # Channels which appear in params
        # for param in params.split():
            # if len(param) and param[0] in self.supports["CHANTYPES"]:
                # channel=self.channel(param)
                #self._event("onRecv", channel.addons, **data)

    def _trynick(self):
        (q, s) = divmod(self.trynick, len(self.nick)
                        if type(self.nick) in (list, tuple) else 1)
        nick = self.nick[s] if type(self.nick) in (list, tuple) else self.nick
        if q > 0:
            nick = "%s%d" % (nick, q)
        self._send(u"NICK %s" % nick)
        self.trynick += 1

    def _send(self, line, origin=None, T=None):
        with self.lock:
            if not self.connected:
                raise NotConnected
        if "\r" in line or "\n" in line:
            raise InvalidCharacter
        if type(line) == str:
            line = autodecode(line)
        cmd = line.split(" ")[0].upper()

        if T == None:
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

    def _cancelsend(self, line, origin=None, T=None):
        with self._sendline:
            self._outgoing.remove((T, line, origin))
            self._sendline.notify()

    def _procsendline(self, line, origin=None):
        match = re.findall(_ircmatch, line)
        if len(match) == 0:
            return
        (null, username, host, cmd, target, params, extinfo) = match[0]
        cmd = cmd.upper()
        with self.lock:
            if cmd == "QUIT":
                self._quitexpected = True
            if self._connection == None:
                return
            origline = line

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

                #ctcp=re.findall(_ctcpmatch, extinfo)
                # if ctcp:
                    #(ctcptype,ext)=ctcp[0]
                    # if ctcptype.upper()=="ACTION":
                        # if type(target)==Channel:
                            #self._event("onSendChanAction", self.addons+target.addons, origin=origin, channel=target, targetprefix=targetprefix, action=ext)
                        # elif type(target)==User:
                            #self._event("onSendPrivAction", self.addons, origin=origin, user=target, action=ext)
                    # else:
                        # if type(target)==Channel:
                            #self._event("onSendChanCTCP", self.addons+target.addons, origin=origin, channel=target, targetprefix=targetprefix, ctcptype=ctcptype, params=ext)
                        # elif type(target)==User:
                            #self._event("onSendPrivCTCP", self.addons, origin=origin, user=target, ctcptype=ctcptype, params=ext)
                # else:
                    # if type(target)==Channel:
                        #self._event("onSendChanMsg", self.addons+target.addons, origin=origin, channel=target, targetprefix=targetprefix, msg=extinfo)
                    # elif type(target)==User:
                        #self._event("onSendPrivMsg", self.addons, origin=origin, user=target, msg=extinfo)
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

            prefix = self.supports.get("PREFIX", _defaultprefix)
            chantypes = self.supports.get("CHANTYPES", _defaultchantypes)
            chanmatch = re.findall(_targchanmatch %
                                   (re.escape(prefix[1]), re.escape(chantypes)), target)

            # Check to see if target matches a channel (optionally with prefix)
            if chanmatch:
                targetprefix, channame = chanmatch[0]
                target = self.channel(channame)
                if target.name != channame:
                    # Target channel name has changed
                    target.name = channame
            # Check to see if target matches a valid nickname. Do NOT convert
            # target to User instance if cmd is NICK.
            elif re.match(_nickmatch, target) and cmd != "NICK":
                targetprefix = ""
                target = self.user(target)

            # Otherwise, target is just left as a string
            else:
                targetprefix = ""

            parsename = ("parse%03d" if type(cmd) == int else "parse%s") % cmd
            if hasattr(self, parsename):
                parsemethod = getattr(self, parsename)
                if callable(parsemethod):
                    try:
                        addons, events = parsemethod(
                            origin, target, targetprefix, params, extinfo, outgoing=True)
                    except:
                        exc, excmsg, tb = sys.exc_info()

                        # Print to log AND stderr
                        tblines = [
                            u"!!! There was an error in parsing the following line:", u"!!! %s" % line]
                        for tbline in traceback.format_exc().split("\n"):
                            tblines.append(u"!!! %s" % autodecode(tbline))
                        self.logwrite(*tblines)
                        print >>sys.stderr, u"There was an error in parsing the following line:"
                        print >>sys.stderr, u"%s" % line
                        print >>sys.stderr, traceback.format_exc()
                        return
            else:
                addons = self.addons
                if type(cmd) == unicode:
                    events = [(
                        "onSend%s" % cmd.upper(), dict(line=line, origin=origin if origin else self,
                                                       target=target, targetprefix=targetprefix, params=params, extinfo=extinfo), True)]
                else:
                    events = []
            if addons == None:
                addons = []

            if cmd not in ("PING", "PONG") or not self.quietpingpong:  # Supress pings and pongs if self.quietpingpong is set to True
                self._event(
                    addons + [self], [("onSend", dict(origin=origin if origin else self, line=line, cmd=cmd, target=target, targetprefix=targetprefix, params=params, extinfo=extinfo), False)], line)
                self._event(addons + [self], events, line)

            if not (cmd in ("PING", "PONG") and self.quietpingpong):
                #self._event(self.addons, [("onSend" , dict(origin=origin, line=line, cmd=cmd, target=target, params=params, extinfo=extinfo), False)])
                self.logwrite(">>> %s" % line)
            self._connection.send("%s\n" % origline.encode('utf8'))

    def _sendhandler(self):
        # Enforce that this function must only be run from within
        # self._sendhandlerthread.
        if currentThread() != self._sendhandlerthread:
            raise RuntimeError, "This function is designed to run in its own thread."

        try:
            while True:
                with self._sendline:
                    if "quit" in self._outgoing:
                        sys.exit()
                    S = time.time()
                    if len(self._outgoing):
                        T, line, origin = min(self._outgoing)
                        if T > S:
                            # The next item in the queue (by time) is still
                            # scheduled to be sent later. We wait until then,
                            # or when another item is put into the queue,
                            # whichever is first.
                            self._sendline.wait(T - S)
                            continue
                        else:
                            # The next item in the queue (by time) should be
                            # sent now.
                            self._outgoing.remove((T, line, origin))
                    else:
                        # The queue is empty, so we will wait until something
                        # is put into the queue, then restart the while loop.
                        self._sendline.wait()
                        continue

                try:
                    self._procsendline(line, origin=origin)
                except socket.error:
                    exc, excmsg, tb = sys.exc_info()
                    with self.lock:
                        self.logwrite(
                            u"*** Connection to {self:uri} failed: {excmsg}.".format(**vars()))
                        self._event(self.getalladdons(), [
                                    ("onConnectFail", dict(exc=exc, excmsg=excmsg, tb=tb), False)])
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
            tblines = [u"!!! FATAL Exception"]
            for line in traceback.format_exc().split("\n"):
                tblines.append(u"!!! %s" % autodecode(line))
            self.logwrite(*tblines)
            print >>sys.stderr, "FATAL Exception in {self}".format(**vars())
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
        if self.ipver == socket.AF_INET6 and ":" in server:
            server = "[%s]" % server
        if self.identity:
            return "<IRC Context: {self.identity:full} on {self:uri}>".format(**locals())
        else:
            return "<IRC Context: *!*@* on {self:uri}>".format(**locals())

    def __format__(self, fmt):
        port = self.port if self.port is not None else 6697 if self.secure else 6667
        if fmt == "uri":
            ssl = "s" if self.secure else ""
            proto = "6" if self.ipver == socket.AF_INET6 else ""
            if self.ipver == socket.AF_INET6 and ":" in self.server:
                return "irc{ssl}{proto}://[{self.server}]:{port}".format(**locals())
            else:
                return "irc{ssl}{proto}://{self.server}:{port}".format(**locals())

    def oper(self, name, passwd, origin=None):
        if re.match(".*[\n\r\\s]", name) or re.match(".*[\n\r\\s]", passwd):
            raise InvalidCharacter
        self._send(u"OPER {name} {passwd}".format(**vars()), origin=origin)

    def list(self, params="", origin=None):
        if re.match(".*[\n\r\\s]", params):
            raise InvalidCharacter
        if params:
            self._send(u"LIST {params}".format(**vars()), origin=origin)
        else:
            self._send(u"LIST", origin=origin)

    def getmotd(self, target="", origin=None):
        if re.match(".*[\n\r\\s]", name) or re.match(".*[\n\r\\s]", passwd):
            raise InvalidCharacter
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self._send(u"MOTD %s" %
                       (re.findall("^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self._send(u"MOTD", origin=origin)

    def version(self, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self._send(u"VERSION %s" %
                       (re.findall("^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self._send(u"VERSION", origin=origin)

    def stats(self, query, target="", origin=None):
        if len(re.findall("^([^\r\n\\s]*)", target)[0]):
            self._send(u"STATS %s %s" %
                       (query, re.findall("^([^\r\n\\s]*)", target)[0]), origin=origin)
        else:
            self._send(u"STATS %s" % query, origin=origin)

    # Quit IRC session gracefully
    def quit(self, msg="", origin=None, blocking=False):
        if "\r" in msg or "\n" in msg:
            raise InvalidCharacter
        if msg:
            self._send(u"QUIT :%s" % msg, origin=origin)
        else:
            self._send(u"QUIT", origin=origin)
        if blocking:
            with self._disconnecting:
                while self.connected:
                    self._disconnecting.wait()
                self._recvhandlerthread.join()
                self._sendhandlerthread.join()

    # Force disconnect -- Not even sending QUIT to server.
    def disconnect(self):
        with self.lock:
            self._quitexpected = True
            self._connection.shutdown(2)

    def ctcpversion(self):
        reply = []
        # Prepare reply for this module
        reply.append(
            u"{self.__name__} {self.__version__}, {self.__author__}".format(**vars()))

        # Prepare reply for Python and OS versions
        pyver = sys.version.split("\n")
        pyver[0] = "Python " + pyver[0]
        reply.extend(pyver)
        reply.extend(platform.platform().split("\n"))

        # Prepare reply for each addons
        for addon in self.addons:
            try:
                if hasattr(addon, "__extinfo__"):
                    reply.append(
                        u"{addon.__name__} {addon.__version__}, {addon.__extinfo__}".format(**vars()))
                else:
                    reply.append(
                        u"{addon.__name__} {addon.__version__}".format(**vars()))
            except:
                pass
        return u"; ".join(reply)

    def raw(self, line, origin=None):
        self._send(line, origin=origin)

    def user(self, nick, init=False):
        if type(nick) == str:
            nick = autodecode(nick)
        if self.supports.get("CASEMAPPING", "rfc1459") == "ascii":
            users = [
                user for user in self.users if user.nick.lower() == nick.lower()]
        else:
            users = [user for user in self.users if user.nick.translate(
                _rfc1459casemapping) == nick.translate(_rfc1459casemapping)]
        if len(users):
            if init:
                users[0]._init()
            return users[0]
        else:
            user = User(nick, self)
            self.users.append(user)
            timestamp = reduce(lambda x, y: x + ":" + y, [
                               str(t).rjust(2, "0") for t in time.localtime()[0:6]])
            return user

    def channel(self, name, init=False):
        if type(name) == str:
            name = autodecode(name)
        if self.supports.get("CASEMAPPING", "rfc1459") == "ascii":
            channels = [
                chan for chan in self.channels if chan.name.lower() == name.lower()]
        else:
            channels = [chan for chan in self.channels if chan.name.translate(
                _rfc1459casemapping) == name.translate(_rfc1459casemapping)]
        if len(channels):
            if init:
                channels[0]._init()
            return channels[0]
        else:
            timestamp = reduce(lambda x, y: x + ":" + y, [
                               str(t).rjust(2, "0") for t in time.localtime()[0:6]])
            chan = Channel(name, self)
            self.channels.append(chan)
            return chan

    def __getitem__(self, item):
        chantypes = self.supports.get("CHANTYPES", _defaultchantypes)
        if re.match(_chanmatch % re.escape(chantypes), item):
            return self.channel(item)
        elif re.match(_usermatch, item):
            return self.user(item)
        else:
            raise TypeError, "String argument does not match valid channel name or nick name."

    def fmtsupports(self):
        supports = [
            "CHANMODES=%s" % (",".join(value)) if name == "CHANMODES" else "PREFIX=(%s)%s" %
            value if name == "PREFIX" else "%s=%s" % (name, value) if value else name for name, value in self.supports.items()]
        supports.sort()
        supports = " ".join(supports)
        lines = []
        while len(supports) > 196:
            index = supports.rfind(" ", 0, 196)
            slice = supports[:index]
            lines.append(
                u":{self.serv} 005 {self.identity.nick} {slice} :are supported by this server".format(**vars()))
            supports = supports[index + 1:]
        if supports:
            lines.append(
                u":{self.serv} 005 {self.identity.nick} {supports} :are supported by this server".format(**vars()))
        return lines

    def fmtgreeting(self):
        # Prepare greeting (Responses 001 through 004)
        lines = []
        if self.welcome:
            lines.append(
                u":{self.serv} 001 {self.identity.nick} :{self.welcome}".format(**vars()))
        if self.hostinfo:
            lines.append(
                u":{self.serv} 002 {self.identity.nick} :{self.hostinfo}".format(**vars()))
        if self.servcreated:
            lines.append(
                u":{self.serv} 003 {self.identity.nick} :{self.servcreated}".format(**vars()))
        if self.servinfo:
            lines.append(
                u":{self.serv} 004 {self.identity.nick} {self.servinfo}".format(**vars()))
        return lines

    def fmtusermodes(self):
        # Prepars 221 response
        return u":{self.serv} 221 {self.identity.nick} +{self.identity.modes}".format(**vars())

    def fmtsnomasks(self):
        # Prepare 008 response
        return u":{self.serv} 008 {self.identity.nick} +{self.identity.snomask} :Server notice mask".format(**vars())

    def fmtmotd(self):
        if self.motdgreet and self.motd and self.motdend:
            lines = []
            lines.append(
                u":{self.serv} 375 {self.identity.nick} :{self.motdgreet}".format(**vars()))
            for motdline in self.motd:
                lines.append(
                    u":{self.serv} 372 {self.identity.nick} :{motdline}".format(**vars()))
            lines.append(
                u":{self.serv} 376 {self.identity.nick} :{self.motdend}".format(**vars()))
            return lines
        else:
            return [u":{self.serv} 422 {self.identity.nick} :MOTD File is missing".format(**vars())]


class Channel(object):

    def __init__(self, name, context, key=None):
        chantypes = context.supports.get("CHANTYPES", _defaultchantypes)
        if not re.match(_chanmatch % re.escape(chantypes), name):
            raise InvalidName, repr(name)
        self.name = name
        self.context = context
        self.key = key
        self.lock = Lock()
        self._init()
        self._joining = Condition(self.lock)
        self._parting = Condition(self.lock)
        self._joinrequested = False
        self._joinreply = None
        self._partrequested = False
        self._partreply = None

    def _init(self):
        for user in self.context.users:
            if self in user.channels:
                user.channels.remove(self)
        self.addons = []
        self.topic = ""
        self.topicsetby = ""
        self.topictime = None
        self.topicmod = ""
        self.modes = {}
        self.users = UserList(context=self.context)
        self.created = None

    def msg(self, msg, target="", origin=None):
        if target and target not in self.context.supports.get("PREFIX", ("ohv", "@%+"))[1]:
            raise InvalidPrefix
        for line in re.findall("([^\r\n]+)", msg):
            self.context._send(u"PRIVMSG %s%s :%s" %
                               (target, self.name, line), origin=origin)

    def who(self, origin=None, blocking=False):
        # Send WHO request to server
        self.context._send(u"WHO %s" % (self.name), origin=origin)

    def fmtwho(self):
        # Create WHO reply from current data. TODO
        pass

    def names(self, origin=None):
        self.context._send(u"NAMES %s" % (self.name), origin=origin)

    def fmtnames(self, sort=None, uhnames=False, namesx=False):
        # Create NAMES reply from current data.
        secret = "s" in self.modes.keys() and self.modes["s"]
        private = "p" in self.modes.keys() and self.modes["p"]
        flag = "@" if secret else ("*" if private else "=")

        modes, symbols = self.context.supports.get("PREFIX", ("ohv", "@%+"))
        users = list(self.users)
        if sort == "mode":
            users.sort(key=lambda user: ([user not in self.modes.get(mode, [])
                       for mode, char in zip(*self.context.supports.get("PREFIX", ("ohv", "@%+")))], user.nick.lower()))
        elif sort == "nick":
            users.sort(key=lambda user: user.nick.lower())
        if uhnames:
            template = u"{prefixes}{user:full}"
        else:
            template = u"{prefixes}{user}"

        nameslist = []
        for user in users:
            prefixes = u"".join(
                [prefix if mode in self.modes.keys() and user in self.modes[mode] else "" for prefix, mode in zip(symbols, modes)])
            if not namesx:
                prefixes = prefixes[:1]
            nameslist.append(template.format(**vars()))
        names = " ".join(nameslist)

        lines = []
        while len(names) > 196:
            index = names.rfind(" ", 0, 196)
            slice = names[:index]
            lines.append(
                u":{self.context.identity.server} 353 {self.context.identity.nick} {flag} {self.name} :{slice}".format(**vars()))
            names = names[index + 1:]
        if len(names):
            lines.append(
                u":{self.context.identity.server} 353 {self.context.identity.nick} {flag} {self.name} :{names}".format(**vars()))

        lines.append(
            u":{self.context.identity.server} 366 {self.context.identity.nick} {self.name} :End of /NAMES list.".format(**vars()))
        return lines

    def fmttopic(self):
        # Prepares 332 and 333 responses
        if self.topic and self.topictime:
            response332 = u":{self.context.identity.server} 332 {self.context.identity.nick} {self.name} :{self.topic}".format(
                **vars())
            if type(self.topicsetby) == User:
                response333 = u":{self.context.identity.server} 333 {self.context.identity.nick} {self.name} {self.topicsetby.nick} {self.topictime}".format(
                    **vars())
            else:
                response333 = u":{self.context.identity.server} 333 {self.context.identity.nick} {self.name} {self.topicsetby} {self.topictime}".format(
                    **vars())
            return [response332, response333]
        else:
            return [u":{self.context.identity.server} 331 {self.context.identity.nick} {self.name} :No topic is set".format(**vars())]

    def fmtchancreated(self):
        # Prepares 329 responses
        return u":{self.context.identity.server} 329 {self.context.identity.nick} {self.name} {self.created}".format(**vars())

    def fmtmodes(self):
        items = self.modes.items()
        chanmodes = self.context.supports.get("CHANMODES", _defaultchanmodes)
        modes = "".join(
            [mode for (mode, val) in items if mode not in chanmodes[0] + self.context.supports["PREFIX"][0] and val])
        params = " ".join(
            [val for (mode, val) in items if mode in chanmodes[1] + chanmodes[2] and val])
        if modes and params:
            return u":{self.context.identity.server} 324 {self.context.identity.nick} {self.name} +{modes} {params}".format(**vars())
        elif modes:
            return u":{self.context.identity.server} 324 {self.context.identity.nick} {self.name} +{modes}".format(**vars())
        else:
            return None

    def notice(self, msg, target="", origin=None):
        if target and target not in self.context.supports.get("PREFIX", ("ohv", "@%+"))[1]:
            raise InvalidPrefix
        for line in re.findall("([^\r\n]+)", msg):
            self.context._send(u"NOTICE %s%s :%s" %
                               (target, self.name, line), origin=origin)

    def settopic(self, msg, origin=None):
        self.context._send(u"TOPIC %s :%s" %
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
                        u"PART %s :%s" % (self.name, re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
                else:
                    self.context._send(u"PART %s" % self.name, origin=origin)

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
                        elif self._partreply in ("PART", "KICK"):
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
        self.context._send(u"INVITE %s %s" %
                           (nickname, self.name), origin=origin)

    def join(self, key="", blocking=False, timeout=30, origin=None):
        with self.context.lock:
            if self.context.identity in self.users:
                # Bot is already on the channel
                raise AlreadyJoined
            if not self.context.connected:
                raise NotConnected
        with self._joining:
            try:
                if self._joinrequested:
                    raise ActionAlreadyRequested
                self._joinrequested = True
                if len(re.findall("^([^\r\n\\s]*)", key)[0]):
                    self.context._send(
                        u"JOIN %s %s" % (self.name, re.findall("^([^\r\n\\s]*)", key)[0]), origin=origin)
                else:
                    self.context._send(u"JOIN %s" % self.name, origin=origin)

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
            self.context._send(u"KICK %s %s :%s" %
                               (self.name, nickname, re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.context._send(u"KICK %s %s" %
                               (self.name, nickname), origin=origin)

    def __repr__(self):
        return u"<Channel: {self.name} on {self.context:uri}>".format(**vars())

    def __contains__(self, item):
        return item in self.users

    def __format__(self, fmt):
        return self.name

    def json(self):
        return self.name


class User(object):

    def __init__(self, nick, context):
        if not re.match(_nickmatch, nick):
            raise InvalidName
        self.nick = nick
        self.context = context
        self._init()

    def _init(self):
        self.username = ""
        self.host = ""
        self.channels = ChanList(context=self.context)
        self.modes = ""
        self.snomask = ""
        self.server = None
        self.hops = None
        self.ircop = False
        self.ircopmsg = ""
        self.idlesince = None
        self.signontime = None
        self.secure = None
        self.away = None

    def __repr__(self):
        return (u"<User: %(nick)s!%(username)s@%(host)s>" % vars(self)).encode("utf8")

    def __format__(self, fmt):
        if fmt == "full":
            return u"{self.nick}!{self.username}@{self.host}".format(**locals())
        else:
            return self.nick

    def msg(self, msg, origin=None):
        for line in re.findall("([^\r\n]+)", msg):
            self.context._send(u"PRIVMSG %s :%s" %
                               (self.nick, line), origin=origin)

    def notice(self, msg, origin=None):
        for line in re.findall("([^\r\n]+)", msg):
            self.context._send(u"NOTICE %s :%s" %
                               (self.nick, line), origin=origin)

    def ctcp(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.msg(u"\01%s %s\01" %
                     (act.upper(), re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.msg(u"\01%s\01" % act.upper())

    def ctcpreply(self, act, msg="", origin=None):
        if len(re.findall("^([^\r\n]*)", msg)[0]):
            self.notice("\01%s %s\01" %
                        (act.upper(), re.findall("^([^\r\n]*)", msg)[0]), origin=origin)
        else:
            self.notice("\01%s\01" % act.upper(), origin=origin)

    def me(self, msg="", origin=None):
        self.ctcp("ACTION", msg, origin=origin)

    def json(self):
        return self.nick


class Config(object):

    def __init__(self, addon, **kwargs):
        self.addon = addon
        self.__dict__.update(kwargs)

    def json(self):
        if "onAddonAdd" in dir(self.addon) and type(self.addon.onAddonAdd) == new.instancemethod:
            conf = OrderedDict(addon=self.addon)
            try:
                arginspect = inspect.getargspec(self.addon.onAddonAdd)
            except:
                raise TypeError(
                    repr(self.addon.onAddonAdd) + " is not JSON serializable")

            if arginspect.defaults:
                requiredargs = arginspect.args[
                    2:len(arginspect.args) - len(arginspect.defaults)]
                argswithdefaults = arginspect.args[
                    len(arginspect.args) - len(arginspect.defaults):]
                defaultvalues = arginspect.defaults
            else:
                requiredargs = arginspect.args[2:]
                argswithdefaults = []
                defaultvalues = []

            for key in requiredargs:
                try:
                    conf[key] = getattr(self, key)
                except AttributeError:
                    print key
                    raise TypeError(
                        repr(self) + " is not JSON serializable (Cannot recover required argument '%s')" % key)

            for key, default in zip(argswithdefaults, defaultvalues):
                try:
                    value = getattr(self, key)
                    if value != default:
                        conf[key] = getattr(self, key)
                except AttributeError:
                    pass
            return conf
        else:
            return self.addon


class ChanList(list):

    def __init__(self, iterable=None, context=None):
        if context != None and type(context) != Connection:
            raise TypeError, "context must be irc.Connection object or None"
        self.context = context
        if iterable:
            chanlist = []
            for channel in iterable:
                if type(channel) == Channel:
                    chanlist.append(channel)
                elif type(channel) in (str, unicode):
                    if context == None:
                        raise ValueError, "No context given for string object."
                    chanlist.append(context.channel(channel))
            list.__init__(self, chanlist)
        else:
            list.__init__(self)

    def append(self, item):
        if type(item) in (str, unicode):
            if self.context:
                list.append(self, self.context.channel(item))
                return
            else:
                raise ValueError, "No context given for string object."
        if type(item) != Channel:
            raise TypeError, "Only channel objects are permitted in list"
        if self.context and item.context != self.context:
            raise ValueError, "Channel object does not belong to context."
        list.append(self, item)

    def insert(self, index, item):
        if type(item) in (str, unicode):
            if self.context:
                list.insert(self, index, self.context.channel(item))
                return
            else:
                raise ValueError, "No context given for string object."
        if type(item) != Channel:
            raise TypeError, "Only channel objects are permitted in list"
        if self.context and item.context != self.context:
            raise ValueError, "Channel object does not belong to context."
        list.insert(self, index, item)

    def extend(self, iterable):
        chanlist = []
        for item in iterable:
            if type(item) in (str, unicode):
                if self.context:
                    chanlist.append(self.context.channel(item))
                    return
                else:
                    raise ValueError, "No context given for string object."
            if type(item) != Channel:
                raise TypeError, "Only channel objects are permitted in list"
            if self.context and item.context != self.context:
                raise ValueError, "Channel object does not belong to context."
            chanlist.append(item)
        list.extend(self, chanlist)

    def join(self, origin=None):
        if not self.context:
            raise ValueError, "No context defined."
        if any([channel.key for channel in self]):
            self.context._send(u"JOIN %s %s" %
                               (self, ",".join([channel.key if channel.key else "" for channel in self])), origin=origin)
        else:
            self.context._send(u"JOIN %s" % self, origin=origin)

    def part(self, partmsg=None, origin=None):
        if not self.context:
            raise ValueError, "No context defined."
        if partmsg:
            self.context._send(u"PART %s :%s" %
                               (",".join([channel.name for channel in self]), partmsg), origin=origin)
        else:
            self.context._send(u"PART %s" % self, origin=origin)

    def msg(self, msg, origin=None):
        if not self.context:
            raise ValueError, "No context defined."
        self.context._send(u"PRIVMSG %s :%s" % (self, msg), origin=origin)

    def __str__(self):
        return ",".join([channel.name for channel in self])


class UserList(list):

    def __init__(self, iterable=None, context=None):
        if context != None and type(context) != Connection:
            raise TypeError, "context must be irc.Connection object or None"
        self.context = context
        if iterable:
            userlist = []
            for user in iterable:
                if type(user) == User:
                    userlist.append(user)
                elif type(user) in (str, unicode):
                    if context == None:
                        raise ValueError, "No context given for string object."
                    userlist.append(context.user(user))
            list.__init__(self, userlist)
        else:
            list.__init__(self)

    def append(self, item):
        if type(item) in (str, unicode):
            if self.context:
                list.append(self, self.context.user(item))
                return
            else:
                raise ValueError, "No context given for string object."
        if type(item) != User:
            raise TypeError, "Only user objects are permitted in list"
        if self.context and item.context != self.context:
            raise ValueError, "User object does not belong to context."
        list.append(self, item)

    def insert(self, index, item):
        if type(item) in (str, unicode):
            if self.context:
                list.insert(self, index, self.context.user(item))
                return
            else:
                raise ValueError, "No context given for string object."
        if type(item) != User:
            raise TypeError, "Only user objects are permitted in list"
        if self.context and item.context != self.context:
            raise ValueError, "User object does not belong to context."
        list.insert(self, index, item)

    def extend(self, iterable):
        userlist = []
        for item in iterable:
            if type(item) in (str, unicode):
                if self.context:
                    userlist.append(self.context.user(item))
                    return
                else:
                    raise ValueError, "No context given for string object."
            if type(item) != User:
                raise TypeError, "Only user objects are permitted in list"
            if self.context and item.context != self.context:
                raise ValueError, "User object does not belong to context."
            userlist.append(item)
        list.extend(self, userlist)

    def msg(self, msg, origin=None):
        if not self.context:
            raise ValueError, "No context defined."
        self.context._send(u"PRIVMSG %s :%s" % (self, msg), origin=origin)

    def __str__(self):
        return ",".join([user.nick for user in self])


class Server(object):

    def __init__(self, name, context):
        self.name = name
        self.context = context
        self.lock = Lock()
        self._init()

    def _init(self):
        self.stats = {}
        self.users = UserList(context=self.context)
        self.created = None
        self.motdgreet = None
        self.motd = []
        self.motdend = None
