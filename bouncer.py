#!/usr/bin/python
import socket
import ssl
import os
import re
import time
import sys
import string
import hashlib
import traceback
import irc
import getpass
from threading import Thread, Lock
import Queue
import chardet

# TODO: Rewrite this *entire* module and make more efficient.


def BouncerReload(BNC):
    if BNC.isAlive():
        BNC.stop()
    if BNC.__version__ == "1.2":
        newBNC = Bouncer(
            addr=BNC.addr, port=BNC.port, ssl=BNC.ssl, ipv6=BNC.ipv6,
            certfile=BNC.certfile, keyfile=BNC.keyfile, timeout=BNC.timeout, autoaway=BNC.autoaway)
        for label, (context, passwd, hashtype) in BNC.servers.items():
            context.rmAddon(BNC)
            context.addAddon(
                newBNC, label=label, passwd=passwd, hashtype=hashtype)
    else:
        newBNC = Bouncer(**BNC.__options__)
        for context, conf in BNC.conf.items():
            context.rmAddon(BNC)
            context.addAddon(newBNC, **conf.__dict__)
    return newBNC


class Bouncer (Thread):

    def __init__(self, addr="", port=16667, ssl=False, ipv6=False, certfile=None, keyfile=None, ignore=None, debug=False, timeout=300, autoaway=None):
        self.__name__ = "Bouncer for pyIRC"
        self.__version__ = "1.3"
        self.__author__ = "Brian Sherson"
        self.__date__ = "February 9, 2014"
        self.__options__ = dict(
            addr=addr, port=port, ssl=ssl, ipv6=ipv6, certfile=certfile,
            keyfile=keyfile, ignore=ignore, debug=debug, timeout=timeout, autoaway=autoaway)

        self.addr = addr
        self.port = port
        self.conf = {}
        self.passwd = {}
        self.socket = socket.socket(
            socket.AF_INET6 if ipv6 else socket.AF_INET)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssl = ssl
        self.ipv6 = ipv6
        self.certfile = certfile
        self.keyfile = keyfile
        self.socket.bind((self.addr, self.port))
        self.connections = []
        self.ignore = ignore
        self.debug = debug
        self.timeout = timeout
        self.autoaway = autoaway
        self._stopexpected = False

        # Keep track of what extensions/connections are requesting WHO, WHOIS, and LIST, because we don't want to spam every bouncer connection with the server's replies.
        # In the future, MAY implement this idea in the irc module.
        self._whoexpected = {}
        self._whoisexpected = {}
        self._listexpected = {}
        self.lock = Lock()
        self.starttime = int(time.time())
        Thread.__init__(self)
        self.daemon = True
        self.start()

    def __repr__(self):
        return "<Bouncer listening on port %(addr)s:%(port)s>" % vars(self)

    def run(self):
        self.socket.listen(5)
        #print ((self,"Now listening on port "+str(self.port)))
        while True:
            try:
                (connection, addr) = self.socket.accept()
                if self.ssl:
                    connection = ssl.wrap_socket(
                        connection, server_side=True, certfile=self.certfile, keyfile=self.keyfile, ssl_version=ssl.PROTOCOL_SSLv23)
                #print ((self,"New client connecting from %s:%s"%addr))
            except socket.error:
                # print "Shutting down Listener"
                self.socket.close()
                if not self._stopexpected:
                    raise
                sys.exit()
            except:
                tb = traceback.format_exc()
                print >>sys.stderr, tb
                continue
            connection.settimeout(self.timeout)
            bouncer = BouncerConnection(
                self, connection, addr, debug=self.debug)
            time.sleep(0.5)
        try:
            self.socket.close()
        except:
            pass

    def onAddonAdd(self, context, label, passwd=None, hashtype="sha512", ignore=None, autoaway=None, translations=None, hidden=None):
        for (context2, conf2) in self.conf.items():
            if context == context2:
                raise ValueError, "Context already exists in config."
            if label == conf2.label:
                raise ValueError, "Unique label required."
        if passwd == None:
            while True:
                passwd = getpass.getpass("Enter new password: ")
                if passwd == getpass.getpass("Confirm new password: "):
                    break
                print "Passwords do not match!"
            passwd = hashlib.new(hashtype, passwd).hexdigest()
        conf = irc.Config(
            label=label, passwd=passwd, hashtype=hashtype, ignore=ignore, autoaway=autoaway,
            translations={} if translations == None else translations, hidden=irc.ChanList(hidden, context=context))
        self.conf[context] = conf
        self._whoexpected[context] = []
        if self.debug:
            context.logwrite(
                "dbg [Bouncer.onAddonAdd] Clearing WHO expected list." % vars())
        self._whoisexpected[context] = []
        self._listexpected[context] = []

    def onAddonRem(self, context):
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                bouncerconnection.quit(quitmsg="Bouncer extension removed")
        del self.conf[context]
        del self._whoexpected[context], self._whoisexpected[
            context], self._listexpected[context]

    def stop(self):
        self._stopexpected = True
        self.socket.shutdown(0)

    def disconnectall(self, quitmsg="Disconnecting all sessions"):
        for bouncerconnection in self.connections:
            bouncerconnection.quit(quitmsg=quitmsg)

    def onDisconnect(self, context, expected=False):
        self._whoexpected[context] = []
        self._whoisexpected[context] = []
        self._listexpected[context] = []
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                #bouncerconnection.quit(quitmsg="context connection lost")
                if context.identity:
                    for channel in context.identity.channels:
                        bouncerconnection.send(":%s!%s@%s PART %s :Bouncer Connection Lost\n" % (
                            context.identity.nick, context.identity.username, context.identity.host, channel.name))
                    bouncerconnection.send(":%s!%s@%s QUIT :Bouncer Connection Lost\n" % (
                        context.identity.nick, context.identity.username, context.identity.host))
                bouncerconnection.send(
                    ":*Bouncer* NOTICE %s :Connection to %s:%s has been lost.\n" %
                    (bouncerconnection.nick, context.server, context.port))

    def onQuit(self, context, user, quitmsg):
        # For some odd reason, certain networks (*cough*Freenode*cough*) will send a quit message for the user, causing context.identity.channels to be cleared
        # before onDisconnect can be executed. This is the remedy.
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                if quitmsg:
                    bouncerconnection.send(":%s!%s@%s QUIT :%s\n" % (
                        user.nick, user.username, user.host, quitmsg))
                else:
                    bouncerconnection.send(
                        ":%s!%s@%s QUIT\n" % (user.nick, user.username, user.host))
                if user == context.identity:
                    for channel in context.identity.channels:
                        bouncerconnection.send(":%s!%s@%s PART %s :Bouncer Connection Lost\n" % (
                            context.identity.nick, context.identity.username, context.identity.host, channel.name))

    def onConnectAttempt(self, context):
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                bouncerconnection.send(
                    ":*Bouncer* NOTICE %s :Attempting connection to %s:%s.\n" %
                    (bouncerconnection.nick, context.server, context.port))

    def onConnect(self, context):
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                bouncerconnection.send(
                    ":*Bouncer* NOTICE %s :Connection to %s:%s established.\n" %
                    (bouncerconnection.nick, context.server, context.port))

    def onMeNickChange(self, context, newnick):
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                bouncerconnection.send(":%s!%s@%s NICK %s\n" %
                                       (context.identity.nick, context.identity.username, context.identity.host, newnick))
                bouncerconnection.nick = newnick

    def onNickChange(self, context, user, newnick):
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                bouncerconnection.send(":%s!%s@%s NICK %s\n" %
                                       (user.nick, user.username, user.host, newnick))
                bouncerconnection.nick = newnick

    def onRegistered(self, context):
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                if bouncerconnection.nick != context.identity.nick:
                    bouncerconnection.send(":%s!%s@%s NICK %s\n" % (
                        bouncerconnection.nick, bouncerconnection.username, bouncerconnection.host, context.identity.nick))
                    bouncerconnection.nick = context.identity.nick

    def onConnectFail(self, context, exc, excmsg, tb):
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context:
                bouncerconnection.send(
                    ":*Bouncer* NOTICE %s :Connection to %s:%s failed: %s.\n" %
                    (bouncerconnection.nick, context.server, context.port, excmsg))

    def onSendChanMsg(self, context, origin, channel, targetprefix, msg):
        # Called when bot sends a PRIVMSG to channel.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        conf = self.conf[context]
        if channel in conf.translations.keys():
            channame = conf.translations[channel]
        else:
            channame = channel.name
        for bouncerconnection in self.connections:
            if context == bouncerconnection.context and origin != bouncerconnection and channel not in bouncerconnection.hidden:
                bouncerconnection.send(":%s!%s@%s PRIVMSG %s%s :%s\n" % (
                    context.identity.nick, context.identity.username, context.identity.host, targetprefix, channame, msg))

    def onSendChanAction(self, context, origin, channel, targetprefix, action):
        self.onSendChanMsg(
            context, origin, channel, targetprefix, "\x01ACTION %s\x01" % action)

    def onSendChanNotice(self, context, origin, channel, targetprefix, msg):
        # Called when bot sends a NOTICE to channel.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        conf = self.conf[context]
        if channel in conf.translations.keys():
            channame = conf.translations[channel]
        else:
            channame = channel.name
        for bouncerconnection in self.connections:
            if context == bouncerconnection.context and origin != bouncerconnection:
                bouncerconnection.send(":%s!%s@%s NOTICE %s%s :%s\n" %
                                       (context.identity.nick, context.identity.username, context.identity.host, targetprefix, channame, msg))

    def onSend(self, context, origin, line, cmd, target, params, extinfo):
        if cmd.upper() == "WHO":
            self._whoexpected[context].append(origin)
            if self.debug:
                if issubclass(type(origin), Thread):
                    name = origin.name
                    context.logwrite(
                        "dbg [Bouncer.onSend] Adding %(origin)s (%(name)s) to WHO expected list." % vars())
                else:
                    context.logwrite(
                        "dbg [Bouncer.onSend] Adding %(origin)s to WHO expected list." % vars())
                context.logwrite(
                    "dbg [Bouncer.onSend] WHO expected list size: %d" % len(self._whoexpected[context]))
        elif cmd.upper() == "WHOIS":
            self._whoisexpected[context].append(origin)
        elif cmd.upper() == "LIST":
            self._listexpected[context].append(origin)

    def onWhoEntry(self, context, origin, channel, user, channame, username, host, serv, nick, flags, hops, realname):
        # Called when a WHO list is received.
        conf = self.conf[context]
        if context.channel(channame) in conf.translations.keys():
            channame = conf.translations[context.channel(channame)]
        if len(self._whoexpected[context]) and self._whoexpected[context][0] in self.connections:
            bncconnection = self._whoexpected[context][0]
            bncconnection.send(":%s 352 %s %s %s %s %s %s %s :%s %s\n" %
                               (origin, context.identity.nick, channame, username, host, serv, nick, flags, hops, realname))

    def onWhoEnd(self, context, origin, param, endmsg):
        # Called when a WHO list is received.
        try:
            conf = self.conf[context]
            chantypes = context.supports.get("CHANTYPES", "&#+!")
            if re.match(irc._chanmatch % re.escape(chantypes), param) and context[param] in conf.translations.keys():
                param = conf.translations[context.channel(param)]
        except:
            pass
        if len(self._whoexpected[context]) and self._whoexpected[context][0] in self.connections:
            bncconnection = self._whoexpected[context][0]
            bncconnection.send(":%s 315 %s %s :%s\n" %
                               (origin, context.identity.nick, param, endmsg))
        if self.debug:
            if issubclass(type(self._whoexpected[context][0]), Thread):
                name = self._whoexpected[context][0].name
                context.logwrite(
                    "dbg [Bouncer.onWhoEnd] Removing %s (%s) from WHO expected list." %
                    (self._whoexpected[context][0], name))
            else:
                context.logwrite(
                    "dbg [Bouncer.onWhoEnd] Removing %s from WHO expected list." % self._whoexpected[context][0])
        del self._whoexpected[context][0]
        if self.debug:
            context.logwrite(
                "dbg [Bouncer.onWhoEnd] WHO expected list size: %d" %
                len(self._whoexpected[context]))

    def onListStart(self, context, origin, params, extinfo):
        # Called when a WHO list is received.
        if len(self._listexpected[context]) and self._listexpected[context][0] in self.connections:
            bncconnection = self._listexpected[context][0]
            bncconnection.send(":%s 321 %s %s :%s\n" %
                               (origin, context.identity.nick, params, extinfo))

    def onListEntry(self, context, origin, channel, population, extinfo):
        # Called when a WHO list is received.
        conf = self.conf[context]
        if channel in conf.translations.keys():
            channame = conf.translations[channel]
        else:
            channame = channel.name
        if len(self._listexpected[context]) and self._listexpected[context][0] in self.connections:
            bncconnection = self._listexpected[context][0]
            bncconnection.send(":%s 322 %s %s %d :%s\n" %
                               (origin, context.identity.nick, channame, population, extinfo))

    def onListEnd(self, context, origin, endmsg):
        # Called when a WHO list is received.
        if len(self._listexpected[context]) and self._listexpected[context][0] in self.connections:
            bncconnection = self._listexpected[context][0]
            bncconnection.send(":%s 323 %s :%s\n" %
                               (origin, context.identity.nick, endmsg))
        del self._listexpected[context][0]

    def onWhoisStart(self, context, origin, user, nickname, username, host, realname):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]):
            if self._whoisexpected[context][0] in self.connections:
                bncconnection = self._whoisexpected[context][0]
                bncconnection.send(":%s 311 %s %s %s %s * :%s\n" %
                                   (origin, context.identity.nick, nickname, username, host, realname))

    def onWhoisRegisteredNick(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 307 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, msg))

    def onWhoisConnectingFrom(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 378 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, msg))

    def onWhoisChannels(self, context, origin, user, nickname, chanlist):
        # Called when a WHOIS reply is received.
        # TODO: Translations implementation
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 319 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, " ".join(chanlist)))

    def onWhoisAvailability(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 310 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, msg))

    def onWhoisServer(self, context, origin, user, nickname, server, servername):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 312 %s %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, server, servername))

    def onWhoisOp(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 313 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, msg))

    def onWhoisAway(self, context, origin, user, nickname, awaymsg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 301 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, awaymsg))

    def onWhoisTimes(self, context, origin, user, nickname, idletime, signontime, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 317 %s %s %d %d :%s\n" %
                               (origin, context.identity.nick, nickname, idletime, signontime, msg))

    def onWhoisSSL(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 671 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, msg))

    def onWhoisModes(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 339 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, msg))

    def onWhoisLoggedInAs(self, context, origin, user, nickname, loggedinas, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 330 %s %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, loggedinas, msg))

    def onWhoisEnd(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.connections:
            bncconnection = self._whoisexpected[context][0]
            bncconnection.send(":%s 318 %s %s :%s\n" %
                               (origin, context.identity.nick, nickname, msg))
        del self._whoisexpected[context][0]

    def onJoin(self, context, user, channel):
        conf = self.conf[context]
        if channel in conf.translations.keys():
            channame = conf.translations[channel]
        else:
            channame = channel.name
        line = ":%s!%s@%s JOIN %s" % (
            user.nick, user.username, user.host, channame)
        for bouncerconnection in self.connections:
            if bouncerconnection.context == context and channel not in bouncerconnection.hidden:
                bouncerconnection.send("%s\n" % line)

    def onUnhandled(self, context, line, origin, cmd, target, params, extinfo, targetprefix):
        conf = self.conf[context]

        if type(origin) == irc.User:
            origin = "%s!%s@%s" % (origin.nick, origin.username, origin.host)

        if target in conf.translations.keys():
            target = conf.translations[target]

        chantarg = None

        if type(target) == irc.User:
            target = target.nick
        elif type(target) == irc.Channel:
            chantarg = target
            target = target.name

        if params:  # Channels which appear in params
            oldparams = params
            params = []
            for param in oldparams.split():
                chantypes = context.supports.get("CHANTYPES", "&#+!")
                if re.match(irc._chanmatch % re.escape(chantypes), param) and context[param] in conf.translations.keys():
                    params.append(conf.translations[context[param]])
                else:
                    params.append(param)

        if target:
            if type(cmd) == int:
                cmd = "%03d" % cmd
            if params and extinfo:
                line = ":%s %s %s %s :%s" % (
                    origin, cmd, target, " ".join(params), extinfo)
            elif params:
                line = ":%s %s %s %s" % (origin, cmd, target, " ".join(params))
            elif extinfo:
                line = ":%s %s %s :%s" % (origin, cmd, target, extinfo)
            else:
                line = ":%s %s %s" % (origin, cmd, target)

        for bouncerconnection in self.connections:
            if bouncerconnection.context == context and chantarg not in bouncerconnection.hidden:
                bouncerconnection.send("%s\n" % line)


class BouncerConnection (Thread):

    def __init__(self, bouncer, connection, addr, debug=False):
        # print "Initializing ListenThread..."
        self.bouncer = bouncer
        self.connection = connection
        self.host, self.port = self.addr = addr[:2]
        self.context = None
        self.pwd = None
        self.nick = None
        self.label = None
        self.username = None
        self.realname = None
        self.addr = addr
        self.debug = debug
        self.lock = Lock()
        self.quitmsg = "Connection Closed"
        self.quitting = False
        self.hidden = irc.ChanList()

        Thread.__init__(self)
        self.daemon = True
        self.start()

    def send(self, data, flags=0):
        try:
            with self.lock:
                self.connection.send(data.encode("utf8"))
        except socket.error:
            exc, excmsg, tb = sys.exc_info()
            print >>self.context.logwrite(*["!!! [BouncerConnection.send] Exception in thread %(self)s" % vars()] + [
                                          "!!! [BouncerConnection.send] %(tbline)s" % vars() for tbline in traceback.format_exc().split("\n")])
            self.quit(quitmsg=excmsg.message)

    def __repr__(self):
        server = self.context.server if self.context else "*"
        port = self.context.port if self.context else "*"
        if self.context and self.context.identity:
            nick = self.context.identity.nick
            ident = self.context.identity.username if self.context.identity.username else "*"
            host = self.context.identity.host if self.context.identity.host else "*"
        else:
            nick = "*"
            ident = "*"
            host = "*"
        if self.context.ssl and self.context.ipv6:
            protocol = "ircs6"
        elif self.context.ssl:
            protocol = "ircs"
        elif self.context.ipv6:
            protocol = "irc6"
        else:
            protocol = "irc"
        addr = self.host
        return "<Bouncer connection from %(addr)s to %(nick)s!%(ident)s@%(host)s on %(protocol)s://%(server)s:%(port)s>" % locals()

    def quit(self, quitmsg="Disconnected"):
        if not self.quitting:
            self.quitmsg = quitmsg
            with self.lock:
                try:
                    self.connection.send("ERROR :Closing link: (%s@%s) [%s]\n" % (
                        self.context.identity.nick if self.context else "*", self.host, quitmsg))
                except:
                    pass
                try:
                    self.connection.shutdown(socket.SHUT_WR)
                    self.connection.close()
                except:
                    pass
                self.quitting = True

    def run(self):
        # Name loopup should happen here instead
        ipv4match = re.findall(
            r"^::ffff:((\d+)\.(\d+)\.(\d+)\.(\d+))$", self.host)
        if self.bouncer.ipv6 and ipv4match:
            addr, a, b, c, d = ipv4match[0]
            if max(int(a), int(b), int(c), int(d)) < 256:
                self.host = addr
                self.ipv6 = False
        elif self.bouncer.ipv6:
            self.ipv6 = True
        try:
            self.host, aliaslist, addresslist = socket.gethostbyaddr(self.host)
            self.addr = (self.host, addr[1])
        except:
            pass

        # Add connection to connection list.

        listnumerics = dict(b=(367, 368, "channel ban list"),
                            e=(348, 349, "Channel Exception List"),
                            I=(346, 347, "Channel Invite Exception List"),
                            w=(910, 911, "Channel Access List"),
                            g=(941, 940, "chanel spamfilter list"),
                            X=(954, 953, "channel exemptchanops list"))

        passwd = None
        nick = None
        user = None
        addr = self.host

        readbuf = ""
        linebuf = []

        try:
            while True:
                # Read data (appending) into readbuf, then break lines and
                # append lines to linebuf
                while len(linebuf) == 0:
                    timestamp = irc.timestamp()
                    read = self.connection.recv(512)
                    if read == "" and len(linebuf) == 0:  # No more data to process.
                        #self.quitmsg="Connection Closed"
                        sys.exit()

                    readbuf += read
                    lastlf = readbuf.rfind("\n")

                    if lastlf >= 0:
                        linebuf.extend(string.split(readbuf[0:lastlf], "\n"))
                        readbuf = readbuf[lastlf + 1:]

                line = string.rstrip(linebuf.pop(0))
                try:
                    line = line.decode("utf8")
                except UnicodeDecodeError:
                    # Attempt to figure encoding
                    charset = chardet.detect(line)['encoding']
                    line = line.decode(charset)
                match = re.findall(
                    "^(.+?)(?:\\s+(.+?)(?:\\s+(.+?))??)??(?:\\s+:(.*))?$", line, re.I)
                # print match

                if len(match) == 0:
                    continue
                (cmd, target, params, extinfo) = match[0]

                if not passwd:  # Bouncer expects a password
                    if cmd.upper() == "PASS":
                        passwd = target if target else extinfo
                    else:
                        self.quit("Access Denied")
                        print "*** [BouncerConnection] Incoming connection from %s failed: Expected PASS." % (self.host)
                        break

                elif not self.nick:  # Bouncer expects a NICK command
                    if cmd.upper() == "NICK":
                        self.nick = target if target else extinfo
                    else:
                        self.quit("Access Denied")
                        print "*** [BouncerConnection] Incoming connection from %s failed: Expected NICK." % (self.host)
                        break

                elif not self.username:  # Bouncer expects a USER command to finish registration
                    if cmd.upper() == "USER":
                        self.username = target
                        contextfound = False
                        for self.context, conf in self.bouncer.conf.items():
                            # print conf.label, self.username
                            if conf.label == self.username:
                                contextfound = True
                                break
                        if not contextfound:
                            with self.context.lock:
                                self.quit("Access Denied")
                                self.context.logwrite(
                                    "*** [BouncerConnection] Incoming connection from %s to %s denied: Invalid password." % (self.host, self.context))
                                for bouncerconnection in self.bouncer.connections:
                                    if bouncerconnection.context != self.context:
                                        continue
                                    if not bouncerconnection.quitting:
                                        bouncerconnection.send(":*Bouncer* NOTICE %s :Incoming connection from %s to %s dened: Invalid password.\n" % (
                                            bouncerconnection.context.identity.nick, self.host, self.context))
                                break
                        passmatch = hashlib.new(
                            conf.hashtype, passwd).hexdigest() == conf.passwd
                        with self.context.lock:
                            if not passmatch:
                                self.quit("Access Denied")
                                self.context.logwrite(
                                    "*** [BouncerConnection] Incoming connection from %s to %s denied: Invalid password." % (self.host, self.context))
                                for bouncerconnection in self.bouncer.connections:
                                    if bouncerconnection.context != self.context:
                                        continue
                                    if not bouncerconnection.quitting:
                                        bouncerconnection.send(":*Bouncer* NOTICE %s :Incoming connection from %s to %s dened: Invalid password.\n" % (
                                            bouncerconnection.context.identity.nick, self.host, self.context))
                                break

                            self.context.logwrite(
                                "*** [BouncerConnection] Incoming connection from %s to %s." % (self.host, self.context))
                            with self.bouncer.lock:
                                # Announce connection to all other bouncer
                                # connections.
                                for bouncerconnection in self.bouncer.connections:
                                    if bouncerconnection.context != self.context:
                                        continue
                                    if not bouncerconnection.quitting:
                                        bouncerconnection.send(":*Bouncer* NOTICE %s :Incoming connection from %s to %s\n" % (
                                            bouncerconnection.context.identity.nick, self.host, self.context))
                                if len([bncconnection for bncconnection in self.bouncer.connections if bncconnection.context == self.context]) == 0 and self.context.registered and type(self.context.identity) == irc.User and self.context.identity.away:
                                    # Bouncer connection should automatically
                                    # return from away status.
                                    self.context.raw("AWAY")
                                self.hidden = irc.ChanList(
                                    self.bouncer.conf[self.context].hidden, context=self.context)
                                self.bouncer.connections.append(self)

                            if self.context.registered:
                                # Send Greeting.
                                with self.lock:
                                    if self.context.welcome:
                                        self.connection.send(
                                            (u":%s 001 %s :%s\n" % (self.context.serv, self.context.identity.nick, self.context.welcome)).encode("utf8"))
                                    if self.context.hostinfo:
                                        self.connection.send(
                                            (u":%s 002 %s :%s\n" % (self.context.serv, self.context.identity.nick, self.context.hostinfo)).encode("utf8"))
                                    if self.context.servcreated:
                                        self.connection.send(
                                            (u":%s 003 %s :%s\n" % (self.context.serv, self.context.identity.nick, self.context.servcreated)).encode("utf8"))
                                    if self.context.servinfo:
                                        self.connection.send(
                                            (u":%s 004 %s %s\n" % (self.context.serv, self.context.identity.nick, self.context.servinfo)).encode("utf8"))

                                    # Send 005 response.
                                    if self.context.supports:
                                        supports = ["CHANMODES=%s" % (",".join(value)) if name == "CHANMODES" else "PREFIX=(%s)%s" % value if name == "PREFIX" else "%s=%s" % (
                                            name, value) if value else name for name, value in self.context.supports.items()]
                                        supports.sort()
                                        supportsreply = []
                                        supportsstr = " ".join(supports)
                                        index = 0
                                        while True:
                                            if len(supportsstr) - index > 196:
                                                nextindex = supportsstr.rfind(
                                                    " ", index, index + 196)
                                                supportsreply.append(
                                                    supportsstr[index:nextindex])
                                                index = nextindex + 1
                                            else:
                                                supportsreply.append(
                                                    supportsstr[index:])
                                                break
                                        for support in supportsreply:
                                            self.connection.send((u":%s 005 %s %s :are supported by this server\n" % (
                                                self.context.serv, self.context.identity.nick, support)).encode("utf8"))

                                    # Send MOTD
                                    if self.context.motdgreet and self.context.motd and self.context.motdend:
                                        self.connection.send(
                                            (u":%s 375 %s :%s\n" % (self.context.serv, self.context.identity.nick, self.context.motdgreet)).encode("utf8"))
                                        for motdline in self.context.motd:
                                            self.connection.send(
                                                (u":%s 372 %s :%s\n" % (self.context.serv, self.context.identity.nick, motdline)).encode("utf8"))
                                        try:
                                            self.connection.send(
                                                (u":%s 376 %s :%s\n" % (self.context.serv, self.context.identity.nick, self.context.motdend)).encode("utf8"))
                                        except AttributeError:
                                            self.connection.send(
                                                (u":%s 376 %s\n" % (self.context.serv, self.context.identity.nick)).encode("utf8"))
                                    else:
                                        self.connection.send((u":%s 422 %s :MOTD File is missing\n" % (
                                            self.context.serv, self.context.identity.nick)).encode("utf8"))

                                    # Send user modes and snomasks.
                                    self.connection.send(
                                        (u":%s 221 %s +%s\n" % (self.context.serv, self.context.identity.nick, self.context.identity.modes)).encode("utf8"))

                                    if "s" in self.context.identity.modes and self.context.identity.snomask:
                                        self.connection.send((u":%s 008 %s +%s :Server notice mask\n" % (
                                            self.context.serv, self.context.identity.nick, self.context.identity.snomask)).encode("utf8"))

                                    # Join user to channels.
                                    for channel in self.context.identity.channels:
                                        if channel in self.hidden:
                                            continue

                                        if channel in conf.translations.keys():
                                            channame = conf.translations[
                                                channel]
                                        else:
                                            channame = channel.name
                                        # JOIN command
                                        self.connection.send(
                                            (u":%s!%s@%s JOIN :%s\n" % (self.context.identity.nick, self.context.identity.username, self.context.identity.host, channame)).encode("utf8"))

                                        # Topic
                                        self.connection.send(
                                            (u":%s 332 %s %s :%s\n" % (self.context.serv, self.context.identity.nick, channame, channel.topic)).encode("utf8"))
                                        self.connection.send((u":%s 333 %s %s %s %s\n" % (self.context.serv, self.context.identity.nick, channame, channel.topicsetby.nick if type(
                                            channel.topicsetby) == irc.User else channel.topicsetby, channel.topictime)).encode("utf8"))

                                        # Determine if +s or +p modes are set
                                        # in channel
                                        secret = "s" in channel.modes.keys() and channel.modes[
                                            "s"]
                                        private = "p" in channel.modes.keys(
                                        ) and channel.modes["p"]

                                        # Construct NAMES for channel.
                                        namesusers = []
                                        modes, symbols = self.context.supports[
                                            "PREFIX"]
                                        self.connection.send((u":%s 353 %s %s %s :%s\n" % (
                                            self.context.serv,
                                            self.context.identity.nick,
                                            "@" if secret else (
                                                "*" if private else "="),
                                            channame,
                                            u" ".join([u"".join([symbols[k] if modes[k] in channel.modes.keys() and user in channel.modes[modes[k]] else "" for k in xrange(len(modes))]) + user.nick for user in channel.users]))
                                        ).encode("utf8"))
                                        self.connection.send((u":%s 366 %s %s :End of /NAMES list.\n" % (
                                            self.context.serv, self.context.identity.nick, channame)).encode("utf8"))
                            else:
                                self.send(
                                    u":*Bouncer* NOTICE %s :Not connected to server. Type /bncconnect to attempt connection.\n" % self.nick)
                                self.send(
                                    u":%s 001 %s :Welcome to the Bouncer context Network %s!%s@%s\n" %
                                    ("*Bouncer*", self.nick, self.nick, self.username, self.host))
                    else:  # Client did not send USER command when expected
                        self.quit("Access Denied")
                        print "*** [BouncerConnection] Incoming connection from %s failed: Expected USER." % (self.host)
                        break

                elif cmd.upper() == "QUIT":
                    self.quit(extinfo)
                    break

                elif cmd.upper() == "SHOW":
                    if target:
                        for chan in target.split(","):
                            chantypes = self.context.supports.get(
                                "CHANTYPES", "&#+!")
                            if re.match(irc._chanmatch % re.escape(chantypes), target):
                                translationfound = False
                                for channel, channame in conf.translations.items():
                                    if translation.lower() == chan.lower():
                                        translationfound = True
                                if not translationfound:
                                    channel = self.context[chan]
                                    channame = channel.name

                                if channel in self.hidden:
                                    with self.lock:
                                        self.hidden.remove(channel)

                                        if channel in self.context.identity.channels:
                                            # JOIN command
                                            self.connection.send(
                                                (u":%s!%s@%s JOIN :%s\n" % (self.context.identity.nick, self.context.identity.username, self.context.identity.host, channame)).encode("utf8"))

                                            # Topic
                                            self.connection.send(
                                                (u":%s 332 %s %s :%s\n" % (self.context.serv, self.context.identity.nick, channame, channel.topic)).encode("utf8"))
                                            self.connection.send((u":%s 333 %s %s %s %s\n" % (self.context.serv, self.context.identity.nick, channame, channel.topicsetby.nick if type(
                                                channel.topicsetby) == irc.User else channel.topicsetby, channel.topictime)).encode("utf8"))

                                            # Determine if +s or +p modes are
                                            # set in channel
                                            secret = "s" in channel.modes.keys() and channel.modes[
                                                "s"]
                                            private = "p" in channel.modes.keys(
                                            ) and channel.modes["p"]

                                            # Construct NAMES for channel.
                                            namesusers = []
                                            modes, symbols = self.context.supports[
                                                "PREFIX"]
                                            self.connection.send((u":%s 353 %s %s %s :%s\n" % (
                                                self.context.serv,
                                                self.context.identity.nick,
                                                "@" if secret else (
                                                    "*" if private else "="),
                                                channame,
                                                u" ".join([u"".join([symbols[k] if modes[k] in channel.modes.keys() and user in channel.modes[modes[k]] else "" for k in xrange(len(modes))]) + user.nick for user in channel.users]))
                                            ).encode("utf8"))
                                            self.connection.send((u":%s 366 %s %s :End of /NAMES list.\n" % (
                                                self.context.serv, self.context.identity.nick, channame)).encode("utf8"))
                                        else:
                                            self.connection.send((u":%s 442 %s %s :You are not on that channel.\n" % (
                                                self.context.serv, self.context.identity.nick, channame)).encode("utf8"))
                            else:
                                self.connection.send((u":%s 403 %s %s :Invalid channel name.\n" % (
                                    self.context.serv, self.context.identity.nick, chan)).encode("utf8"))
                    else:
                        self.connection.send((u":%s 461 %s SHOW :Not enough parameters.\n" % (
                            self.context.serv, self.context.identity.nick)).encode("utf8"))
                        self.connection.send((u":%s 304 %s :SYNTAX SHOW <channel>{,<channel>}\n" % (
                            self.context.serv, self.context.identity.nick)).encode("utf8"))
                elif cmd.upper() == "HIDE":
                    if target:
                        for chan in target.split(","):
                            chantypes = self.context.supports.get(
                                "CHANTYPES", "&#+!")
                            if re.match(irc._chanmatch % re.escape(chantypes), target):
                                translationfound = False
                                for channel, channame in conf.translations.items():
                                    if translation.lower() == chan.lower():
                                        translationfound = True
                                if not translationfound:
                                    channel = self.context[chan]
                                    channame = channel.name

                                if channel not in self.hidden:
                                    with self.lock:
                                        self.hidden.append(channel)

                                        if channel in self.context.identity.channels:
                                            # PART command
                                            self.connection.send((u":%s!%s@%s PART %s :Hiding channel\n" % (
                                                self.context.identity.nick, self.context.identity.username, self.context.identity.host, channame)).encode("utf8"))
                                        else:
                                            self.connection.send((u":%s 442 %s %s :You are not on that channel.\n" % (
                                                self.context.serv, self.context.identity.nick, channame)).encode("utf8"))
                            else:
                                self.connection.send((u":%s 403 %s %s :Invalid channel name.\n" % (
                                    self.context.serv, self.context.identity.nick, chan)).encode("utf8"))
                    else:
                        self.connection.send((u":%s 461 %s HIDE :Not enough parameters.\n" % (
                            self.context.serv, self.context.identity.nick)).encode("utf8"))
                        self.connection.send((u":%s 304 %s :SYNTAX HIDE <channel>{,<channel>}\n" % (
                            self.context.serv, self.context.identity.nick)).encode("utf8"))

                elif cmd.upper() == "PING":
                    self.send(":%s PONG %s :%s\n" %
                              (self.context.serv, self.context.serv, self.context.identity.nick if type(self.context.identity) == irc.User else "***"))

                elif cmd.upper() == "BNCCONNECT":
                    with self.context.lock:
                        if self.context.isAlive() and self.context.connected:
                            self.send(
                                ":*Bouncer* NOTICE %s :Bouncer is already connected.\n" % self.nick)
                    self.context.start()

                elif cmd.upper() == "BNCQUIT":
                    with self.context.lock:
                        if self.context.isAlive() and self.context.connected and self.context.registered:
                            quitmsg = " ".join(
                                [word for word in [target, params, extinfo] if word])
                            self.context.quit(quitmsg)
                        else:
                            self.send(
                                ":*Bouncer* NOTICE %s :Bouncer is already disconnected.\n" % self.nick)

                else:
                    if target:
                        targetlist = []
                        for targ in target.split(","):
                            translationfound = False
                            for (channel, translation) in conf.translations.items():
                                if translation.lower() == targ.lower():
                                    # print channel
                                    targetlist.append(channel.name)
                                    translationfound = True
                                    break
                            if not translationfound:
                                targetlist.append(targ)
                        target = ",".join(targetlist)

                        oldparams = params
                        params = []
                        for param in oldparams.split():
                            translationfound = False
                            for (channel, translation) in conf.translations.items():
                                # print target, (channel, translation)
                                if translation.lower() == param.lower():
                                    # print channel
                                    params.append(channel.name)
                                    translationfound = True
                                    break
                            if not translationfound:
                                params.append(param)
                        params = " ".join(params)

                        #print (cmd, target, params, extinfo)

                        if params and extinfo:
                            line = "%s %s %s :%s" % (
                                cmd, target, params, extinfo)
                        elif params:
                            line = "%s %s %s" % (cmd, target, params)
                        elif extinfo:
                            line = "%s %s :%s" % (cmd, target, extinfo)
                        else:
                            line = "%s %s" % (cmd, target)

                    with self.context.lock:
                        # print "Locked"
                        # print self.context.connected,
                        # self.context.registered, cmd.upper()
                        if not self.context.connected:
                            self.send(
                                ":*Bouncer* NOTICE %s :Not connected to server. Type /bncconnect to attempt connection.\n" % self.nick)
                            break

                        elif not self.context.registered:
                            self.send(
                                ":*Bouncer* NOTICE %s :Not registered.\n" % self.nick)
                            break

                        elif cmd.upper() in ("PRIVMSG", "NOTICE"):
                            # Check if CTCP
                            ctcp = re.findall(
                                "^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$", extinfo)

                            if ctcp:  # If CTCP, only want to
                                (ctcptype, ext) = ctcp[0]  # Unpack CTCP info

                                if ctcptype == "LAGCHECK":  # Client is doing a lag check. No need to send to context network, just reply back.
                                    self.send(":%s!%s@%s %s\n" % (
                                        self.context.identity.nick, self.context.identity.username, self.context.identity.host, line))
                                else:
                                    self.context.raw(line, origin=self)
                            else:
                                self.context.raw(line, origin=self)

                        elif cmd.upper() == "MODE":  # Will want to determine is requesting modes, or attempting to modify modes.
                            # if target and "CHANTYPES" in
                            # self.context.supports.keys() and target[0] in
                            # self.context.supports["CHANTYPES"]:
                            chantypes = self.context.supports.get(
                                "CHANTYPES", "&#+!")
                            if re.match(irc._chanmatch % re.escape(chantypes), target):
                                channel = self.context[target]
                                if channel in conf.translations.keys():
                                    channame = conf.translations[channel]
                                else:
                                    channame = channel.name

                                if params == "":
                                    modes = channel.modes.keys()
                                    modestr = "".join([mode for mode in modes if mode not in self.context.supports[
                                                      "CHANMODES"][0] + self.context.supports["PREFIX"][0] and channel.modes[mode]])
                                    params = " ".join([channel.modes[mode] for mode in modes if mode in self.context.supports[
                                                      "CHANMODES"][1] + self.context.supports["CHANMODES"][2] and channel.modes[mode]])
                                    with self.lock:
                                        if len(modestr):
                                            self.connection.send(
                                                (u":%s 324 %s %s +%s %s\n" % (self.context.serv, self.context.identity.nick, channame, modestr, params)).encode("utf8"))
                                        if channel.created:
                                            self.connection.send(
                                                (u":%s 329 %s %s %s\n" % (self.context.serv, self.context.identity.nick, channame, channel.created)).encode("utf8"))
                                elif re.match("^\\+?[%s]+$" % self.context.supports["CHANMODES"][0], params) and extinfo == "":
                                    # print "ddd Mode List Request", params
                                    redundant = []
                                    for mode in params.lstrip("+"):
                                        if mode in redundant or mode not in listnumerics.keys():
                                            continue
                                        i, e, l = listnumerics[mode]
                                        with self.lock:
                                            if mode in channel.modes.keys():
                                                for (mask, setby, settime) in channel.modes[mode]:
                                                    self.connection.send(
                                                        (u":%s %d %s %s %s %s %s\n" % (self.context.serv, i, channel.context.identity.nick, channame, mask, setby, settime)).encode("utf8"))
                                            self.connection.send(
                                                (u":%s %d %s %s :End of %s\n" % (self.context.serv, e, channel.context.identity.nick, channame, l)).encode("utf8"))
                                        redundant.append(mode)
                                else:
                                    self.context.raw(line, origin=self)
                            elif params == "" and target.lower() == self.context.identity.nick.lower():
                                with self.lock:
                                    self.connection.send(
                                        (u":%s 221 %s +%s\n" % (self.context.serv, self.context.identity.nick, self.context.identity.modes)).encode("utf8"))
                                    if "s" in self.context.identity.modes and self.context.identity.snomask:
                                        self.connection.send((u":%s 008 %s +%s :Server notice mask\n" % (
                                            self.context.serv, self.context.identity.nick, self.context.identity.snomask)).encode("utf8"))
                            else:
                                self.context.raw(line, origin=self)
                        else:
                            self.context.raw(line, origin=self)

        except SystemExit:
            pass  # No need to pass error message if break resulted from sys.exit()
        except:
            exc, excmsg, tb = sys.exc_info()
            self.quitmsg = str(excmsg)
            if self.context:
                exc, excmsg, tb = sys.exc_info()
                self.context.logwrite(*["!!! [BouncerConnection] Exception in thread %(self)s" % vars()] + [
                                      "!!! [BouncerConnection] %(tbline)s" % vars() for tbline in traceback.format_exc().split("\n")])
                print >>sys.stderr, "Exception in thread %(self)s" % vars()
                print >>sys.stderr, traceback.format_exc()
        finally:
            # Juuuuuuust in case.
            with self.lock:
                try:
                    self.connection.shutdown(1)
                    self.connection.close()
                except:
                    pass

            if self.context:
                self.context.logwrite(
                    "*** [BouncerConnection] Connection from %s terminated (%s)." % (self.host, self.quitmsg))

            if self in self.bouncer.connections:
                with self.bouncer.lock:
                    self.bouncer.connections.remove(self)
                    if self.context.connected and self.context.identity and len([bncconnection for bncconnection in self.bouncer.connections if bncconnection.context == self.context]) == 0 and self.context.registered and type(self.context.identity) == irc.User and not self.context.identity.away and self.bouncer.autoaway:
                        # Bouncer automatically sets away status.
                        self.context.raw("AWAY :%s" % self.bouncer.autoaway)
                    if self.debug:
                        self.context.logwrite(
                            "dbg [BouncerConnection] Attempting to broadcast terminated connection %(self)s." % vars())
                    for bouncerconnection in self.bouncer.connections:
                        if bouncerconnection.context == self.context:
                            if self.debug:
                                self.context.logwrite(
                                    "dbg [BouncerConnection] Broadcasting to %(bouncerconnection)s." % vars())
                            if not bouncerconnection.quitting:
                                bouncerconnection.connection.send(":*Bouncer* NOTICE %s :Connection from %s to %s terminated (%s)\n" % (
                                    bouncerconnection.context.identity.nick, self.host, self.context, self.quitmsg))
                                if self.debug:
                                    self.context.logwrite(
                                        "dbg [BouncerConnection] Success: %(bouncerconnection)s." % vars())

# Announce QUIT to other bouncer connections.
#				for bouncerconnection in self.bouncer.connections:
#					try:
#						bouncerconnection.connection.send(":%s!%s@%s QUIT :%s\n" % (self.label, self.username, self.host, self.quitmsg))
#					except:
#						pass
