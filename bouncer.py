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
from threading import Thread
from threading import RLock as Lock
import Queue
import chardet
import modjson

dec = modjson.ModJSONDecoder()
enc = modjson.ModJSONEncoder(indent=3)

# TODO: Rewrite this *entire* module and make more efficient.

_listnumerics = dict(b=(367, 368, "channel ban list"),
                     e=(348, 349, "Channel Exception List"),
                     I=(346, 347, "Channel Invite Exception List"),
                     w=(910, 911, "Channel Access List"),
                     g=(941, 940, "chanel spamfilter list"),
                     X=(954, 953, "channel exemptchanops list"))


def BouncerReload(BNC):
    networks, configs = zip(*BNC.conf.items())
    json = enc.encode([BNC, configs])
    if BNC.isAlive():
        BNC.stop()
    newBNC, newconfs = dec.decode(json)
    for network, newconf in zip(networks, newconfs):
        network.rmAddon(BNC)
        network.addAddon(**newconf)
    return newBNC


class Bouncer (Thread):
    __name__ = "Bouncer for pyIRC"
    __version__ = "2.0"
    __author__ = "Brian Sherson"
    __date__ = "February 21, 2014"

    def __init__(self, addr="", port=16667, secure=False, ipv6=False, certfile=None, keyfile=None, ignore=None, debug=False, timeout=300, autoaway=None, servname="bouncer.site"):
        self.addr = addr
        self.port = port
        self.conf = {}
        self.passwd = {}
        self.socket = None
        self.secure = secure
        self.ipv6 = ipv6
        self.certfile = certfile
        self.keyfile = keyfile
        self.clients = []
        self.ignore = ignore
        self.debug = debug
        self.timeout = timeout
        self.autoaway = autoaway
        self.servname = servname
        self._stopexpected = False

        # Keep track of what extensions/clients are requesting WHO, WHOIS, and LIST, because we don't want to spam every bouncer connection with the server's replies.
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
        h = hash(self)
        return "<Bouncer listening on {self.addr}:{self.port} at 0x{h:x}0>".format(**vars())

    def run(self):
        self.socket = socket.socket(
            socket.AF_INET6 if self.ipv6 else socket.AF_INET)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.addr, self.port))
        self.socket.listen(5)
        #print ((self,"Now listening on port "+str(self.port)))
        while True:
            try:
                (connection, addr) = self.socket.accept()
                if self.secure:
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
        self.socket = None
        Thread.__init__(self)
        self.daemon = True

    def onAddonAdd(self, context, label, passwd=None, hashtype="sha512", ignore=None, autoaway=None, translations=[], hidden=[]):
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
        conf = irc.Config(self, label=label, passwd=passwd, hashtype=hashtype, ignore=ignore, autoaway=autoaway, translations=[
                          (key if type(key) == irc.Channel else context[key], value) for key, value in translations], hidden=irc.ChanList(hidden, context=context))
        self.conf[context] = conf
        self._whoexpected[context] = []
        if self.debug:
            context.logwrite(
                "dbg [Bouncer.onAddonAdd] Clearing WHO expected list." % vars())
        self._whoisexpected[context] = []
        self._listexpected[context] = []
        return conf

    def onAddonRem(self, context):
        for client in self.clients:
            if client.context == context:
                client.quit(quitmsg="Bouncer extension removed")
        del self.conf[context]
        del self._whoexpected[context], self._whoisexpected[
            context], self._listexpected[context]

    def stop(self, disconnectall=False):
        self._stopexpected = True
        self.socket.shutdown(0)
        if disconnectall:
            self.disconnectall()

    def disconnectall(self, quitmsg="Disconnecting all sessions"):
        for client in self.clients:
            client.quit(quitmsg=quitmsg)

    def onDisconnect(self, context, expected=False):
        self._whoexpected[context] = []
        self._whoisexpected[context] = []
        self._listexpected[context] = []
        if context.identity:
            for channel in context.identity.channels:
                self.broadcast(context, origin=context.identity, cmd="PART", target=channel, extinfo="Bouncer Connection Lost", clients=[
                               client for client in self.clients if channel not in client.hidden])
            self.broadcast(context, origin=context.identity,
                           cmd="QUIT", extinfo="Bouncer Connection Lost")
        self.broadcast(
            context, origin=self.servname, cmd="NOTICE", target=context.identity,
            extinfo=":Connection to %s:%s has been lost." % (context.server, context.port))

    def onQuit(self, context, user, quitmsg):
        # For some odd reason, certain networks (*cough*Freenode*cough*) will send a quit message for the user, causing context.identity.channels to be cleared
        # before onDisconnect can be executed. This is the remedy.
        if user == context.identity:
            for channel in context.identity.channels:
                self.broadcast(context, origin=user, cmd="PART", target=channel, extinfo="Bouncer Connection Lost", clients=[
                               client for client in self.clients if channel not in client.hidden])
        self.broadcast(context, origin=user, cmd="QUIT", extinfo=quitmsg, clients=[
                       client for client in self.clients if any([user in channel for channel in context.channels if channel not in client.hidden])])

    def onConnectAttempt(self, context):
        self.broadcast(
            context, origin=self.servname, cmd="NOTICE", target=context.identity,
            extinfo="Attempting connection to %s:%s." % (context.server, context.port))

    def onConnect(self, context):
        self.broadcast(
            context, origin=self.servname, cmd="NOTICE", target=context.identity,
            extinfo="Connection to %s:%s established." % (context.server, context.port))

    def onMeNickChange(self, context, newnick):
        for client in self.clients:
            if client.context == context:
                client.send(
                    origin=context.identity, cmd="NICK", target=newnick)
                client.nick = newnick

    def onNickChange(self, context, user, newnick):
        self.broadcast(context, origin=user, cmd="NICK", target=newnick, clients=[
                       client for client in self.clients if any([user in channel for channel in context.channels if channel not in client.hidden])])

    def onRegistered(self, context):
        for client in self.clients:
            if client.context == context:
                if client.nick != context.identity.nick:
                    client.send(origin="%s!%s@%s" %
                                (client.nick, client.username, client.host), cmd="NICK", target=context.identity.nick)
                    client.nick = context.identity.nick

    def onConnectFail(self, context, exc, excmsg, tb):
        for client in self.clients:
            if client.context == context:
                client.send(
                    origin=self.servname, cmd="NOTICE", target=client.nick,
                    extinfo="Connection to %s:%s failed: %s." % (context.server, context.port, excmsg))

    def onSendChanMsg(self, context, origin, channel, targetprefix, msg):
        # Called when bot sends a PRIVMSG to channel.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        self.broadcast(
            context, origin=context.identity, cmd="PRIVMSG", targetprefix=targetprefix,
            target=channel, extinfo=msg, clients=[client for client in self.clients if client != origin])

    def onSendChanAction(self, context, origin, channel, targetprefix, action):
        self.onSendChanMsg(
            context, origin, channel, targetprefix, u"\x01ACTION {action}\x01".format(**vars()))

    def onSendChanNotice(self, context, origin, channel, targetprefix, msg):
        # Called when bot sends a NOTICE to channel.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        self.broadcast(
            context, origin=context.identity, cmd="NOTICE", targetprefix=targetprefix,
            target=channel, extinfo=msg, clients=[client for client in self.clients if client != origin])

    def onSend(self, context, origin, line, cmd, target, targetprefix, params, extinfo):
        if cmd.upper() == "WHO":
            self._whoexpected[context].append(origin)
            if self.debug:
                if issubclass(type(origin), Thread):
                    name = origin.name
                    context.logwrite(
                        "dbg [Bouncer.onSend] Adding {origin} ({name}) to WHO expected list.".format(**vars()))
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
        if len(self._whoexpected[context]):
            client = self._whoexpected[context][0]
            if client in self.clients:
                client.send(origin=origin, cmd=352, target=context.identity, params=u"{channame} {username} {host} {serv} {nick} {flags}".format(
                    **vars()), extinfo=u"{hops} {realname}".format(**vars()))
                # client.send(":%s 352 %s %s %s %s %s %s %s :%s %s\n"%(origin, context.identity.nick, channame, username, host, serv, nick, flags, hops, realname))

    def onWhoEnd(self, context, origin, param, endmsg):
        # Called when a WHO list is received.
        if len(self._whoexpected[context]) and self._whoexpected[context][0] in self.clients:
            client = self._whoexpected[context][0]
            client.send(
                origin=origin, cmd=315, target=context.identity, params=param, extinfo=endmsg)
                #client.send(":%s 315 %s %s :%s\n"%(origin, context.identity.nick, param, endmsg))
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
        if len(self._listexpected[context]) and self._listexpected[context][0] in self.clients:
            client = self._listexpected[context][0]
            client.send(origin=origin, cmd=321,
                        target=context.identity, params=params, extinfo=extinfo)
                #client.send(":%s 321 %s %s :%s\n"%(origin, context.identity.nick, params, extinfo))

    def onListEntry(self, context, origin, channel, population, extinfo):
        # Called when a WHO list is received.
        if len(self._listexpected[context]) and self._listexpected[context][0] in self.clients:
            client = self._listexpected[context][0]
            client.send(origin=origin, cmd=322, target=context.identity,
                        params=u"{channel.name} {population}".format(**vars()), extinfo=extinfo)
                # client.send(":%s 322 %s %s %d :%s\n"%(origin, context.identity.nick, channame, population, extinfo))

    def onListEnd(self, context, origin, endmsg):
        # Called when a WHO list is received.
        if len(self._listexpected[context]) and self._listexpected[context][0] in self.clients:
            client = self._listexpected[context][0]
            client.send(
                origin=origin, cmd=323, target=context.identity, extinfo=endmsg)
                # client.send(":%s 323 %s :%s\n"%(origin, context.identity.nick, endmsg))
        del self._listexpected[context][0]

    def onWhoisStart(self, context, origin, user, nickname, username, host, realname):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=311, target=context.identity,
                        params=u"{nickname} {username} {host} *".format(**vars()), extinfo=realname)
                # client.send(":%s 311 %s %s %s %s * :%s\n" % (origin, context.identity.nick, nickname, username, host, realname))

    def onWhoisRegisteredNick(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(
                origin=origin, cmd=307, target=context.identity, params=nickname, extinfo=msg)
                # client.send(":%s 307 %s %s :%s\n" % (origin, context.identity.nick, nickname, msg))

    def onWhoisConnectingFrom(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=378,
                        target=context.identity, params=nickname, extinfo=msg)
                # client.send(":%s 378 %s %s :%s\n" % (origin, context.identity.nick, nickname, msg))

    def onWhoisChannels(self, context, origin, user, nickname, chanlist):
        # Called when a WHOIS reply is received.
        # TODO: Translations implementation
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=319, target=context.identity,
                        params=nickname, extinfo=" ".join(chanlist))
                # client.send(":%s 319 %s %s :%s\n" % (origin, context.identity.nick, nickname, " ".join(chanlist)))

    def onWhoisAvailability(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(
                origin=origin, cmd=310, target=context.identity, params=nickname, extinfo=msg)
                # client.send(":%s 310 %s %s :%s\n" % (origin, context.identity.nick, nickname, msg))

    def onWhoisServer(self, context, origin, user, nickname, server, servername):
        # Called when a WHOIS reply is received.
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=312, target=context.identity,
                        params=u"{nickname} {server}".format(**vars()), extinfo=servername)
                # client.send(":%s 312 %s %s %s :%s\n" % (origin, context.identity.nick, nickname, server, servername))

    def onWhoisOp(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(
                origin=origin, cmd=313, target=context.identity, params=nickname, extinfo=msg)
                # client.send(":%s 313 %s %s :%s\n" % (origin, context.identity.nick, nickname, msg))

    def onWhoisAway(self, context, origin, user, nickname, awaymsg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=301, target=context.identity,
                        params=u"{nickname} {idletime} {signontime}".format(**vars()), extinfo=awaymsg)
                # client.send(":%s 301 %s %s :%s\n" % (origin, context.identity.nick, nickname, awaymsg))

    def onWhoisTimes(self, context, origin, user, nickname, idletime, signontime, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=317, target=context.identity,
                        params=u"{nickname} {idletime} {signontime}".format(**vars()), extinfo=msg)
                # client.send(":%s 317 %s %s %d %d :%s\n" % (origin, context.identity.nick, nickname, idletime, signontime, msg))

    def onWhoisSSL(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=671,
                        target=context.identity, params=nickname, extinfo=msg)
                # client.send(":%s 671 %s %s :%s\n" % (origin, context.identity.nick, nickname, msg))

    def onWhoisModes(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(
                origin=origin, cmd=339, target=context.identity, params=nickname, extinfo=msg)
                # ":%s 339 %s %s :%s\n" % (origin, context.identity.nick, nickname, msg))

    def onWhoisLoggedInAs(self, context, origin, user, nickname, loggedinas, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=330, target=context.identity,
                        params=" ".join((nickname, loggedinas)), extinfo=msg)
                # ":%s 330 %s %s %s :%s\n" % (origin, context.identity.nick, nickname, loggedinas, msg))

    def onWhoisEnd(self, context, origin, user, nickname, msg):
        if len(self._whoisexpected[context]) and self._whoisexpected[context][0] in self.clients:
            client = self._whoisexpected[context][0]
            client.send(origin=origin, cmd=318,
                        target=context.identity, params=nickname, extinfo=msg)
                # ":%s 318 %s %s :%s\n" % (origin, context.identity.nick, nickname, msg)
        del self._whoisexpected[context][0]

    def onJoin(self, context, user, channel):
        self.broadcast(context, origin=user, cmd="JOIN", target=channel, clients=[
                       client for client in self.clients if channel not in client.hidden])

    def onOther(self, context, line, origin, cmd, target, params, extinfo, targetprefix):
        conf = self.conf[context]
        self.broadcast(
            context, origin=origin, cmd=cmd, target=target, params=params, extinfo=extinfo,
            targetprefix=targetprefix, clients=[client for client in self.clients if target not in client.hidden])

    def broadcast(self, context, origin=None, cmd=None, target=None, params=None, extinfo=None, targetprefix=None, clients=None):
        if clients == None:
            clients = self.clients
        for client in clients:
            with client.lock:
                if client.context == context and not client.quitting:
                    client.send(
                        origin, cmd, target, params, extinfo, targetprefix)


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
        self.translations = {}
        self.namesx = False
        self.uhnames = False

        Thread.__init__(self)
        self.daemon = True
        self.start()

    def sendstr(self, data, flags=0):
        with self.lock:
            try:
                self.connection.send(data.encode("utf8"))
            except socket.error:
                exc, excmsg, tb = sys.exc_info()
                print >>self.context.logwrite(*["!!! [BouncerConnection.send] Exception in thread %(self)s" % vars()] + [
                                              "!!! [BouncerConnection.send] %(tbline)s" % vars() for tbline in traceback.format_exc().split("\n")])
                self.quit(quitmsg=excmsg.message)

    # Format and send a string to the client
    def send(self, origin=None, cmd=None, target=None, params=None, extinfo=None, targetprefix=None, flags=0):
        if type(target) == irc.Channel:
            if targetprefix == None:
                targetprefix = ""
            # if target in self.translations.keys():
            #	target=targetprefix+self.translations[target]
            # else:
            #	target=targetprefix+target.name
            target = targetprefix + target.name
        elif type(target) == irc.User:
            target = target.nick

        if type(cmd) == int:
            cmd = "%03d" % cmd

        # translated=[]
        # if params:
            # for param in params.split(" "):
                #chantypes=self.context.supports.get("CHANTYPES", irc._defaultchantypes)
                # if re.match(irc._chanmatch % re.escape(chantypes), param) and self.context[param] in self.translations.keys():
                    # translated.append(self.translations[self.context[param]])
                # else:
                    # translated.append(param)
        #params=" ".join(translated)

        if params:
            line = u"{cmd} {target} {params}".format(**vars())
        elif target:
            line = u"{cmd} {target}".format(**vars())
        else:
            line = cmd

        if extinfo != None:
            line = u"{line} :{extinfo}".format(**vars())

        if type(origin) == irc.User:
            line = u":{origin:full} {line}".format(**vars())
        elif origin:
            line = u":{origin} {line}".format(**vars())
        self.sendstr(u"{line}\n".format(**vars()))

        #server=self.context.server if self.context else "*"
        #port=self.context.port if self.context else "*"
        # if self.context and self.context.identity:
            # nick=self.context.identity.nick
            #ident=self.context.identity.username if self.context.identity.username else "*"
            #host=self.context.identity.host if self.context.identity.host else "*"
        # else:
            # nick="*"
            # ident="*"
            # host="*"
        # if self.context.ssl and self.context.ipv6:
            # protocol="ircs6"
        # elif self.context.ssl:
            # protocol="ircs"
        # elif self.context.ipv6:
            # protocol="irc6"
        # else:
            # protocol="irc"
        # addr=self.host
    def __repr__(self):
        return "<Bouncer connection from {self.host} to {self.context.identity} on {self.context:uri}>".format(**vars())

    def quit(self, quitmsg="Disconnected"):
        with self.lock:
            if not self.quitting:
                self.quitmsg = quitmsg
                try:
                    self.send(cmd="ERROR", extinfo="Closing link: (%s@%s) [%s]\n" % (
                        self.context.identity.nick if self.context else "*", self.host, quitmsg))
                except:
                    pass
                try:
                    self.connection.shutdown(socket.SHUT_WR)
                    self.connection.close()
                except:
                    pass
                self.quitting = True

    def showchannel(self, channel):
        with self.context.lock, self.lock:
            if channel in self.hidden:
                self.hidden.remove(channel)
            if self.context.identity in channel.users:
                self.send(
                    origin=self.context.identity, cmd="JOIN", target=channel)
                self.sendchanneltopic(channel)
                self.sendchannelnames(channel)

    def sendchanneltopic(self, channel):
        with self.context.lock, self.lock:
            if channel.topic and channel.topictime:
                self.send(origin=self.bouncer.servname, cmd=332,
                          target=self.context.identity, params=channel.name, extinfo=channel.topic)
                # u":{self.context.serv} 332 {self.context.identity.nick} {self.name} :{self.topic}".format(**vars())
                self.send(
                    origin=self.bouncer.servname, cmd=333, target=self.context.identity,
                    params="{channel.name} {channel.topicsetby} {channel.topictime}".format(**vars()))
                # u":{self.context.serv} 333 {self.context.identity.nick} {self.name} {self.topicsetby.nick} {self.topictime}".format(**vars())
            else:
                self.send(origin=self.bouncer.servname, cmd=331,
                          target=self.context.identity, params=channel.name, extinfo="No topic is set")
                # u":{self.context.serv} 331 {self.context.identity.nick}
                # {self.name} :No topic is set".format(**vars())]

    def sendchannelnames(self, channel):
        with self.context.lock, self.lock:
            secret = "s" in channel.modes.keys() and channel.modes["s"]
            private = "p" in channel.modes.keys() and channel.modes["p"]
            flag = "@" if secret else ("*" if private else "=")

            modes, symbols = supports = self.context.supports.get(
                "PREFIX", irc._defaultprefix)
            users = list(channel.users)
            users.sort(key=lambda user: ([user not in channel.modes.get(mode, [])
                       for mode, char in zip(*supports)], user.nick.lower()))
            if self.uhnames:
                template = u"{prefixes}{user:full}"
            else:
                template = u"{prefixes}{user}"

            nameslist = []
            for user in users:
                prefixes = u"".join(
                    [prefix if mode in channel.modes.keys() and user in channel.modes[mode] else "" for prefix, mode in zip(symbols, modes)])
                if not self.namesx:
                    prefixes = prefixes[:1]
                nameslist.append(template.format(**vars()))
            names = " ".join(nameslist)

            lines = []
            while len(names) > 196:
                index = names.rfind(" ", 0, 196)
                slice = names[:index]
                self.send(
                    origin=self.bouncer.servname, cmd=353, target=self.context.identity,
                    params="{flag} {channel.name}".format(**vars()), extinfo=slice)
                    #u":{channel.context.serv} 353 {channel.context.identity.nick} {flag} {channel.name} :{slice}".format(**vars())
                names = names[index + 1:]
            if len(names):
                self.send(
                    origin=self.bouncer.servname, cmd=353, target=self.context.identity,
                    params="{flag} {channel.name}".format(**vars()), extinfo=names)
                    #u":{channel.context.serv} 353 {channel.context.identity.nick} {flag} {channel.name} :{names}".format(**vars())

            self.send(
                origin=self.bouncer.servname, cmd=366, target=self.context.identity,
                params=channel.name, extinfo="End of /NAMES list.")
                # u":{channel.context.serv} 366 {channel.context.identity.nick} {channel.name} :End of /NAMES list.".format(**vars())

    def sendchannelmodes(self, channel, modechars=None):
        with self.context.lock, self.lock:
            if modechars:
                for mode in modechars:
                    if mode not in _listnumerics.keys():
                        continue
                    i, e, l = _listnumerics[mode]
                    if mode in channel.modes.keys():
                        for (mask, setby, settime) in channel.modes[mode]:
                            self.send(
                                origin=self.bouncer.servname, cmd=i, target=self.context.identity,
                                params=u"{channel.name} {mask} {setby} {settime}".format(**vars()))
                    self.send(origin=self.bouncer.servname, cmd=e,
                              target=self.context.identity, params=u"{channel.name} {l}".format(**vars()))
            else:
                items = channel.modes.items()
                chanmodes = self.context.supports.get(
                    "CHANMODES", irc._defaultchanmodes)
                prefix = self.context.supports.get(
                    "PREFIX", irc._defaultprefix)
                modes = "".join(
                    [mode for (mode, val) in items if mode not in chanmodes[0] + prefix[0] and val])
                params = " ".join(
                    [val for (mode, val) in items if mode in chanmodes[1] + chanmodes[2] and val])
                if modes and params:
                    self.send(
                        origin=self.bouncer.servname, cmd=324, target=self.context.identity,
                        params="{channel.name} +{modes} {params}".format(**vars()))
                    # u":{channel.context.identity.server} 324 {channel.context.identity.nick} {channel.name} +{modes} {params}".format(**vars())
                elif modes:
                    self.send(
                        origin=self.bouncer.servname, cmd=324, target=self.context.identity,
                        params="{channel.name} +{modes}".format(**vars()))
                    # u":{channel.context.identity.server} 324 {channel.context.identity.nick} {channel.name} +{modes}".format(**vars())

    def sendsupports(self):
        with self.context.lock, self.lock:
            supports = [
                "CHANMODES=%s" % (",".join(value)) if name == "CHANMODES" else "PREFIX=(%s)%s" %
                value if name == "PREFIX" else "%s=%s" % (name, value) if value else name for name, value in self.context.supports.items()]
            if "UHNAMES" not in supports:
                supports.append("UHNAMES")
            if "NAMESX" not in supports:
                supports.append("NAMESX")
            supports.sort()
            supports = " ".join(supports)
            lines = []
            while len(supports) > 196:
                index = supports.rfind(" ", 0, 196)
                slice = supports[:index]
                self.send(
                    origin=self.bouncer.servname, cmd=5, target=self.context.identity,
                    params=slice, extinfo="are supported by this server")
                    # u":{self.context.serv} 005 {self.context.identity.nick} {slice} :are supported by this server".format(**vars())
                supports = supports[index + 1:]
            if supports:
                self.send(
                    origin=self.bouncer.servname, cmd=5, target=self.context.identity,
                    params=supports, extinfo="are supported by this server")
                    # u":{self.context.serv} 005 {self.context.identity.nick} {supports} :are supported by this server".format(**vars())

    def sendgreeting(self):
        with self.context.lock, self.lock:
            if self.context.welcome:
                self.send(origin=self.bouncer.servname, cmd=1,
                          target=self.context.identity, extinfo=self.context.welcome)
                    # u":{self.context.serv} 001 {self.context.identity.nick} :{self.context.welcome}".format(**vars())
            if self.context.hostinfo:
                self.send(origin=self.bouncer.servname, cmd=2,
                          target=self.context.identity, extinfo=self.context.hostinfo)
                    # u":{self.context.serv} 002 {self.context.identity.nick} :{self.context.hostinfo}".format(**vars())
            if self.context.servcreated:
                self.send(origin=self.bouncer.servname, cmd=3,
                          target=self.context.identity, extinfo=self.context.servcreated)
                    # u":{self.context.serv} 003 {self.context.identity.nick} :{self.context.servcreated}".format(**vars())
            if self.context.servinfo:
                self.send(origin=self.bouncer.servname, cmd=4,
                          target=self.context.identity, params=self.context.servinfo)
                    # u":{self.context.serv} 004 {self.context.identity.nick} {self.context.servinfo}".format(**vars())

    def sendmotd(self):
        with self.context.lock, self.lock:
            if self.context.motdgreet and self.context.motd and self.context.motdend:
                self.send(origin=self.bouncer.servname, cmd=375,
                          target=self.context.identity, extinfo=self.context.motdgreet)
                    # u":{server} 375 {self.identity.nick} :{self.motdgreet}".format(**vars())
                for motdline in self.context.motd:
                    self.send(origin=self.bouncer.servname, cmd=372,
                              target=self.context.identity, extinfo=motdline)
                        # u":{server} 372 {self.identity.nick} :{motdline}".format(**vars())
                self.send(origin=self.bouncer.servname, cmd=376,
                          target=self.context.identity, extinfo=self.context.motdend)
                    # u":{server} 376 {self.identity.nick} :{self.motdend}".format(**vars())
            else:
                self.send(origin=self.bouncer.servname, cmd=422,
                          target=self.context.identity, extinfo="MOTD File is missing")
                    # u":{server} 422 {self.identity.nick} :MOTD File is missing".format(**vars())

    def sendusermodes(self):
        with self.context.lock, self.lock:
            self.send(
                origin=self.bouncer.servname, cmd=221, target=self.context.identity,
                params="+{self.context.identity.modes}".format(**vars()))
            if "s" in self.context.identity.modes:
                self.send(
                    origin=self.bouncer.servname, cmd=8, target=self.context.identity,
                    params="+{self.context.identity.snomask}".format(**vars()), extinfo="Server notice mask")

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
                    try:
                        read = self.connection.recv(512)
                    except socket.error, msg:
                        self.quit(msg)
                        sys.exit()
                    except ssl.SSLError, msg:
                        self.quit(msg)
                        sys.exit()
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
                            self.quit("Access Denied")
                            print >>sys.stderr, "*** [BouncerConnection] Incoming connection from %s denied: Context not found." % (
                                self.host)
                            break
                        passmatch = hashlib.new(
                            conf.hashtype, passwd).hexdigest() == conf.passwd
                        with self.context.lock:
                            if not passmatch:
                                self.quit("Access Denied")
                                self.context.logwrite(
                                    "*** [BouncerConnection] Incoming connection from %s to %s denied: Invalid password." % (self.host, self.context))
                                self.bouncer.broadcast(
                                    self.context, origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                                    extinfo="Incoming connection from %s to %s denied: Invalid password." % (self.host, self.context))
                                # for client in self.bouncer.clients:
                                        # if client.context!=self.context:
                                                # continue
                                        # if not client.quitting:
                                                #client.send(origin=self.bouncer.servname, cmd="NOTICE", target=client.context.identity, extinfo="Incoming connection from %s to %s dened: Invalid password.\n" % (self.host, self.context))
                                break

                            self.context.logwrite(
                                "*** [BouncerConnection] Incoming connection from %s to %s established." % (self.host, self.context))
                            with self.bouncer.lock:
                                self.translations = dict(
                                    self.bouncer.conf[self.context].translations)
                                # Announce connection to all other bouncer
                                # clients.
                                self.bouncer.broadcast(
                                    self.context, origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                                    extinfo="Incoming connection from %s to %s established." % (self.host, self.context))
                                # for client in self.bouncer.clients:
                                        # if client.context!=self.context:
                                                # continue
                                        # if not client.quitting:
                                                #client.send(":*Bouncer* NOTICE %s :Incoming connection from %s to %s\n" % (client.context.identity.nick, self.host, self.context))
                                if len([client for client in self.bouncer.clients if client.context == self.context]) == 0 and self.context.registered and type(self.context.identity) == irc.User and self.context.identity.away:
                                        # Bouncer connection should
                                        # automatically return from away
                                        # status.
                                    self.context.raw("AWAY")
                                self.hidden = irc.ChanList(
                                    self.bouncer.conf[self.context].hidden, context=self.context)
                                self.bouncer.clients.append(self)

                            if self.context.registered:
                                # Send Greeting.
                                with self.lock:
                                    self.sendgreeting()
                                    self.sendsupports()
                                    self.sendmotd()
                                    self.sendusermodes()

                                    # Join user to channels.
                                    for channel in self.context.identity.channels:
                                        if channel not in self.hidden:
                                            self.showchannel(channel)
                            else:
                                self.send(
                                    origin=self.bouncer.servname, cmd="NOTICE", target=self.nick,
                                    extinfo="Not connected to server. Type /bncconnect to attempt connection.")
                                #self.send(u":%s 001 %s :Welcome to the Bouncer context Network %s!%s@%s\n" % ("*Bouncer*", self.nick, self.nick, self.username, self.host))
                    else:  # Client did not send USER command when expected
                        self.quit("Access Denied")
                        print "*** [BouncerConnection] Incoming connection from %s failed: Expected USER." % (self.host)
                        break

                else:
                    chantypes = self.context.supports.get(
                        "CHANTYPES", irc._defaultchantypes)
                    # Disable translating for now.
                    if False and cmd.upper() not in ("SETTRANSLATE", "RMTRANSLATE"):
                        translated = []
                        for targ in target.split(","):
                            translatefound = False
                            if re.match(irc._chanmatch % re.escape(chantypes), targ):
                                for channel, translate in self.translations.items():
                                    if targ.lower() == translate.lower():
                                        translated.append(channel.name)
                                        translatefound = True
                                        break
                            if not translatefound:
                                translated.append(targ)
                        target = ",".join(translated)

                        translated = []
                        for param in params.split(" "):
                            translatefound = False
                            if re.match(irc._chanmatch % re.escape(chantypes), param):
                                for channel, translate in self.translations.items():
                                    if param.lower() == translate.lower():
                                        translated.append(channel.name)
                                        translatefound = True
                                        break
                            if not translatefound:
                                translated.append(param)
                        params = " ".join(translated)

                        if params:
                            line = u"{cmd} {target} {params}".format(**vars())
                        elif target:
                            line = u"{cmd} {target}".format(**vars())
                        else:
                            line = cmd

                        if extinfo:
                            line = u"{line} :{extinfo}".format(**vars())

                    cmdmethod = "cmd%s" % cmd.upper()
                    if hasattr(self, cmdmethod):
                        method = getattr(self, cmdmethod)
                        try:
                            method(line, target, params, extinfo)
                        except SystemExit:
                            sys.exit()
                        except:
                            if self.context:
                                exc, excmsg, tb = sys.exc_info()
                                self.context.logwrite(*[u"!!! [BouncerConnection] Exception in thread %(self)s" % vars()] + [
                                                      u"!!! [BouncerConnection] %(tbline)s" % vars() for tbline in traceback.format_exc().split("\n")])
                            print >>sys.stderr, "Exception in thread %(self)s" % vars(
                            )
                            print >>sys.stderr, traceback.format_exc()
                    elif not self.context.connected:
                        self.send(
                            origin=self.bouncer.servname, cmd="NOTICE", target=self.nick,
                            extinfo="Not connected to server. Type /bncconnect to attempt connection.")
                        continue

                    elif not self.context.registered:
                        self.send(origin=self.bouncer.servname, cmd="NOTICE",
                                  target=self.nick, extinfo="Not registered.")
                        continue

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

            with self.bouncer.lock:
                if self in self.bouncer.clients:
                    self.bouncer.clients.remove(self)
                    if self.context.connected and self.context.identity and len([client for client in self.bouncer.clients if client.context == self.context]) == 0 and self.context.registered and type(self.context.identity) == irc.User and not self.context.identity.away and self.bouncer.autoaway:
                        # Bouncer automatically sets away status.
                        self.context.raw("AWAY :%s" % self.bouncer.autoaway)
                    self.bouncer.broadcast(
                        self.context, origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                        extinfo="Connection from %s to %s terminated (%s)\n" % (self.host, self.context, self.quitmsg))
                                    # ":*Bouncer* NOTICE %s :Connection from %s to %s terminated (%s)\n" % (client.context.identity.nick, self.host, self.context, self.quitmsg))

    def cmdQUIT(self, line, target, params, extinfo):
        self.quit(extinfo)
        sys.exit()

    def cmdPROTOCTL(self, line, target, params, extinfo):
        protoparams = [target.upper()] + params.upper().split()
        if "NAMESX" in protoparams:
            self.namesx = True
        if "UHNAMES" in protoparams:
            self.uhnames = True

    def cmdPING(self, line, target, params, extinfo):
        with self.context.lock:
            if True or (self.context.identity and type(self.context.identity) == irc.User):
                self.send(origin=self.bouncer.servname,
                          cmd="PONG", target=params, extinfo=target)
                    # u":{self.context.identity.server} PONG {params}
                    # :{target}\n".format(**vars()).encode("utf8"))
            else:
                self.send(origin=self.bouncer.servname,
                          cmd="PONG", params=params, extinfo=target)
                self.send(
                    u":{self.context.server} PONG {params} :{target}\n".format(**vars()).encode("utf8"))

    def cmdPRIVMSG(self, line, target, params, extinfo):
        # Check if CTCP
        ctcp = re.findall("^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$", extinfo)

        if ctcp:
            (ctcptype, ext) = ctcp[0]  # Unpack CTCP info

            if ctcptype == "LAGCHECK":  # Client is doing a lag check. No need to send to context network, just reply back.
                self.send(
                    u":{self.context.identity:full} {line}\n".format(**vars()).encode("utf8"))
            else:
                self.context.raw(line, origin=self)
        else:
            self.context.raw(line, origin=self)

    def cmdMODE(self, line, target, params, extinfo):  # Will want to determine is requesting modes, or attempting to modify modes.
        # if target and "CHANTYPES" in self.context.supports.keys() and
        # target[0] in self.context.supports["CHANTYPES"]:
        chantypes = self.context.supports.get(
            "CHANTYPES", irc._defaultchantypes)
        chanmodes = self.context.supports.get(
            "CHANMODES", irc._defaultchanmodes)
        prefix = self.context.supports.get("PREFIX", irc._defaultprefix)
        if re.match(irc._chanmatch % re.escape(chantypes), target):
            channel = self.context[target]

            if params == "":
                # We are requesting the modes for the channel
                if self.context.identity in channel.users:
                    # We are in the channel, and we know the channel modes
                    self.sendchannelmodes(channel)
                else:
                    # We are NOT in the channel, so we will forward the request
                    # to the server.
                    self.context.raw(
                        u"MODE {channel.name}".format(**vars()), origin=self)

            elif re.match("^\\+?[%s]+$" % chanmodes[0], params) and extinfo == "":
                # We are requesting one or more mode lists.
                modechars = ""
                for mode in params.lstrip("+"):
                    if mode not in modechars:
                        modechars += mode
                if self.context.identity in channel.users:
                    self.sendchannelmodes(channel, modechars)
                else:
                    self.context.raw(
                        u"MODE {channel.name} {params}".format(**vars()), origin=self)
            else:
                self.context.raw(line, origin=self)
        elif params == "" and target.lower() == self.context.identity.nick.lower():
            self.sendusermodes()
        else:
            self.context.raw(
                u"MODE {target} {params}".format(**vars()), origin=self)

    def cmdNAMES(self, line, target, params, extinfo):
        chantypes = self.context.supports.get(
            "CHANTYPES", irc._defaultchantypes)
        chanmodes = self.context.supports.get(
            "CHANMODES", irc._defaultchanmodes)
        prefix = self.context.supports.get("PREFIX", irc._defaultprefix)
        fallback = []
        with self.lock:
            for channame in target.split():
                if re.match(irc._chanmatch % re.escape(chantypes), channame):
                    channel = self.context[channame]
                    with self.lock:
                        if self.context.identity in channel:
                            self.sendchannelnames(channel)
                        else:
                            fallback.append(channame)
                else:
                    fallback.append(channame)
            if fallback:
                self.context.raw("NAMES %s" %
                                 (",".join(fallback)), origin=self)

    def cmdSHOW(self, line, target, params, extinfo):
        chantypes = self.context.supports.get(
            "CHANTYPES", irc._defaultchantypes)
        with self.context.lock, self.lock:
            for channame in target.split():
                if re.match(irc._chanmatch % re.escape(chantypes), channame):
                    channel = self.context[channame]
                    if channel in self.hidden:
                        if self.context.identity in channel:
                            self.showchannel(channel)
                        else:
                            self.hidden.remove(channel)
                            self.send(
                                origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                                extinfo="{channel.name} removed from hidden list, but not joined.".format(**vars()))
                    else:
                        self.send(
                            origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                            extinfo="{channel.name} not in hidden list.".format(**vars()))
                else:
                    self.send(
                        origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                        extinfo="{channame}: invalid channel name.".format(**vars()))

    def cmdHIDE(self, line, target, params, extinfo):
        chantypes = self.context.supports.get(
            "CHANTYPES", irc._defaultchantypes)
        with self.context.lock, self.lock:
            for channame in target.split():
                if re.match(irc._chanmatch % re.escape(chantypes), channame):
                    channel = self.context[channame]
                    if channel not in self.hidden:
                        if self.context.identity in channel:
                            self.send(
                                origin=self.context.identity, cmd="PART", target=channel, extinfo="Hiding channel")
                        else:
                            self.send(
                                origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                                extinfo="{channel.name} added to the hidden list, but not joined.".format(**vars()))
                        self.hidden.append(channel)
                    else:
                        self.send(
                            origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                            extinfo="{channel.name} already in hidden list.".format(**vars()))
                else:
                    self.send(
                        origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                        extinfo="{channame}: invalid channel name.".format(**vars()))

    def cmdSETTRANSLATE(self, line, target, params, extinfo):
        chantypes = self.context.supports.get(
            "CHANTYPES", irc._defaultchantypes)
        with self.context.lock, self.lock:
            if re.match(irc._chanmatch % re.escape(chantypes), target) and re.match(irc._chanmatch % re.escape(chantypes), target):
                channel = self.context[target]
                if self.context.supports.get("CASEMAPPING", "rfc1459") == "ascii":
                    translations_lower = [translation.translate(irc._rfc1459casemapping)
                                          for translation in self.translations.values()]
                    params_lower = params.translate(irc._rfc1459casemapping)
                else:
                    translations_lower = [translation.lower()
                                          for translation in self.translations.values()]
                    params_lower = params.lower()
                if params_lower in translations_lower:
                    self.send(
                        origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                        extinfo="Cannot set translation for {channel.name} to {param}.".format(**vars()))
                else:
                    self.send(origin=self.context.identity, cmd="PART",
                              target=channel, extinfo="Translating...")
                    self.translations[channel] = params
                    self.showchannel(channel)

    def cmdRMTRANSLATE(self, line, target, params, extinfo):
        chantypes = self.context.supports.get(
            "CHANTYPES", irc._defaultchantypes)
        with self.context.lock, self.lock:
            if re.match(irc._chanmatch % re.escape(chantypes), target):
                channel = self.context[target]
                if channel not in self.translations.keys():
                    self.send(
                        origin=self.bouncer.servname, cmd="NOTICE", target=self.context.identity,
                        extinfo="Cannot remove translation for {channel.name}.".format(**vars()))
                else:
                    self.send(origin=self.context.identity, cmd="PART",
                              target=channel, extinfo="Translating...")
                    del self.translations[channel]
                    self.showchannel(channel)
