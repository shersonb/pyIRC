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
import irc
import codecs

modemapping = dict(Y="ircop", q="owner",
                   a="admin", o="op", h="halfop", v="voice")


def LoggerReload(log):
    newlog = Logger(logroot=log.logroot)
    with newlog.rotatelock, log.rotatelock:
        newlog.logs = log.logs
        log.logs = {}
    for context, label in log.labels.items():
        context.rmAddon(log)
        context.addAddon(newlog, label=label)
    return newlog


class Logger(Thread):

    def __init__(self, logroot):
        self.logroot = logroot
        path = [logroot]

        while not os.path.isdir(path[0]):
            split = os.path.split(path[0])
            path.insert(1, split[1])
            path[0] = split[0]

        while len(path) > 1:
            path[0] = os.path.join(*path[:2])
            del path[1]
            # print path
            os.mkdir(path[0])

        self.logs = {}
        self.labels = {}
        self.rotatelock = Lock()

        Thread.__init__(self)
        self.daemon = True
        self.start()

    def run(self):
        try:
            Y, M, D, h, m, s, w, d, dst = time.localtime()
            nextrotate = int(time.mktime((Y, M, D + 1, 0, 0, 0, 0, 0, -1)))
            while True:
                while nextrotate > time.time():  # May need to do this in a loop in case the following time.sleep command wakes up a second too early.
                    time.sleep(max(0.1, min((nextrotate - time.time(), 3600))))
                with self.rotatelock:
                    if all([not log or log.closed for log in self.logs.values()]):
                        break
                Y, M, D, h, m, s, w, d, dst = now = time.localtime()
                for context in self.labels.keys():
                    if context.connected:
                        with context.lock:
                            try:
                                self.rotateLog(context)
                            except:
                                exc, excmsg, tb = sys.exc_info()
                                context.logwrite(*["!!! [Logger] Exception in module %(module)s" % vars()] + [
                                                 "!!! [Logger] %s" % tbline for tbline in traceback.format_exc().split("\n")])
                            if context.identity:
                                for channel in context.identity.channels:
                                    try:
                                        self.rotateLog(channel)
                                    except:
                                        exc, excmsg, tb = sys.exc_info()
                                        context.logwrite(*["!!! [Logger] Exception in module %(module)s" % vars()] + [
                                                         "!!! [Logger] %s" % tbline for tbline in traceback.format_exc().split("\n")])
                                for user in context.users:
                                    if user in self.logs.keys():
                                        try:
                                            self.closeLog(user)
                                        except:
                                            exc, excmsg, tb = sys.exc_info()
                                            context.logwrite(*["!!! [Logger] Exception in module %(module)s" % vars()] + [
                                                             "!!! [Logger] %s" % tbline for tbline in traceback.format_exc().split("\n")])
                            context.logopen(
                                os.path.join(self.logroot, self.labels[context], "rawdata-%04d.%02d.%02d.log" % now[:3]))
                nextrotate = int(time.mktime((Y, M, D + 1, 0, 0, 0, 0, 0, -1)))
        finally:
            Thread.__init__(self)
            self.daemon = True

    def onAddonAdd(self, context, label):
        if label in self.labels.values():
            raise BaseException, "Label already exists"
        if context in self.labels.keys():
            raise BaseException, "Network already exists"
        if not os.path.isdir(os.path.join(self.logroot, label)):
            os.mkdir(os.path.join(self.logroot, label))
        self.labels[context] = label
        if context.connected:
            self.openLog(context)
            if context.identity:
                for channel in context.identity.channels:
                    self.openLog(channel)
        now = time.localtime()
        timestamp = reduce(lambda x, y: x + ":" + y, [
                           str(t).rjust(2, "0") for t in now[0:6]])
        context.logopen(
            os.path.join(self.logroot, self.labels[context], "rawdata-%04d.%02d.%02d.log" % now[:3]))

    def onAddonRem(self, context):
        if context.connected:
            for channel in self.logs.keys():
                if channel in context.channels:
                    if not self.logs[channel].closed:
                        self.closeLog(channel)
            for user in self.logs.keys():
                if user in context.users:
                    if not self.logs[user].closed:
                        self.closeLog(user)
            if context in self.logs.keys() and not self.logs[context].closed:
                self.closeLog(context)
        del self.labels[context]

    def openLog(self, window):
        with self.rotatelock:
            if not self.isAlive():
                self.start()

        if window in self.logs.keys():
            # Don't do anything
            return

        now = time.localtime()
        timestamp = reduce(lambda x, y: x + ":" + y, [
                           str(t).rjust(2, "0") for t in now[0:6]])
        if type(window) == irc.Connection:
            log = self.logs[window] = codecs.open(
                os.path.join(self.logroot, self.labels[window], "console-%04d.%02d.%02d.log" % now[:3]), "a", encoding="utf8")
            print >>log, "%s ### Log file opened" % (irc.timestamp())

        elif type(window) == irc.Channel:
            label = self.labels[window.context]
            log = self.logs[window] = codecs.open(os.path.join(self.logroot, label, "channel-%s-%04d.%02d.%02d.log" % (
                (urllib2.quote(window.name.lower().decode("utf8")).replace("/", "%2f"),) + now[:3])), "a", encoding="utf8")
            print >>log, "%s ### Log file opened" % (irc.timestamp())
            self.logs[window].flush()
            if window in window.context.identity.channels:
                if window.topic:
                    for line in window.fmttopic():
                        print >>log, "%s <<< %s" % (irc.timestamp(), line)
                if window.users:
                    for line in window.fmtnames(sort="mode"):
                        print >>log, "%s <<< %s" % (irc.timestamp(), line)
                if window.modes:
                    print >>log, "%s <<< %s" % (
                        irc.timestamp(), window.fmtmodes())
                if window.created:
                    print >>log, "%s <<< %s" % (
                        irc.timestamp(), window.fmtchancreated())

        if type(window) == irc.User:
            logname = os.path.join(self.logroot, self.labels[window.context], "query-%s-%04d.%02d.%02d.log" % (
                (urllib2.quote(window.nick.lower()).replace("/", "%2f"),) + now[:3]))
            for (other, log) in self.logs.items():
                if other == window:
                    continue
                if log.name == logname:
                    print >>log, "%s ### Log file closed" % (irc.timestamp())
                    del self.logs[other]
                    self.logs[window] = log
            if window not in self.logs.keys():
                log = self.logs[window] = codecs.open(
                    logname, "a", encoding="utf8")
            else:
                log = self.logs[window]
            print >>log, "%s ### Log file opened" % (irc.timestamp())
        log.flush()

    def closeLog(self, window):
        if window in self.logs.keys() and isinstance(self.logs[window], codecs.StreamReaderWriter) and not self.logs[window].closed:
            print >>self.logs[
                window], "%s ### Log file closed" % (irc.timestamp())
            self.logs[window].close()
        if window in self.logs.keys():
            del self.logs[window]

    def rotateLog(self, window):
        self.closeLog(window)
        self.openLog(window)

    def onConnectAttempt(self, context):
        if context not in self.logs.keys() or (not self.logs[context]) or self.logs[context].closed:
            self.openLog(context)
        ts = irc.timestamp()
        print >>self.logs[context], "%s *** Attempting connection to %s:%s." % (
            ts, context.server, context.port)

    def onConnect(self, context):
        if context not in self.logs.keys() or (not self.logs[context]) or self.logs[context].closed:
            self.openLog(context)
        ts = irc.timestamp()
        print >>self.logs[context], "%s *** Connection to %s:%s established." % (
            ts, context.server, context.port)

    def onConnectFail(self, context, exc, excmsg, tb):
        # Called when a connection attempt fails.
        if context not in self.logs.keys() or (not self.logs[context]) or self.logs[context].closed:
            self.openLog(context)
        ts = irc.timestamp()
        print >>self.logs[context], "%s *** Connection to %s:%s failed: %s." % (
            ts, context.server, context.port, excmsg)

    def onDisconnect(self, context, expected=False):
        ts = irc.timestamp()
        for window in self.logs.keys():
            if type(window) in (irc.Channel, irc.User) and window.context == context:
                print >>self.logs[window], "%s *** Connection to %s:%s terminated." % (
                    ts, context.server, context.port)
                self.logs[window].flush()
                self.closeLog(window)
        print >>self.logs[context], "%s *** Connection %s:%s terminated." % (
            ts, context.server, context.port)
        self.logs[context].flush()
        self.closeLog(context)

    def onJoin(self, context, user, channel):
        # Called when somebody joins a channel, includes bot.
        if user == context.identity:
            self.openLog(channel)
        ts = irc.timestamp()
        print >>self.logs[channel], "%s <<< :%s!%s@%s JOIN %s" % (
            ts, user.nick, user.username, user.host, channel.name)
        self.logs[channel].flush()

    def onChanMsg(self, context, user, channel, targetprefix, msg):
        # Called when someone sends a PRIVMSG to channel.
        ts = irc.timestamp()
        if type(user) == irc.User:
            classes = " ".join([modemapping[mode]
                               for mode in context.supports["PREFIX"][0] if mode in channel.modes.keys() and user in channel.modes[mode]])
            if classes:
                print >>self.logs[channel], "%s %s <<< :%s!%s@%s PRIVMSG %s%s :%s" % (
                    ts, classes, user.nick, user.username, user.host, targetprefix, channel.name, msg)
            else:
                print >>self.logs[channel], "%s <<< :%s!%s@%s PRIVMSG %s%s :%s" % (
                    ts, user.nick, user.username, user.host, targetprefix, channel.name, msg)
        elif type(user) in (str, unicode):
            classes = "server"
            print >>self.logs[channel], "%s %s <<< :%s PRIVMSG %s%s :%s" % (
                ts, classes, user, targetprefix, channel.name, msg)
        self.logs[channel].flush()

    def onChanAction(self, context, user, channel, targetprefix, action):
        self.onChanMsg(context, user, channel,
                       targetprefix, "\x01ACTION %s\x01" % action)

    def onChanNotice(self, context, origin, channel, targetprefix, msg):
        # Called when someone sends a NOTICE to channel.
        ts = irc.timestamp()
        if type(origin) == irc.User:
            classes = " ".join([modemapping[mode]
                               for mode in context.supports["PREFIX"][0] if mode in channel.modes.keys() and origin in channel.modes[mode]])
            if classes:
                print >>self.logs[channel], "%s %s <<< :%s!%s@%s NOTICE %s%s :%s" % (
                    ts, classes, origin.nick, origin.username, origin.host, targetprefix, channel.name, msg)
            else:
                print >>self.logs[channel], "%s <<< :%s!%s@%s NOTICE %s%s :%s" % (
                    ts, origin.nick, origin.username, origin.host, targetprefix, channel.name, msg)
        elif type(origin) in (str, unicode):
            classes = "server"
            print >>self.logs[channel], "%s %s <<< :%s NOTICE %s%s :%s" % (
                ts, classes, origin, targetprefix, channel.name, msg)
        self.logs[channel].flush()

    def onPart(self, context, user, channel, partmsg):
        # Called when somebody parts the channel, includes bot.
        ts = irc.timestamp()
        if partmsg:
            print >>self.logs[channel], "%s <<< :%s!%s@%s PART %s :%s" % (
                ts, user.nick, user.username, user.host, channel.name, partmsg)
        else:
            print >>self.logs[channel], "%s <<< :%s!%s@%s PART %s" % (
                ts, user.nick, user.username, user.host, channel.name)
        self.logs[channel].flush()
        if user == context.identity:
            self.closeLog(channel)

    def onKick(self, context, kicker, channel, kicked, kickmsg):
        # Called when somebody is kicked from the channel, includes bot.
        ts = irc.timestamp()
        if kickmsg:
            print >>self.logs[channel], "%s <<< :%s!%s@%s KICK %s %s :%s" % (
                ts, kicker.nick, kicker.username, kicker.host, channel.name, kicked.nick, kickmsg)
        else:
            print >>self.logs[channel], "%s <<< :%s!%s@%s KICK %s %s" % (
                ts, user.nick, user.username, user.host, channel.name, kicked.nick)
        self.logs[channel].flush()
        if kicked == context.identity:
            self.closeLog(channel)

    def onSendChanMsg(self, context, origin, channel, targetprefix, msg):
        # Called when bot sends a PRIVMSG to channel.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        ts = irc.timestamp()
        classes = " ".join([modemapping[mode]
                           for mode in context.supports["PREFIX"][0] if mode in channel.modes.keys() and context.identity in channel.modes[mode]])
        if classes:
            print >>self.logs[channel], "%s %s >>> :%s!%s@%s PRIVMSG %s%s :%s" % (
                ts, classes, context.identity.nick, context.identity.username, context.identity.host, targetprefix, channel.name, msg)
        else:
            print >>self.logs[channel], "%s >>> :%s!%s@%s PRIVMSG %s%s :%s" % (
                ts, context.identity.nick, context.identity.username, context.identity.host, targetprefix, channel.name, msg)
        self.logs[channel].flush()

    def onSendChanAction(self, context, origin, channel, targetprefix, action):
        # origin is the source of the channel message
        # Called when bot sends an action (/me) to channel.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        self.onSendChanMsg(
            context, origin, channel, targetprefix, "\x01ACTION %s\x01" % action)

    def onPrivMsg(self, context, user, msg):
        # Called when someone sends a PRIVMSG to the bot.
        if user not in self.logs.keys():
            self.openLog(user)
        ts = irc.timestamp()
        print >>self.logs[user], "%s <<< :%s!%s@%s PRIVMSG %s :%s" % (
            ts, user.nick, user.username, user.host, context.identity.nick, msg)
        self.logs[user].flush()

    def onPrivNotice(self, context, origin, msg):
        # Called when someone sends a NOTICE to the bot.
        ts = irc.timestamp()
        if type(origin) == irc.User:
            if origin not in self.logs.keys():
                self.openLog(origin)
            ts = irc.timestamp()
            print >>self.logs[origin], "%s <<< :%s!%s@%s NOTICE %s :%s" % (
                ts, origin.nick, origin.username, origin.host, context.identity.nick, msg)
            self.logs[origin].flush()
        else:
            print >>self.logs[context], "%s <<< :%s NOTICE %s :%s" % (
                ts, origin, context.identity.nick, msg)
            self.logs[context].flush()

    def onPrivAction(self, context, user, action):
        # Called when someone sends an action (/me) to the bot.
        self.onPrivMsg(context, user, "\x01ACTION %s\x01" % action)

    def onSendPrivMsg(self, context, origin, user, msg):
        # Called when bot sends a PRIVMSG to a user.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        if user not in self.logs.keys():
            self.openLog(user)
        ts = irc.timestamp()
        print >>self.logs[user], "%s >>> :%s!%s@%s PRIVMSG %s :%s" % (
            ts, context.identity.nick, context.identity.username, context.identity.host, user.nick, msg)
        self.logs[user].flush()

    def onSendPrivAction(self, context, origin, user, action):
        # Called when bot sends an action (/me) to a user.
        # The variable origin refers to a class instance voluntarily
        # identifying itself as that which requested data be sent.
        self.onSendPrivMsg(context, origin, user, "\x01ACTION %s\x01" % action)

    def onNickChange(self, context, user, newnick):
        # Called when somebody changes nickname.
        ts = irc.timestamp()
        line = "%s <<< :%s!%s@%s NICK %s" % (
            ts, user.nick, user.username, user.host, newnick)

        # Print nick change in each channel the user is in.
        for channel in user.channels:
            if channel in context.identity.channels:
                print >>self.logs[channel], line
                self.logs[channel].flush()

        # And in the query if open.
        if user in self.logs.keys():
            print >>self.logs[user], line
            self.logs[user].flush()

    def onMeNickChange(self, context, newnick):
        # Called when the bot changes nickname.

        # Print nick change to all open queries, except for query with self
        # (already done with onNickChange).
        ts = irc.timestamp()
        line = "%s <<< :%s!%s@%s NICK %s" % (
            ts, context.identity.nick, context.identity.username, context.identity.host, newnick)
        for (window, log) in self.logs.items():
            if type(window) == irc.User and window != context.identity:
                print >>log, line
                log.flush()

    def onQuit(self, context, user, quitmsg):
        # Called when somebody quits context.
        ts = irc.timestamp()
        if quitmsg:
            line = "%s <<< :%s!%s@%s QUIT :%s" % (
                ts, user.nick, user.username, user.host, quitmsg)
        else:
            line = "%s <<< :%s!%s@%s QUIT" % (
                ts, user.nick, user.username, user.host)

        # Print quit in each channel the user was in.
        for channel in user.channels:
            if channel in context.identity.channels and channel in self.logs.keys() and not self.logs[channel].closed:
                print >>self.logs[channel], line
                self.logs[channel].flush()

        # And in the query if open.
        if user in self.logs.keys():
            print >>self.logs[user], line
            self.logs[user].flush()
            self.closeLog(user)

    def onNames(self, context, origin, channel, flag, channame, nameslist):
        # Called when a NAMES list is received.
        if channel in self.logs.keys() and not self.logs[channel].closed:
            log = self.logs[channel]
        else:
            log = self.logs[context]
        ts = irc.timestamp()

        secret = "s" in channel.modes.keys() and channel.modes["s"]
        private = "p" in channel.modes.keys() and channel.modes["p"]
        modes, symbols = channel.context.supports["PREFIX"]
        print >>log, "%s <<< :%s 353 %s %s %s :%s" % (ts, origin, context.identity.nick, flag, channame,
                                                      " ".join(["%s%s!%s@%s" % (prefix, nick, username, host) if username and host else "%s%s" % (prefix, nick) for (prefix, nick, username, host) in nameslist]))
        log.flush()

    def onNamesEnd(self, context, origin, channel, channame, endmsg):
        if channel in self.logs.keys() and not self.logs[channel].closed:
            log = self.logs[channel]
        else:
            log = self.logs[context]
        ts = irc.timestamp()
        print >>log, "%s <<< :%s 366 %s %s :%s" % (
            ts, origin, context.identity.nick, channame, endmsg)
        log.flush()

    def onWhoisStart(self, context, origin, user, nickname, username, host, realname):
        # Called when a WHOIS reply is received.
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 311 %s %s %s %s * :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, username, host, realname)

    def onWhoisRegisteredNick(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 307 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, msg)

    def onWhoisAway(self, context, origin, user, nickname, awaymsg):
        # Called when a WHOIS reply is received.
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 301 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, awaymsg)

    def onWhoisConnectingFrom(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 378 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, msg)

    def onWhoisChannels(self, context, origin, user, nickname, chanlist):
        # Called when a WHOIS reply is received.
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 319 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, " ".join(chanlist))

    def onWhoisAvailability(self, context, origin, user, nickname, msg):
        # Called when a WHOIS reply is received.
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 310 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, msg)

    def onWhoisServer(self, context, origin, user, nickname, server, servername):
        # Called when a WHOIS reply is received.
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 312 %s %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, server, servername)

    def onWhoisOp(self, context, origin, user, nickname, msg):
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 313 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, msg)

    def onWhoisTimes(self, context, origin, user, nickname, idletime, signontime, msg):
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 317 %s %s %d %d :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, idletime, signontime, msg)

    def onWhoisSSL(self, context, origin, user, nickname, msg):
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 671 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, msg)

    def onWhoisModes(self, context, origin, user, nickname, msg):
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 339 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, msg)

    def onWhoisLoggedInAs(self, context, origin, user, nickname, loggedinas, msg):
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 330 %s %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, loggedinas, msg)

    def onWhoisEnd(self, context, origin, user, nickname, msg):
        if user not in self.logs.keys():
            self.openLog(user)
        print >>self.logs[user], "%s <<< :%s 318 %s %s :%s" % (
            irc.timestamp(), origin, context.identity.nick, nickname, msg)
        self.logs[user].flush()

    def onWhoEntry(self, context, **kwargs):
        # Called when a WHO list is received.
        pass

    def onWhoEnd(self, context, **kwargs):
        # Called when a WHO list is received.
        pass

    def onList(self, context, chanlistbegin, chanlist, endmsg):
        # Called when a channel list is received.
        pass

    def onTopic(self, context, origin, channel, topic):
        # Called when channel topic is received via 332 response.
        ts = irc.timestamp()
        if channel in self.logs.keys() and not self.logs[channel].closed:
            log = self.logs[channel]
        else:
            log = self.logs[context]
        print >>log, "%s <<< :%s 332 %s %s :%s" % (
            ts, origin, context.identity.nick, channel.name, topic)
        log.flush()

    def onTopicInfo(self, context, origin, channel, topicsetby, topictime):
        # Called when channel topic info is received via 333 response.
        ts = irc.timestamp()
        if channel in self.logs.keys() and not self.logs[channel].closed:
            log = self.logs[channel]
        else:
            log = self.logs[context]
        print >>log, "%s <<< :%s 333 %s %s %s %d" % (
            ts, origin, context.identity.nick, channel.name, topicsetby, topictime)
        log.flush()

    def onTopicSet(self, context, user, channel, topic):
        # Called when channel topic is changed.
        ts = irc.timestamp()
        if type(user) == irc.User:
            print >>self.logs[channel], "%s <<< :%s!%s@%s TOPIC %s :%s" % (
                ts, user.nick, user.username, user.host, channel.name, topic)
        else:
            print >>self.logs[channel], "%s <<< :%s TOPIC %s :%s" % (
                ts, user, channel.name, topic)
        self.logs[channel].flush()

    def onChanModeSet(self, context, user, channel, modedelta):
        # Called when channel modes are changed.
        # modedelta is a list of tuples of the format ("+x", parameter), ("+x",
        # None) if no parameter is provided.
        ts = irc.timestamp()
        modestr = ""
        params = []
        sign = ""
        for (sgn, modechar), param in modedelta:
            if sgn != sign:
                modestr += sgn
                sign = sgn
            modestr += modechar
            if param != None:
                params.append(param.nick if type(param) == irc.User else param)
        if len(params):
            if type(user) == irc.User:
                print >>self.logs[channel], "%s <<< :%s!%s@%s MODE %s %s %s" % (
                    ts, user.nick, user.username, user.host, channel.name, modestr, " ".join(params))
            else:
                print >>self.logs[channel], "%s <<< :%s MODE %s %s %s" % (
                    ts, user, channel.name, modestr, " ".join(params))
        else:
            if type(user) == irc.User:
                print >>self.logs[channel], "%s <<< :%s!%s@%s MODE %s %s" % (
                    ts, user.nick, user.username, user.host, channel.name, modestr)
            else:
                print >>self.logs[channel], "%s <<< :%s MODE %s %s" % (
                    ts, user, channel.name, modestr)
        self.logs[channel].flush()

    def onChannelModes(self, context, origin, channel, modedelta):
        # Called when channel modes are received via 324 response.
        ts = irc.timestamp()
        if channel in self.logs.keys() and not self.logs[channel].closed:
            log = self.logs[channel]
        else:
            log = self.logs[context]
        modestr = ""
        params = []
        sign = ""
        for (sgn, modechar), param in modedelta:
            if sgn != sign:
                modestr += sgn
                sign = sgn
            modestr += modechar
            if param != None:
                params.append(param)
        if len(params):
            print >>log, "%s <<< :%s 324 %s %s %s %s" % (
                ts, origin, context.identity.nick, channel.name, modestr, " ".join(params))
        else:
            print >>log, "%s <<< :%s 324 %s %s %s" % (
                ts, origin, context.identity.nick, channel.name, modestr)
        log.flush()

    def onChanCreated(self, context, origin, channel, created):
        # Called when a 329 response is received.
        ts = irc.timestamp()
        if channel in self.logs.keys() and not self.logs[channel].closed:
            log = self.logs[channel]
        else:
            log = self.logs[context]
        print >>log, "%s <<< :%s 329 %s %s %d" % (
            ts, origin, context.identity.nick, channel.name, created)
        log.flush()

    def onUnhandled(self, context, line, origin, cmd, target, params, extinfo, targetprefix):
        ts = irc.timestamp()
        print >>self.logs[context], "%s <<< %s" % (ts, line)
        self.logs[context].flush()
