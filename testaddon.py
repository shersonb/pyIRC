class Addon(object):
    def onAddonAdd(self, IRC, **params):
        ### Stuff you want the Addon to do when added or inserted into the addon list of an IRC instance.
        print "onAddonAdd:", IRC, params

    def onAddonRem(self, IRC):
        ### Stuff you want the Addon to do when removed from the addon list of an IRC instance.
        print "onAddonRem:", IRC

    def onSessionOpen(self, IRC):
        ### Called when the thread handling the IRC instance is started.
        print "onSessionOpen:", IRC

    def onSessionClose(self, IRC):
        ### Called when the thread handling the IRC instance is terminated.
        print "onSessionClose:", IRC

    def onConnectAttempt(self, IRC):
        ### Called when a connection attempt is made.
        print "onConnectAttempt:", IRC

    def onConnectFail(self, IRC, exc, excmsg, tb):
        ### Called when a connection attempt fails.
        print "onConnectFail:", IRC, exc, excmsg, tb

    def onConnect(self, IRC):
        ### Called when a connection is established.
        print "onConnect:", IRC

    def onRegistered(self, IRC):
        ### Called when registration is complete.
        print "onRegistered:", IRC

    def onDisconnect(self, IRC):
        ### Called when a connection is terminated.
        print "onDisconnect:", IRC

    def onRecv(self, IRC, line, origin=None, cmd=None, target=None, targetprefix=None, params=None, extinfo=None):
        ### Called when a line of data is received from the IRC server. If line also matches ":origin cmd target [params] :[extinfo]",
        ### then other variables are provided, with origin and target automatically converted to Channel and User instances as needed.
        pass

    def onSend(self, IRC, origin, line, cmd=None, target=None, targetprefix=None, params=None, extinfo=None):
        ### Called when a line of data is sent to the IRC server. If line also matches "cmd target [params] :[extinfo]",
        ### then other variables are provided, with target automatically converted to Channel and User instances as needed.
        ### The variable origin refers to a class instance voluntarily identifying itself as that which requested data be sent.
        pass

    def onMOTD(self, IRC, motdgreet, motd, motdend):
        ### Called when MOTD is received.
        print "onMOTD:", motdgreet
        for line in motd:
            print line
        print motdend

    def onJoin(self, IRC, user, channel):
        ### Called when somebody joins a channel, includes bot.
        print "onJoin:", user, channel

    def onMeJoin(self, IRC, channel):
        ### Called when the bot enters the channel.
        print "onMeJoin:", channel

    def onChanMsg(self, IRC, user, channel, targetprefix, msg):
        ### Called when someone sends a PRIVMSG to channel.
        print "onChanMsg: [%s%s] <%s> %s" % (
            targetprefix, channel.name, user.nick, msg)

    def onChanAction(self, IRC, user, channel, targetprefix, action):
        ### Called when someone sends an action (/me) to channel.
        print "onChanAction: [%s%s] *%s %s" % (
            targetprefix, channel.name, user.nick, action)

    def onSendChanMsg(self, IRC, origin, channel, targetprefix, msg):
        ### Called when bot sends a PRIVMSG to channel.
        ### The variable origin refers to a class instance voluntarily identifying itself as that which requested data be sent.
        print "onSendChanMsg: [%s%s] <%s> %s" % (
            targetprefix, channel.name, IRC.identity.nick, msg)

    def onSendChanAction(self, IRC, origin, channel, targetprefix, action):
        ### origin is the source of the channel message
        ### Called when bot sends an action (/me) to channel.
        ### The variable origin refers to a class instance voluntarily identifying itself as that which requested data be sent.
        print "onSendChanAction: [%s%s] *%s %s" % (
            targetprefix, channel.name, IRC.identity.nick, action)

    def onPrivMsg(self, IRC, user, msg):
        ### Called when someone sends a PRIVMSG to the bot.
        print "onPrivMsg: <%s> %s" % (user.nick, msg)

    def onPrivAction(self, IRC, user, action):
        ### Called when someone sends an action (/me) to the bot.
        print "onPrivAction: *%s %s" % (user.nick, action)

    def onSendPrivMsg(self, IRC, origin, user, msg):
        ### Called when bot sends a PRIVMSG to a user.
        ### The variable origin refers to a class instance voluntarily identifying itself as that which requested data be sent.
        print "onSendPrivMsg: <%s> %s" % (IRC.identity.nick, msg)

    def onSendPrivAction(self, IRC, origin, user, action):
        ### Called when bot sends an action (/me) to a user.
        ### The variable origin refers to a class instance voluntarily identifying itself as that which requested data be sent.
        print "onSendPrivAction: *%s %s" % (IRC.identity.nick, action)

    def onNickChange(self, IRC, user, newnick):
        ### Called when somebody changes nickname.
        print "onNickChange:", user, newnick

    def onMeNickChange(self, IRC, newnick):
        ### Called when the bot changes nickname.
        print "onMeNickChange:", newnick

    def onPart(self, IRC, user, channel, partmsg):
        ### Called when somebody parts the channel, includes bot.
        print "onPart:", user, channel, partmsg

    def onMePart(self, IRC, channel, partmsg):
        ### Called when the bot parts the channel.
        print "onMePart:", channel, partmsg

    def onKick(self, IRC, kicker, channel, kicked, kickmsg):
        ### Called when somebody is kicked from the channel, includes bot.
        print "onKick:", kicker, channel, kicked, kickmsg

    def onMeKick(self, IRC, channel, kicked, kickmsg):
        ### Called when the bot kicks somebody from the channel.
        print "onMeKick:", channel, kicked, kickmsg

    def onMeKicked(self, IRC, kicker, channel, kickmsg):
        ### Called when the bot is kicked from the channel.
        print "onMeKicked:", kicker, channel, kickmsg

    def onQuit(self, IRC, user, quitmsg):
        ### Called when somebody quits IRC.
        print "onQuit:", user, quitmsg

    def onNames(self, IRC, channel, channame, endmsg, nameslist):
        ### Called when a NAMES list is received.
        print "onNames:", channel, channame, endmsg, nameslist

    def onWhois(self, IRC, **whoisdata):
        ### Called when a WHOIS reply is received.
        print "onWhois:", whoisdata

    def onWho(self, IRC, params, wholist, endmsg):
        ### Called when a WHO list is received.
        print "onWho:", params
        for item in wholist:
            print item
        print endmsg

    def onList(self, IRC, chanlistbegin, chanlist, endmsg):
        ### Called when a channel list is received.
        print "onList:", chanlistbegin
        for item in chanlist:
            print item
        print endmsg

    def onTopic(self, IRC, channel, topic):
        ### Called when channel topic is received via 332 response.
        print "onTopic:", channel, topic

    def onTopicSet(self, IRC, user, channel, topic):
        ### Called when channel topic is changed.
        print "onChannelSet:", user, channel, topic

    def onChanModeSet(self, IRC, user, channel, modedelta):
        ### Called when channel modes are changed.
        ### modedelta is a list of tuples of the format ("+x", parameter), ("+x", None) if no parameter is provided.
        print "onChanModeSet:", user, channel, modedelta

    def onChannelModes(self, IRC, channel, modedelta):
        ### Called when channel modes are received via 324 response.
        print "onChannelModes:", channel, modedelta

    def onBan(self, IRC, user, channel, banmask):
        ### Called when a ban is set.
        print "onBan:", user, channel, banmask

    def onMeBan(self, IRC, user, channel, banmask):
        ### Called when a ban matching bot is set.
        print "Help! I'm being banned!", user, channel, banmask

    def onUnban(self, IRC, user, channel, banmask):
        ### Called when a ban is removed.
        print "onUnban:", user, channel, banmask

    def onMeUnban(self, IRC, user, channel, banmask):
        ### Called when a ban on the bot is removed.
        print "Squeee!!! I've been unbanned!", user, channel, banmask

    def onOp(self, IRC, user, channel, modeuser):
        ### Called when user gives ops to modeuser is set.
        print "onOp:", user, channel, modeuser

    def onMeOp(self, IRC, user, channel):
        ### Called when user ops bot.
        print "onMeOp", user, channel

    def onDeop(self, IRC, user, channel, modeuser):
        ### Called when user deops modeuser.
        print "onDeop:", user, channel, modeuser

    def onMeDeop(self, IRC, user, channel):
        ### Called when user deops bot.
        print "onMeDeop", user, channel

    ### There are a few other event handlers supported by the irc.Connection class. Furthermore, one can program
    ### numeric-based handlers to handle numeric events that are not captured by a named event handler as follows:

    def onNNN(self, IRC, params, extinfo):
        ### Where NNN is a three-digit (leading zeros if necessary) code used to handle a numeric NNN event.
        pass
