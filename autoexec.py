#!/usr/bin/python
import re
import irc
import fnmatch


def AutoexecReload(old_ax):
    ax = Autoexec()
    for (context, conf) in old_ax.networks.items():
        context.rmAddon(old_ax)
        context.addAddon(ax, **conf.__dict__)
    return ax


class Autoexec(object):

    def __init__(self):
        self.networks = {}
        self._rejoinchannels = {}
            # Saved channels for when a connection is lost

    def onAddonAdd(self, context, label, onconnect=[], onregister=[], autojoin=[], usermodes=None, nsautojoin=[], nsmatch=None, wallet=None, opername=None, opermodes=None, snomasks=None, operexec=None, operjoin=[], autorejoin=True):
        labels = [v.label for v in self.networks.values()]
        if label in labels:
            raise BaseException, "Label already exists"
        if context in self.networks.keys():
            raise BaseException, "Network already exists"
        self.networks[context] = irc.Config(
            self, label=label, onconnect=list(onconnect), onregister=list(onregister), autojoin=irc.ChanList(autojoin, context=context),
            usermodes=usermodes, nsautojoin=irc.ChanList(nsautojoin, context=context), nsmatch=nsmatch, wallet=wallet,
            opername=opername, opermodes=opermodes, snomasks=snomasks, operexec=operexec, operjoin=irc.ChanList(operjoin, context=context), autorejoin=autorejoin)
        self._rejoinchannels[context] = None
        return self.networks[context]

    def onDisconnect(self, context, expected):
        conf = self.networks[context]
        if conf.autorejoin and not expected and context.identity and context.identity.channels:
            self._rejoinchannels[context] = irc.ChanList(
                context.identity.channels, context=context)  # Store a *copy* of the list of channels

    def onQuit(self, context, user, quitmsg):
        if user == context.identity and not context._quitexpected:
            # Bot received a QUIT message for itself, and was not expected.
            self.onDisconnect(context, False)

    def onAddonRem(self, context):
        del self.networks[context], self._rejoinchannels[context]

    def onConnect(self, context):
        conf = self.networks[context]
        if conf.onconnect:
            for line in conf.onconnect:
                context.raw(line, origin=self)

    def onRegistered(self, context):
        conf = self.networks[context]
        if conf.onregister:
            for line in conf.onregister:
                context.raw(line, origin=self)
        if conf.usermodes:
            context.raw("MODE %s %s" %
                        (context.identity.nick, conf.usermodes), origin=self)
        if conf.opername and conf.wallet and "%s/opers/%s" % (conf.label, conf.opername) in conf.wallet.keys():
            context.raw("OPER %s %s" %
                        (conf.opername, conf.wallet["%s/opers/%s" % (conf.label, conf.opername)]), origin=self)
        if conf.autojoin:
            conf.autojoin.join(origin=self)
        if conf.autorejoin and self._rejoinchannels[context]:
            rejoin = irc.ChanList([channel for channel in self._rejoinchannels[
                                  context] if channel not in conf.autojoin + conf.nsautojoin + conf.operjoin], context=context)
            if len(rejoin):
                rejoin.join(origin=self)
        self._rejoinchannels[context] = None

    def on381(self, context, line, origin, target, params, extinfo):
        conf = self.networks[context]
        if conf.operexec:
            for line in conf.operexec:
                context.raw(line, origin=self)
        if conf.opermodes:
            context.raw("MODE %s %s" %
                        (context.identity.nick, conf.opermodes), origin=self)
        if conf.snomasks:
            context.raw("MODE %s +s %s" %
                        (context.identity.nick, conf.snomasks), origin=self)
        if conf.operjoin:
            conf.operjoin.join(origin=self)

    def onPrivNotice(self, context, origin, msg):
        conf = self.networks[context]
        if type(origin) == irc.User and origin.nick.lower() == "nickserv":
            if re.match("This nickname is registered( and protected)?", msg) and (not conf.nsmatch or fnmatch.fnmatch("%s!%s@%s" % (origin.nick, origin.username, origin.host), conf.nsmatch)) and conf.wallet and "%s/NickServ/%s" % (conf.label, context.identity.nick.lower()) in conf.wallet.keys():
                origin.msg("identify %s" %
                           conf.wallet["%s/NickServ/%s" % (conf.label, context.identity.nick.lower())])
            if re.match("You are now identified", msg):
                if conf.nsautojoin:
                    conf.nsautojoin.join(origin=self)

    def on900(self, context, line, origin, target, params, extinfo):
        conf = self.networks[context]
        if conf.nsautojoin:
            conf.nsautojoin.join(origin=self)
