#!/usr/bin/python
import os
import re
import time


class SED(object):

    def __init__(self, expiry=1800):
        self.__name__ = "SED Bot"
        self.__version__ = "0.0.2"
        self.expiry = expiry
        self.history = []
        self.pattern1 = r"^!?s([,/#])(.*)$"
        self.pattern2 = r"^((?:[^{separator}]|\\[\\{separator}])*){separator}((?:[^{separator}]|\\[\\{separator}])*){separator}([igmv]*)$"

    def onChanMsg(self, IRC, user, channel, targetprefix, msg):
        matches = re.findall(self.pattern1, msg)
        if matches:
            separator, params = matches[0]
            matches2 = re.findall(
                self.pattern2.format(separator=re.escape(separator)), params)
            if matches2:
                find, replace, flags = matches2[0]
                find = re.sub(r"\\([\\{separator}])".format(
                    separator=re.escape(separator)), "\\1", find)
                replace = re.sub(
                    r"\\([\\{separator}])".format(separator=re.escape(separator)), "\\1", replace)
                match = False
                for t, IRC2, user2, channel2, msg2, isaction in self.history.__reversed__():
                    if channel != channel2:
                        continue
                    try:
                        if re.findall(find, msg2, flags=re.I if "i" in flags else 0):
                            sub = re.sub(
                                find, replace, msg2, flags=re.I if "i" in flags else 0)
                            match = True
                        else:
                            continue
                    except re.error, errmsg:
                        channel.msg(
                            "{user}: error: {errmsg}".format(**vars()), origin=self)
                        raise
                    if isaction:
                        channel.msg("What %s really meant was: *%s %s" %
                                    (user2.nick, user2.nick, sub), origin=self)
                    else:
                        if len(sub.replace("\r\n", "\n").replace("\r", "\n").split("\n")) > 3:
                            channel.msg(
                                "%s: Please do not abuse the bot." % (user.nick))
                        else:
                            channel.msg(
                                "What %s really meant to say was: %s" % (user2.nick, sub), origin=self)
                    break
                if not match:
                    channel.msg("%s: I tried. I really tried! But I could not find the pattern: %s" % (
                        user.nick, find), origin=self)
            else:
                channel.msg(
                    "{user}: Do you even lift?".format(**vars()), origin=self)
        else:
            self.history.append((time.time(), IRC, user, channel, msg, False))
        while len(self.history) and self.history[0][0] < time.time() - 1800:
            del self.history[0]

    def onSendChanMsg(self, IRC, origin, channel, targetprefix, msg):
        if origin != self:  # Ignore messages sent from THIS addon.
            self.onChanMsg(IRC, IRC.identity, channel, targetprefix, msg)

    def onChanAction(self, IRC, user, channel, targetprefix, action):
        self.history.append((time.time(), IRC, user, channel, action, True))
        while len(self.history) and self.history[0][0] < time.time() - 1800:
            del self.history[0]

    def onSendChanAction(self, IRC, origin, channel, targetprefix, action):
        if origin != self:  # Ignore messages sent from THIS addon.
            self.onChanAction(IRC, IRC.identity, channel, targetprefix, action)
