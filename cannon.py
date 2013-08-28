#!/usr/bin/python

import re
import os


class Cannon(object):
    def __init__(self):
        self.firecount = {}

    def onRecv(self, IRC, line, data):
        if data is None:
            return
        (origin, ident, host, cmd, target, params, extinfo) = data
        if len(target) and target[0] == "#" and cmd == "PRIVMSG":
            channel = IRC.channel(target)
            matches = re.findall("^!fire\\s+(.*)$", extinfo)
            if matches:
                nickname = matches[0]
                if any([nickname.lower() == user.nick.lower() for user in channel.users]):
                    user = IRC.user(nickname)
                    if user in self.firecount.keys():
                        count = self.firecount[user]+1
                    else:
                        count = 1
                    self.firecount[user] = count
                    if 10 <= count%100 < 20:
                        ordinal = "th"
                    elif count%10 == 1:
                        ordinal = "st"
                    elif count%10 == 2:
                        ordinal = "nd"
                    elif count%10 == 3:
                        ordinal = "rd"
                    else:
                        ordinal = "th"
                    channel.me("fires %s out of a cannon for the %d%s time." %
                               (user.nick, count, ordinal))
                else:
                    channel.msg("%s: I cannot fire %s out of a cannon, as he or she is not here."%(origin, nickname))
