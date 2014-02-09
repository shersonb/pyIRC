import os
import random
import re
import codecs


class quote(object):

    def __init__(self, quotefile="quotes.txt", encoding="utf8"):
        self.quotefile = quotefile
        self.encoding = encoding
        if os.path.isfile(quotefile):
            with codecs.open(quotefile, encoding=encoding) as f:
                self.quotes = [line for line in f]
        else:
            self.quotes = []

    def onChanMsg(self, IRC, user, channel, targetprefix, msg):
        matches = re.findall(
            r"^!quote(?:\s+(--add|--rem|--flush))?(?:\s+(.+?)\s*)?$", msg)
        if matches:
            cmd, msg = matches[0]
            if cmd == "" and msg == "":
                if self.quotes:
                    channel.msg(random.choice(self.quotes))
                else:
                    channel.msg("%s: There are no quotes!" % user.nick)
            elif cmd == "--add":
                if msg:
                    if msg not in self.quotes:
                        self.quotes.append(msg)
                        channel.msg("%s: Quote added." % user.nick)
                    else:
                        channel.msg("%s: Quote already exists." % user.nick)
                else:
                    channel.msg("%s: What am I adding?" % user.nick)
            elif cmd == "--rem":
                if msg:
                    if msg in self.quotes:
                        self.quotes.remove(msg)
                        channel.msg("%s: Quote removed." % user.nick)
                    else:
                        channel.msg("%s: Quote does not exist." % user.nick)
                else:
                    channel.msg("%s: What am I removing?" % user.nick)
            elif cmd == "--flush":
                with codecs.open(self.quotefile, "w", encoding=encoding) as f:
                    for line in self.quotes:
                        print >>f, line
            else:
                channel.msg(
                    "I am sorry, %s, but I cannot do that." % user.nick)

    def onSendChanMsg(self, IRC, channel, targetprefix, msg, origin):
        self.onChanMsg(IRC, IRC.identity, channel, targetprefix, msg)
