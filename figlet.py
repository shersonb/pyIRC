#!/usr/bin/python
import re
import os


class Figlet(object):
    def onRecv(self, IRC, line, data):
        if data is None:
            return
        (origin, ident, host, cmd, target, params, extinfo) = data
        if len(target) and target[0] == "#" and cmd == "PRIVMSG":
            channel = IRC.channel(target)
            matches = re.findall("^!figlet\\s+(.*)$", extinfo)
            if matches:
                gif, fig = os.popen2("figlet")
                gif.write(matches[0])
                gif.close()
                while True:
                    line = fig.readline()
                    if line == "":
                        break
                    if re.match("^\\s+$", line.rstrip()):
                        continue
                    channel.msg(line.rstrip())
                fig.close()
