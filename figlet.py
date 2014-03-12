#!/usr/bin/python
import re
import os


class Figlet(object):

    def onChanMsg(self, IRC, user, channel, targetprefix, msg):
        matches = re.findall("^!figlet\\s+(.*)$", msg)
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
