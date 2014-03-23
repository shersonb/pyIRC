#!/usr/bin/python
import os
import re
import time
import signal
import sys
import irc
import modjson
import readline
import rlcompleter
import types
import code

nonaddontypes = (types.ModuleType, types.MethodType,
                 types.FunctionType, types.TypeType, irc.Connection)


class IRCApplication:

    def __init__(self, conffile=None):
        self._quitting = False
        self.conffile = conffile
        self.termcaught = False
        self.confdecoder = modjson.ModJSONDecoder()
        self.confencoder = modjson.ModJSONEncoder(indent=3)
        signal.signal(signal.SIGTERM, self.sigterm)
        self.namespace = {}
        if conffile and os.path.isfile(conffile):
            with open(conffile, "r") as f:
                pyirc = self.confdecoder.decode(f.read())
            if "addons" in pyirc.keys():
                self.namespace.update(pyirc["addons"])
            if "networks" in pyirc.keys():
                self.namespace.update(pyirc["networks"])
        self.shell = code.InteractiveConsole(locals=self.namespace)
        self.namespace["quit"] = self.quit
        self.namespace["save"] = self.save
        # self.namespace["exit"]=self.exit
        self.namespace["irc"] = irc

    def quit(self, quitmsg="Goodbye!"):
        networks = [
            o for o in self.namespace.values() if type(o) == irc.Connection]
        for context in networks:
            if type(context) == irc.Connection and context.isAlive():
                context.quit(quitmsg)
        for context in networks:
            if type(context) == irc.Connection:
                with context._disconnecting:
                    while context.connected:
                        context._disconnecting.wait(30)
                    if context._recvhandlerthread:
                        context._recvhandlerthread.join()
                    if context._sendhandlerthread:
                        context._sendhandlerthread.join()

    def complete(self, text, state):
        raise NotImplemented

    def start(self):
        sys.ps1 = "(ircapp) "
        sys.ps2 = "........ "
        readline.parse_and_bind("tab: complete")
        completer = rlcompleter.Completer(self.namespace)
        readline.set_completer(completer.complete)
        for o in self.namespace.values():
            if type(o) == irc.Connection:
                o.connect()
        while True:
            try:
                self.shell.interact(banner="Welcome to pyIRC!")
            except SystemExit, quitmsg:
                if not self._quitting:
                    if quitmsg.message:
                        self.quit(quitmsg.message)
                    else:
                        self.quit()
                break
            # In case CTRL+D is accidentally sent to the console.
            print "Ooops... Did you mean to do that?"

    def sigterm(self, signum, frame):
        if not self.termcaught:
            self.termcaught = True
            self.exit("Caught SIGTERM")

    def save(self, conffile=None):
        addons = {key: o for (key, o) in self.namespace.items()
                  if not isinstance(o, nonaddontypes) and not key.startswith("_")}
        extraaddons = []
        networks = {key: o for (key, o) in self.namespace.items() if type(
            o) == irc.Connection and not key.startswith("_")}
        if not conffile:
            conffile = self.conffile
        with open(conffile, "w") as f:
            print >>f, self.confencoder.encode(
                dict(addons=addons, networks=networks))

    def exit(self, quitmsg="Goodbye!"):
        self.quit(quitmsg)
        addons = [o for (key, o) in self.namespace.items()
                  if not isinstance(o, nonaddontypes) and not key.startswith("_")]
        networks = [o for (key, o) in self.namespace.items() if type(
            o) == irc.Connection and not key.startswith("_")]
        for context in networks:
            for conf in list(context.addons):
                addon = conf.addon if type(conf) == irc.Config else conf
                context.rmAddon(addon)
                if addon not in addons:
                    addons.append(addon)
        for addon in addons:
            if "stop" in dir(addon) and callable(addon.stop) and "isAlive" in dir(addon) and callable(addon.isAlive) and addon.isAlive():
                try:
                    addon.stop()
                except:
                    pass
        print "Quit: {quitmsg}".format(**vars())
        self._quitting = True
        sys.exit()

if __name__ == "__main__":
    ircapp = IRCApplication(
        sys.argv[1] if len(sys.argv) > 1 else "ircapp.conf")
    ircapp.start()
    ircapp.exit()
