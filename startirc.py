#!/usr/bin/python -i
import os
import re
import time
import logger
import signal
import figlet
import cannon
import wallet
import autoexec
import sys
import irc
import bouncer
import readline
readline.parse_and_bind("tab: complete")

networks = {}


def quit(quitmsg="Goodbye!"):
    global networks
    modules = []
    for IRC in networks.values():
        if IRC.isAlive():
            IRC.quit(quitmsg)
    while any([IRC.isAlive() for IRC in networks.values()]):
        time.sleep(0.25)
    for IRC in networks.values():
        for module in list(IRC.modules):
            IRC.rmModule(module)
            if module not in modules:
                modules.append(module)
    for module in modules:
        if "stop" in dir(module) and callable(module.stop) and "isAlive" in dir(module) and callable(module.isAlive) and module.isAlive():
            try:
                module.stop()
            except:
                pass
    print "Goodbye!"
    sys.exit()

termcaught = False


def sigterm(signum, frame):
    global termcaught
    if not termcaught:
        termcaught = True
        quit("Caught SIGTERM")

signal.signal(signal.SIGTERM, sigterm)

logroot = os.path.join(os.environ["HOME"], "IRC")

insomnialog = open(os.path.join(logroot, "insomnia.log"), "a")
InsomniaIRC = networks["InsomniaIRC"] = irc.Connection(
    server="irc.insomniairc.net", ipv6=False, ssl=True, log=insomnialog)

ax = autoexec.Autoexec()
log = logger.Logger(logroot)
BNC = bouncer.Bouncer(
    "", 16698, ssl=True, certfile="cert.pem", keyfile="key.pem")

for (label, IRC) in networks.items():
    IRC.addModule(log, label=label)
    ### The password is 'hunter2'
    IRC.addModule(BNC, label=label, passwd="6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22", hashtype="sha512")

InsomniaIRC.addModule(ax, label="InsomniaIRC", autojoin=["#chat"])

for (label, IRC) in networks.items():
    IRC.start()
