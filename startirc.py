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
import rlcompleter
readline.parse_and_bind("tab: complete")

networks = {}


def quit(quitmsg="Goodbye!"):
    global networks
    addons = []
    for IRC in networks.values():
        if IRC.isAlive():
            IRC.quit(quitmsg)
    while any([IRC.isAlive() for IRC in networks.values()]):
        time.sleep(0.25)
    for IRC in networks.values():
        for addon in list(IRC.addons):
            IRC.rmAddon(addon)
            if addon not in addons:
                addons.append(addon)
    for addon in addons:
        if "stop" in dir(addon) and callable(addon.stop) and "isAlive" in dir(addon) and callable(addon.isAlive) and addon.isAlive():
            try:
                addon.stop()
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

InsomniaIRC = networks["InsomniaIRC"] = irc.Connection(
    server="perseus.insomniairc.net", ipv6=False, ssl=True, log=open("/dev/null", "w"))

ax = autoexec.Autoexec()
log = logger.Logger(logroot)

### Be sure to generate your own cert.pem and key.pem files!
BNC = bouncer.Bouncer(
    "", 16698, ssl=True, certfile="cert.pem", keyfile="key.pem", autoaway="I'm off to see the wizard!")

for (label, IRC) in networks.items():
    IRC.addAddon(log, label=label)
    ### The password is 'hunter2'
    IRC.addAddon(BNC, label=label, passwd="6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22", hashtype="sha512")

InsomniaIRC.addAddon(ax, label="InsomniaIRC", autojoin=["#chat"])

for (label, IRC) in networks.items():
    IRC.start()