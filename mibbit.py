#!/usr/bin/python
import re

class Mibbit(object):
	def onRecv(self, IRC, line, data):
		if data==None: return
		(origin, ident, host, cmd, target, params, extinfo)=data
		if len(target) and target[0]!="#":
			#print target
			#print cmd
			#print extinfo
			target=IRC.user(target)
			if cmd=="NOTICE" and target==IRC.identity:
				matches=re.findall("^\\*\\*\\* CONNECT: Client connecting on port ([0-9]+) \\(class (.*?)\\): (.+)!([0-9a-f]{8})@(.+\\.mibbit\\.com) \\((.+)\\) \\[(.+)\\]$",extinfo)
				#print matches
				"*** REMOTECONNECT: Client connecting at hypocrisy.insomniairc.net: B!463df443@ircip4.mibbit.com (109.169.29.95) [rrcs-70-61-244-67.central.biz.rr.com]"
				if matches:
					(port, cls, nick, hexip, mibbithost, mibbitip, host)=matches[0]
					IRC.raw("CHGHOST %s %s"%(nick, host))
					IRC.raw("CHGIDENT %s %s"%(nick, "mibbit"))
					IRC.raw("CHGNAME %s %s"%(nick, "Mibbit User"))
					return
				matches=re.findall("^\\*\\*\\* REMOTECONNECT: Client connecting at (.+?): (.+)!([0-9a-f]{8})@(.+\\.mibbit\\.com) \\((.+)\\) \\[(.+)\\]$",extinfo)
				#print matches
				"*** REMOTECONNECT: Client connecting at hypocrisy.insomniairc.net: B!463df443@ircip4.mibbit.com (109.169.29.95) [rrcs-70-61-244-67.central.biz.rr.com]"
				if matches:
					(remotehost, nick, hexip, mibbithost, mibbitip, host)=matches[0]
					IRC.raw("CHGHOST %s %s"%(nick, host))
					IRC.raw("CHGIDENT %s %s"%(nick, "mibbit"))
					IRC.raw("CHGNAME %s %s"%(nick, "Mibbit User"))
					return
