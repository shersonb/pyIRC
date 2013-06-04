#!/usr/bin/python
import os, re, time

class SED(object):
	def __init__(self):
		self.__name__="SED Bot"
		self.__version__="0.0.1"
		self.history=[]
		self.pattern=r"^!s([,/#])((?:.|\\\1)*)\1((?:.|\\\1)*)\1([ig]*)$"
	def onRecv(self, IRC, line, data):
		if data==None: return
		self.replace(IRC, *data)
	def onSend(self, IRC, line, data, origin):
		if origin==self: return
		#print data
		(cmd, target, params, extinfo)=data
		self.replace(IRC, IRC.identity.nick, IRC.identity.idnt, IRC.identity.host, *data)
	def replace(self, IRC, origin, ident, host, cmd, target, params, extinfo):
		if len(target) and target[0]=="#" and cmd=="PRIVMSG":
			target=IRC.channel(target)
			matches=re.findall(self.pattern,extinfo)
			if matches:
				separator, find, replace, flags=matches[0]
				#print matches
				find=re.sub("\\\\([,/#\\\\])","\\1",find)
				replace=re.sub("\\\\(,/#\\\\)","\\1",replace)
				#print find, replace
				match=False
				#print self.history
				#print find
				#print replace
				for t, IRC2, (origin2, ident2, host2, cmd2, target2, params2, extinfo2) in self.history.__reversed__():
					#print target, target2, origin2, extinfo2
					if target!=target2: continue
					action=re.findall("^\x01ACTION\\s+(.*)\x01$", extinfo2)
					#print action
					if action:
						try:
							if re.findall(find, action[0]):
								sub=re.sub(find, replace, action[0], flags=re.I if "i" in flags else 0)
								target.msg("What %s really meant was: *%s %s" % (origin2, origin2, sub), origin=self)
								match=True
								break
						except:
							target.msg("%s: Invalid syntax" % (origin), origin=self)
							raise
					else:
						try:
							if re.findall(find, extinfo2):
								sub=re.sub(find, replace, extinfo2, flags=re.I if "i" in flags else 0)
								target.msg("What %s really meant to say was: %s" % (origin2, sub), origin=self)
								match=True
								break
						except:
							target.msg("%s: Invalid syntax" % (origin), origin=self)
							raise
				if not match:
					target.msg("%s: I tried. I really tried! But I could not find the pattern: %s" % (origin, find), origin=self)
			else:
				#print "History",(origin, ident, host, cmd, target, params, extinfo)
				self.history.append((time.time(), IRC, (origin, ident, host, cmd, target, params, extinfo)))
				#print self.history
		while len(self.history) and self.history[0][0]<time.time()-1800: del self.history[0]
		#print self.history
