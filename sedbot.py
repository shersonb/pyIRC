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
		(origin, ident, host, cmd, target, params, extinfo)=data
		if len(target) and target[0]=="#": target=IRC.channel(target)
		if cmd=="PRIVMSG":
			matches=re.findall(self.pattern,extinfo)
			if matches:
				separator, find, replace, flags=matches[0]
				find=re.sub("\\\\([,/#\\\\])","\\1",find)
				replace=re.sub("\\\\(,/#\\\\)","\\1",replace)
				match=False
				for t, IRC2, (origin2, ident2, host2, cmd2, target2, params2, extinfo2) in self.history.__reversed__():
					if target!=IRC2.channel(target2): continue
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
				self.history.append((time.time(), IRC, data))
		while len(self.history) and self.history[0][0]<time.time()-1800: del self.history[0]
	def onSend(self, IRC, line, data, origin):
		if origin==self: return
		#print data
		(cmd, target, params, extinfo)=data
		if len(target) and target[0]=="#": target=IRC.channel(target)
		if cmd=="PRIVMSG":
			matches=re.findall(self.pattern,extinfo)
			#print matches
			if matches:
				separator, find, replace, flags=matches[0]
				find=re.sub("\\\\(.)","\\1",find)
				replace=re.sub("\\\\(.)","\\1",replace)
				match=False
				for t, IRC2, (origin2, ident2, host2, cmd2, target2, params2, extinfo2) in self.history.__reversed__():
					#print target
					#print target2
					#print IRC2.channel(target2)
					if target!=IRC2.channel(target2): continue
					try:
						if re.findall(find, extinfo2):
							sub=re.sub(find, replace, extinfo2, flags=re.I if "i" in flags else 0)
							#print sub
							target.msg("What %s really meant to say was: %s" % (origin2, sub), origin=self)
							match=True
							break
					except:
						target.msg("%s: Invalid syntax" % (origin), origin=self)
						raise
				if not match:
					target.msg("%s: I tried. I really tried! But I could not find the pattern: %s" % (IRC.identity.nick, find), origin=self)
			else:
				self.history.append((time.time(), IRC, (IRC.identity.nick, IRC.identity.idnt, IRC.identity.host)+data))
		while len(self.history) and self.history[0][0]<time.time()-1800: del self.history[0]
