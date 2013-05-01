#!/usr/bin/python
import socket, ssl, os, re, time, sys, string
from threading import Thread
import Queue

class Bouncer (Thread):
	def __init__(self, addr, port, servers, ssl=False, certfile=None, keyfile=None, ignore=None):
		self.__name__="Bouncer for pyIRC"
		self.__version__="1.0.0alpha1"
		self.__author__="Brian Sherson"
		self.__date__="Apr 21, 2013"
		#print "Initializing ListenThread..."
		self.addr=addr
		self.port=port
		self.servers=servers
		self.socket=s=socket.socket()
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.ssl=ssl
		self.certfile=certfile
		self.keyfile=keyfile
		s.bind((self.addr,self.port))
		self.connections=[]
		for server in servers.values(): server.modules.append(self)
		self.ignore=ignore
		self.whoexpected=[]
		Thread.__init__ ( self )

	def run(self):
		self.socket.listen(5)
		#print ((self,"Now listening on port "+str(self.port)))
		while True:
			try:
				(connection,addr)=self.socket.accept()
				if self.ssl:
					connection=ssl.wrap_socket(connection, server_side=True, certfile=self.certfile, keyfile=self.keyfile, ssl_version=ssl.PROTOCOL_SSLv23)
				try:
					hostname, aliaslist, addresslist = socket.gethostbyaddr(addr[0])
					addr = (hostname, addr[1])
				except:
					pass
				#print ((self,"New client connecting from %s:%s"%addr))
			except socket.error:
				print "Shutting down Listener"
				self.socket.close()
				#raise
				sys.exit()
			bouncer=BouncerConnection(self, connection, addr)
			bouncer.daemon=True
			#self.connections.append(bouncer)
			bouncer.start()
			#ccrecv.start()
			time.sleep(0.5)
		try:
			self.socket.close()
		except: pass
	def onRecv(self, IRC, line, data):
		if type(self.ignore) not in (list, tuple) or all([not re.match(pattern, line) for pattern in self.ignore]):
			if data:
				(origin, ident, host, cmd, target, params, extinfo)=data
				#print data
				if cmd=="352": ### Who reply
					if len(self.whoexpected) and self.whoexpected[0] in self.connections and self.whoexpected[0].IRC==IRC:
						self.whoexpected[0].connection.send(line+"\n")
				elif cmd=="315": ### End of Who reply
					if len(self.whoexpected) and self.whoexpected[0] in self.connections and self.whoexpected[0].IRC==IRC:
						self.whoexpected[0].connection.send(line+"\n")
					del self.whoexpected[0]
				else:
					for bouncer in self.connections:
						#print bouncer.IRC
						#print IRC
						#print line
						if bouncer.IRC==IRC: bouncer.connection.send(line+"\n")
	def onSend(self, IRC, line, data, origin):
		#print "Bouncer onSend"
		if type(self.ignore) not in (list, tuple) or all([not re.match(pattern, line) for pattern in self.ignore]):
			(cmd, target, params, extinfo)=data
			if cmd in ("PRIVMSG", "NOTICE"):
				for bouncer in self.connections:
					if bouncer==origin: continue
					#print bouncer.IRC
					#print IRC
					if bouncer.IRC==IRC: bouncer.connection.send(":%s!%s@%s %s\n" % (bouncer.IRC.identity.nick, bouncer.IRC.identity.idnt, bouncer.IRC.identity.host, line))
			elif cmd=="WHO":
				#print origin, line
				self.whoexpected.append(origin)
	def stop(self):
		self.socket.shutdown(0)
	def onDisconnect(self, IRC):
		for bouncer in self.connections:
			if bouncer.IRC==IRC:
				quitmsg="Bouncer has been disconnected from IRC"
				try:
					bouncer.connection.send("ERROR :Closing link: (%s@%s) [%s]\n" % (self.nick, self.addr[0], quitmsg))
					bouncer.connection.close()
					bouncer.connection.shutdown(0)
				except:
					pass
				if bouncer in self.connections:
					self.connections.remove(bouncer)

class BouncerConnection (Thread):
	def __init__(self, bouncerlistener, connection, addr):
		#print "Initializing ListenThread..."
		self.bouncerlistener=bouncerlistener
		self.connection=connection
		self.addr=addr
		self.IRC=None
		self.pwd=None
		self.nick=None
		self.idnt=None
		self.realname=None
		self.addr=addr
		Thread.__init__ ( self )

	def stop(self):
		self.connection.shutdown(0)

	def run(self):
		#print "Bouncer Connection Started"
		r=self.connection.makefile("r")
		w=self.connection.makefile("w")
		k=0
		while self.pwd==None or self.nick==None or self.idnt==None:
			line=r.readline().rstrip()
			match=re.findall("^PASS :?(.*)$", line, re.I)
			if match:
				self.pwd=match[0]
			match=re.findall("^NICK :?(.*)$", line, re.I)
			if match:
				self.nick=match[0]
			match=re.findall("^USER\\s+(.+?)\\s+(.+?)\\s+(.+?):(.*)$", line, re.I)
			if match:
				self.idnt, a, b, self.realname=match[0]
			if k>10:
				self.connection.send("ERROR :Closing link: (%s@%s) [Access Denied]\n" % (self.nick, self.addr[0]))
				self.connection.close()
				sys.exit()
			k+=1
		for idnt, pwd in self.bouncerlistener.servers.keys():
			if idnt.lower()==self.idnt.lower() and pwd==self.pwd:
				self.IRC=self.bouncerlistener.servers[idnt, pwd]
		if self.IRC==None or not self.IRC.registered:
			self.connection.send("ERROR :Closing link: (%s@%s) [Access Denied]\n" % (self.nick, self.addr[0]))
			self.connection.close()
			sys.exit()

		for bouncer in self.bouncerlistener.connections:
			try:
				bouncer.connection.send(":%s!%s@%s NOTICE %s :*** Bouncer Connection to %s originated from %s\n" % (self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, bouncer.IRC.identity.nick, self.IRC, self.addr[0]))
			except:
				self.bouncerlistener.connections.remove(bouncer)

		self.connection.send(":%s 001 %s :%s\n" % (self.IRC.serv, self.IRC.identity.nick, self.IRC.welcome))
		self.connection.send(":%s 002 %s :%s\n" % (self.IRC.serv, self.IRC.identity.nick, self.IRC.hostinfo))
		self.connection.send(":%s 003 %s :%s\n" % (self.IRC.serv, self.IRC.identity.nick, self.IRC.servinfo))
		self.connection.send(":%s 004 %s %s\n" % (self.IRC.serv, self.IRC.identity.nick, self.IRC.serv004))
		for params in self.IRC.serv005:
			self.connection.send(":%s 005 %s %s :are supported by this server\n" % (self.IRC.serv, self.IRC.identity.nick, params))

		self.connection.send(":%s 375 %s :%s\n" % (self.IRC.serv, self.IRC.identity.nick, self.IRC.motdgreet))
		for motdline in self.IRC.motd:
			self.connection.send(":%s 372 %s :%s\n" % (self.IRC.serv, self.IRC.identity.nick, motdline))
		self.connection.send(":%s 376 %s :%s\n" % (self.IRC.serv, self.IRC.identity.nick, self.IRC.motdend))

		self.connection.send(":%s 221 %s +%s\n" % (self.IRC.serv, self.IRC.identity.nick, self.IRC.identity.modes))
		if "s" in self.IRC.identity.modes and self.IRC.identity.snomask:
			self.connection.send(":%s 008 %s +%s :Server notice mask\n" % (self.IRC.server, self.IRC.identity.nick, self.IRC.identity.snomask))

		for channel in self.IRC.identity.channels:
			self.connection.send(":%s!%s@%s JOIN :%s\n" % (self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, channel.name))
			self.connection.send(":%s 332 %s %s :%s\n" % (self.IRC.serv, self.IRC.identity.nick, channel.name, channel.topic))
			self.connection.send(":%s 333 %s %s %s %s\n" % (self.IRC.serv, self.IRC.identity.nick, channel.name, channel.topicsetby, channel.topictime))
			secret="s" in channel.modes.keys() and channel.modes["s"]
			private="p" in channel.modes.keys() and channel.modes["p"]
			namesusers=[]
			modes, symbols=self.IRC.supports["PREFIX"]
			self.connection.send(":%s 353 %s %s %s :%s\n" % (
				self.IRC.serv,
				self.IRC.identity.nick,
				"@" if secret else ("*" if private else "="),
				channel.name,
				string.join([string.join([symbols[k] if modes[k] in channel.modes.keys() and user in channel.modes[modes[k]] else "" for k in xrange(len(modes))],"")+user.nick for user in channel.users]))
				)

		self.bouncerlistener.connections.append(self)

		quitmsg="Connection Closed"
		readbuf=""
		linebuf=[]

		while True:
			while len(linebuf)==0:
				timestamp=reduce(lambda x,y: x+":"+y,[str(t).rjust(2,"0") for t in time.localtime()[0:6]])
				try:
					read=self.connection.recv(512)
				except:
					exc,excmsg,tb=sys.exc_info()
					print >>sys.stderr, "%(timestamp)s *** %(exc)s: %(excmsg)s" % vars()
					server, port=self.addr
					#server=self.addr[0]
					#port=self.port
					print >>sys.stderr, "%(timestamp)s *** Connection from %(server)s:%(port)s terminated" % vars()
					self.bouncerlistener.connections.remove(self)
					sys.stderr.flush()
					raise
				if read=="":
					server, port=self.addr
					#port=self.port
					print >>sys.stderr, "%(timestamp)s *** Connection from %(server)s:%(port)s terminated" % vars()
					self.bouncerlistener.connections.remove(self)
					sys.stderr.flush()
					sys.exit()
				readbuf+=read
				lastlf=readbuf.rfind("\n")
				if lastlf>=0:
					linebuf.extend(string.split(readbuf[0:lastlf], "\n"))
					readbuf=readbuf[lastlf+1:]

			line=string.rstrip(linebuf.pop(0))

			match=re.findall("^(.+?)(?:\\s+(.+?)(?:\\s+(.+?))??)??(?:\\s+:(.*))?$", line, re.I)
			if len(match)==0: continue
			(cmd, target, params, extinfo)=match[0]

			if cmd.upper()=="QUIT":
				quitmsg=extinfo
				break
			elif cmd.upper()=="PING":
				try:
					self.connection.send(":%s PONG %s :%s\n" % (self.IRC.serv, self.IRC.serv, self.IRC.identity.nick))
				except:
					sys.exit()
				continue
			elif cmd.upper() in ("PRIVMSG", "NOTICE"):
				#print line
				ctcp=re.findall("^\x01(.*?)(?:\\s+(.*?)\\s*)?\x01$",extinfo)
				if ctcp:
					(ctcptype,ext)=ctcp[0]
					if ctcptype=="LAGCHECK":
						try:
							self.connection.send(":%s!%s@%s %s\n" % (self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, line))
						except:
							self.connection.remove(self)
							sys.exit()
					elif ctcptype=="ACTION":
						self.IRC.raw(line, origin=self)
						#for bouncer in self.bouncerlistener.connections:
						#	if bouncer!=self and bouncer.IRC==self.IRC:
						#		try:
						#			bouncer.connection.send(":%s!%s@%s %s\n"%(self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, line))
						#		except:
						#			self.bouncerlistener.connections.remove(bouncer)
					else:
						self.IRC.raw(line, origin=self)
				else:
					self.IRC.raw(line, origin=self)
					#for bouncer in self.bouncerlistener.connections:
					#	if bouncer!=self and bouncer.IRC==self.IRC:
					#		try:
					#			bouncer.connection.send(":%s!%s@%s %s\n"%(self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, line))
					#		except:
					#			self.bouncerlistener.connections.remove(bouncer)
			elif cmd.upper() == "MODE":
				#print "ddd", target, params, self.IRC.supports["CHANTYPES"]
				if target and target[0] in self.IRC.supports["CHANTYPES"]:
					if params=="":
						channel=self.IRC.channel(target)
						modes=channel.modes.keys()
						modestr="".join([mode for mode in modes if mode not in self.IRC.supports["CHANMODES"][0]+self.IRC.supports["PREFIX"][0] and channel.modes[mode]])
						params=" ".join([channel.modes[mode] for mode in modes if mode in self.IRC.supports["CHANMODES"][1]+self.IRC.supports["CHANMODES"][2] and channel.modes[mode]])
						self.connection.send(":%s 324 %s %s +%s %s\n" % (self.IRC.server, self.IRC.identity.nick, channel.name, modestr, params))
					elif re.match("^\\+?[%s]+$"%self.IRC.supports["CHANMODES"][0], params) and extinfo=="":
						#print "ddd Mode List Request", params
						channel=self.IRC.channel(target)
						listnumerics=dict(b=(367, 368, "channel ban list"), e=(348, 349, "Channel Exception List"), I=(346, 347, "Channel Invite Exception List"), w=(910, 911, "Channel Access List"), g=(941, 940, "chanel spamfilter list"), X=(954, 953, "channel exemptchanops list"))
						redundant=[]
						for mode in params.lstrip("+"):
							if mode in redundant or mode not in listnumerics.keys(): continue
							i,e,l=listnumerics[mode]
							if mode in channel.modes.keys():
								for (mask, setby, settime) in channel.modes[mode]:
									self.connection.send(":%s %d %s %s %s %s %s\n" % (self.IRC.server, i, channel.context.identity.nick, channel.name, mask, setby, settime))
							self.connection.send(":%s %d %s %s :End of %s\n" % (self.IRC.server, e, channel.context.identity.nick, channel.name, l))
							redundant.append(mode)
					else:
						self.IRC.raw(line, origin=self)
				elif params=="" and target.lower()==self.IRC.identity.lower():
					self.connection.send(":%s 221 %s +%s\n" % (self.IRC.server, self.IRC.identity.nick, channel.name, self.IRC.identity.modes))
					if "s" in self.IRC.identity.modes and self.IRC.identity.snomask:
						self.connection.send(":%s 008 %s +%s :Server notice mask\n" % (self.IRC.server, self.IRC.identity.nick, channel.name, self.IRC.identity.snomask))
				else:
					self.IRC.raw(line, origin=self)
			else:
				self.IRC.raw(line, origin=self)



			continue
			#print line
			match=re.findall("^quit(?:\\s:?(.*))?$", line, re.I)
			#print match
			if match:
				quitmsg=match[0]
				break
			else:
				#match=re.findall("^ping(?:\\s.*:?(.*))?$", line)
				self.IRC.raw(line)
				match=re.findall("^PRIVMSG (\\S+) :(.*)$", line, re.I)
				#print match
				if match:
					(origin, ident, host, cmd, params)=(self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, "PRIVMSG", "")
					target, extinfo=match[0]
					data=(origin, ident, host, cmd, target, params, extinfo)
					modules=list(self.IRC.modules)
					for channel in self.IRC.channels:
						for module in channel.modules:
							if module not in modules: modules.append(module)
					for module in set(modules):
						if module!=self.bouncerlistener:
							#print ":%s!%s@%s %s"%(self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, line)
							try:
								module.process(self.IRC, ":%s!%s@%s %s"%(self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, line), data)
							except:
								pass
						else:
							for bouncer in self.bouncerlistener.connections:
								if bouncer!=self and bouncer.IRC==self.IRC:
									try:
										bouncer.connection.send(":%s!%s@%s %s\n"%(self.IRC.identity.nick, self.IRC.identity.idnt, self.IRC.identity.host, line))
									except:
										self.bouncerlistener.connections.remove(bouncer)
		self.connection.send("ERROR :Closing link: (%s@%s) [%s]\n" % (self.nick, self.addr[0], quitmsg))
		self.connection.close()
		self.bouncerlistener.connections.remove(self)
