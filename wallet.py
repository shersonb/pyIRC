#!/usr/bin/python
import pickle, Crypto.Cipher.Blowfish, os, getpass
from threading import Lock

class Wallet(dict):
	def __init__(self, filename):
		self.lock=Lock()
		if os.path.isfile(filename):
			self.f=open(filename,"rb+")
			self.passwd=getpass.getpass()
			self.crypt=Crypto.Cipher.Blowfish.new(self.passwd)
			contents_encrypted=self.f.read()
			contents=self.crypt.decrypt(contents_encrypted+"\x00"*((-len(contents_encrypted))%8))
			if contents.startswith(self.passwd):
				self.update(dict(pickle.loads(contents[len(self.passwd):])))
			else:
				self.f.close()
				raise BaseException, "Incorrect Password"
		else:
			self.f=open(filename,"wb+")
			passwd=self.passwd=None
			while passwd==None or passwd!=self.passwd:
				passwd=getpass.getpass("Enter new password: ")
				self.passwd=getpass.getpass("Confirm new password: ")
				if passwd!=self.passwd: print "Passwords do not match!"
			self.crypt=Crypto.Cipher.Blowfish.new(self.passwd)
			self.flush()
	def flush(self):
		contents=self.passwd+pickle.dumps(self.items(), protocol=2)
		self.lock.acquire()
		try:
			self.f.seek(0)
			self.f.write(self.crypt.encrypt(contents+"\x00"*((-len(contents))%8)))
			self.f.truncate()
			self.f.flush()
		finally:
			self.lock.release()
