#!/usr/bin/python3

# Student name and No.:     WANG Haicheng 3035140108
# Student name and No.:     N/A
# Development platform:     Ubuntu 1604
# Python version: 			Python 3.5.2
# Version: 					0.1


from tkinter import *
import sys
import socket
import re
import threading
import time


#
# Global constant
#
BUFSIZ = 1024
PROTOCALEND = '::\r\n'
#
# Global variables
#
States = {'STARTED'    : 0,
		  'NAMED'      : 1,
		  'JOINED'	   : 2,
		  'CONNECTED'  : 3,
		  'TERMINATED' : 4 }


Actions = {'USER' 	   : 5,
		   'LIST' 	   : 6,
		   'JOIN' 	   : 7,
		   'SEND' 	   : 8,
		   'QUIT' 	   : 9,
		   'HANDSHAKE' : 10} 

Exceptions = {'INVALID_USERNAME' : 11}
currentState = None
user = None
stateLock = threading.Lock()
userInfoLock = threading.Lock()

class User():
	def __init__(self , serverIP, serverPort, 
					localIP , localPort):
		self._setip(localIP)
		self._setportnumber(localPort)
		self._username = None
		self._clientSocket = None
		self._serverSocket = None
		## here we define the username validation rule
		self.validation = re.compile("^[\x00-\x7F]+$")
		self._socketSetup(serverIP, serverPort, localIP, localPort)
	def _socketSetup(self, serverIP, serverPort, localIP, localPort):
		print("setting up user socket...")
		self._clientSocket = socket.socket()
		self._serverSocket = socket.socket()
		# connect with room server with clientsocket
		try:
			self._clientSocket.connect((serverIP, serverPort))
		except socket.error as errmsg:
			print('Failed to connect to roomServer: ', errmsg)
			self._clientSocket.close()
			sys.exit(1)
		try:
			self._serverSocket.bind((localIP,localPort))
		except socket.error as emsg:
			print("Socket bind error: ", emsg)
			self._serverSocket.close()
			sys.exit(1)
		print('finish setting user socket: connected to roomserver[',
				serverIP,',',serverPort,'], listening at port ', localPort)
	def _setname(self, name):
		self._username = name
	def _setip(self, ip):
		self._IP = ip
	def _setportnumber(self, port):
		self._port = port
	def _getname(self):
		return self._username
	def _getip(self):
		return self._IP
	def _getport(self):
		return self._port
	def _getClientSocket(self):
		return self._clientSocket
	def _getServerSocket(self):
		return self._serverSocket
	def hasUserName(self):
		return self._getname() is not None
	def setUserName(self, username):
		# check first
		if (self.validation.match(username) is None) or (':' in username):
			return Exceptions['INVALID_USERNAME']
		self._setname(username)

class State():
	def __init__(self):
		self._setstate(0)
		self._setroomname(None)
		self._setroominfo(None)

	def _setstate(self,state):
		self._state = state
	def _getstate(self):
		return self._state
	def _setroomname(self,name):
		self._roomname = name
	def _getroomname(self):
		return self._roomname
	def _setroominfo(self,info):
		self._roominfo = info
	def _getroominfo(self):
		return self._roominfo
	def stateTransition(self, action):
		self._setstate(transition(self._getstate,action))
	def updateRoomName(self, roomName):
		self._setroomname(roomName)
	def updateRoomInfo(self, roomInfo):
		if self._getroominfo() is None:
			self._setroominfo(roomInfo)
		else if self._getroominfo()[0] != roomInfo[0]:
			self._setroominfo(roomInfo)
		else:
			print('room member list: duplicated info, do not update')
#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff

# five facilited state transition functions:
def FromStarted(action):
	return {Actions['LIST']: States['STARTED'], 
			Actions['USER']: States['NAMED'],
			Actions['QUIT']: States['TERMINATED']}[action]

def FromNamed(action):
	return {Actions['LIST']: States['NAMED'],
			Actions['USER']: States['NAMED'],
			Actions['JOIN']: States['JOINED'],
			Actions['QUIT']: States['TERMINATED']}[action]

def FromJoined(action):
	return {Actions['LIST']: States['JOINED'],
			Actions['SEND']: States['JOINED'],
			Actions['HANDSHAKE']: States['CONNECTED'],
			Actions['QUIT']: States['TERMINATED']}[action]

def FromConnected(action):
	return {Actions['LIST']: States['CONNECTED'],
			Actions['SEND']: States['CONNECTED'],
			Actions['QUIT']: States['TERMINATED']}[action]

# state transition function, critical, calling should be protected by logic
def transition(currentState, action):
	return {States['STARTED']: lambda x: FromStarted(x),
	 		States['NAMED']: lambda x: FromNamed(x),
	 		States['JOINED']: lambda x: FromJoined(x),
	 		States['CONNECTED']: lambda x: FromConnected(x)}[currentState](action)
#
# functions for facilitation threads
def keepAliveThread()
	global currentState, user
	while True:
		userInfoLock.acquire()
		clientsocket = user._getClientSocket()
		message = ':'.join([currentState._getroomname(), user._getname(), user._getip(), str(user._getport())])
		requestMessage = 'J:' + message + PROTOCALEND
		try:
			requestSocket.send(requestMessage.encode('ascii'))
		except socket.error as errmsg:
			print('socket sending error: ', errmsg)
		try:
			responseData = requestSocket.recv(BUFSIZ)
		except socket.error as errmsg:
			print('socket receving error: ', errmsg)
		responseMessage = responseData.decode('ascii')
		if (responseMessage[0] != 'M'):
			CmdWin.insert(1.0, "\nFailed to join: roomserver error")
			userInfoLock.release()
			return
		userInfoLock.release()
		stateLock.acquire()
		currentState.updateRoomInfo(responseMessage.replace(PROTOCALEND,'').split(':')[1:])
		stateLock.release()
		time.sleep(20)

#
# Functions to handle user input
#

def do_User():

	global currentState, user

	invalidMessage = ['invalid username',
					  'change username after join']
	outstr = "\n[User] username: " + userentry.get()
	CmdWin.insert(1.0, outstr)
	username = userentry.get()
	# check if is joined.
	stateLock.acquire()
	if currentState >= States['JOINED']:
		CmdWin.insert(1.0, '\nFailed: ' + invalidMessage[1])
		stateLock.release()
		return
	stateLock.release()
	# change the username
	userInfoLock.acquire()
	if (user.setUserName(username) is Exceptions['INVALID_USERNAME']):
		CmdWin.insert(1.0, '\nFailed: ' + invalidMessage[0])
		userInfoLock.release()
		return
	userInfoLock.release()
	# set state to named
	stateLock.acquire()
	currentState.transition(Actions['USER'])
	stateLock.release()
	# clear the entry if success
	userentry.delete(0, END)


def do_User_Debug(username):

	global currentState, user

	invalidMessage = ['invalid username',
					  'change username after join']
	# outstr = "\n[User] username: "+userentry.get()
	# CmdWin.insert(1.0, outstr)
	# username = userentry.get()
	# check if is joined.
	stateLock.acquire()
	if currentState >= States['JOINED']:
		print('Failed: ' + invalidMessage[1])
		stateLock.release()
		return
	stateLock.release()
	# change the username
	userInfoLock.acquire()
	if (user.setUserName(username) is Exceptions['INVALID_USERNAME']):
		print('Failed: ' + invalidMessage[0])
		userInfoLock.release()
		return
	userInfoLock.release()
	# set state to named
	stateLock.acquire()
	currentState = transition(currentState, Actions['USER'])
	stateLock.release()
	userentry.delete(0, END)


def do_List():

	global user, currentState

	CmdWin.insert(1.0, "\nPress List")
	userInfoLock.acquire()
	requestSocket = user._getClientSocket()
	requestMessage = 'L'+PROTOCALEND
	try:
		requestSocket.send(requestMessage.encode('ascii'))
	except socket.error as errmsg:
		print('socket sending error: ', errmsg)
	try:
		responseData = requestSocket.recv(BUFSIZ)
	except socket.error as errmsg:
		print('socket receving error: ', errmsg)
	userInfoLock.release()
	responseMessage = responseData.decode('ascii')
	presentMessage = '\n'.join(responseMessage.replace(PROTOCALEND,'').split(':')[1:])
	CmdWin.insert(1.0, "\nHere are the active chatrooms:\n"+presentMessage+'\n')
	# no need actually but stard
	stateLock.acquire()
	currentState = transition(currentState, Actions['LIST'])
	stateLock.release()


def do_List_Debug():

	global user, currentState

	CmdWin.insert(1.0, "\nPress List")
	userInfoLock.acquire()
	requestSocket = user._getClientSocket()
	requestMessage = 'L' + PROTOCALEND
	try:
		requestSocket.send(requestMessage.encode('ascii'))
	except socket.error as errmsg:
		print('socket sending error: ', errmsg)
	try:
		responseData = requestSocket.recv(BUFSIZ)
	except socket.error as errmsg:
		print('socket receving error: ', errmsg)
	userInfoLock.release()
	responseMessage = responseData.decode('ascii')
	presentMessage = '\n'.join(responseMessage.replace(PROTOCALEND,'').split(':')[1:])
	print("\nHere are the active chatrooms:\n"+presentMessage+'\n')

	# no need actually but stard
	stateLock.acquire()
	currentState = transition(currentState, Actions['LIST'])
	stateLock.release()

def do_Join():
	global currentState, user

	CmdWin.insert(1.0, "\nPress JOIN")
	#check username
	userInfoLock.acquire()
	if not user.hasUserName():
		CmdWin.insert(1.0, "\nError: Please input username first")
		userInfoLock.release()
		return
	userInfoLock.release()
	# get and validate the name of chatroom
	roomName = userentry.get()
	if (re.match('^[\x00-\x7f]+$', roomName) is None) or (':' in roomName):
		CmdWin.insert(1.0, "\nFailed: invalid room name")
		return
	# send request to roomserver
	userInfoLock.acquire()
	requestSocket = user._getClientSocket()
	message = ':'.join([roomName, user._getname(), user._getip(), str(user._getport())])
	requestMessage = 'J:' + message + PROTOCALEND
	try:
		requestSocket.send(requestMessage.encode('ascii'))
	except socket.error as errmsg:
		print('socket sending error: ', errmsg)
	try:
		responseData = requestSocket.recv(BUFSIZ)
	except socket.error as errmsg:
		print('socket receving error: ', errmsg)
	userInfoLock.release()
	responseMessage = responseData.decode('ascii')
	if (responseMessage[0] != 'M'):
		CmdWin.insert(1.0, "\nFailed to join: roomserver error")
		return
	presentMessage = '\n'.join(responseMessage.replace(PROTOCALEND,'').split(':')[2::3])
	CmdWin.insert(1.0, '\nJoin Success!\nHere are members in the room:\n' + presentMessage+ '\n' )
	# change the state if success
	stateLock.acquire()
	currentState.updateRoomInfo(responseMessage.replace(PROTOCALEND,'').split(':')[1:])
	currentState.stateTransition(Actions['JOIN'])
	stateLock.release()
	# clear the entry if success
	userentry.delete(0, END)

def do_Join_Debug(roomName):
	global currentState, user
	# send request to roomserver
	userInfoLock.acquire()
	requestSocket = user._getClientSocket()
	message = ':'.join([roomName, user._getname(), user._getip(), str(user._getport())])
	requestMessage = 'J:' + message + PROTOCALEND
	try:
		requestSocket.send(requestMessage.encode('ascii'))
	except socket.error as errmsg:
		print('socket sending error: ', errmsg)
	try:
		responseData = requestSocket.recv(BUFSIZ)
	except socket.error as errmsg:
		print('socket receving error: ', errmsg)
	userInfoLock.release()
	responseMessage = responseData.decode('ascii')
	if (responseMessage[0] != 'M'):
		print("\nFailed to join: roomserver error")
		return
	presentMessage = '\n'.join(responseMessage.replace(PROTOCALEND,'').split(':')[2::3])
	print("\nJoin Success!\nHere are members in the room:\n" + presentMessage + '\n')
	# change the state if success
	stateLock.acquire()
	currentState = transition(currentState, Actions['JOIN'])
	stateLock.release()
	# clear the entry if success
	userentry.delete(0, END)
def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	sys.exit(0)

def cleanUp():
	pass
#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)
	global currentState, user
	currentState = State()
	user = User(sys.argv[1], int(sys.argv[2]), socket.gethostbyname(socket.gethostname()),int(sys.argv[3]))
	win.mainloop()
	# do_User_Debug('abcasdfasdf`0123')
	# do_User_Debug('abcasdff`0123')
	# do_User_Debug('abcasdfasasdfdf`0123')
	# do_User_Debug('abca23')
	# do_User_Debug('')
	# do_User_Debug('abcas:dfasdf`0123')
	# do_User_Debug('hcwang')

	# do_List_Debug()
	# do_Join_Debug('testing1')
	# do_List_Debug()


	# print('username:' + user._getname())
	cleanUp()

if __name__ == "__main__":
	main()

