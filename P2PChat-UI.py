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
PROTOCAL_END = '::\r\n'
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

Exceptions = {'INVALID_USERNAME'           : 11,
			  'SOCKET_ERROR'               : 12,
			  'BACKWARDLINK_NOT_EXIST'     : 13,
			  'BACKWARDLINK_ALREADY_EXIST' : 14}
currentState = None
user = None
# two lock for maintaining user info and current state info
stateLock = threading.Lock()
userInfoLock = threading.Lock()

# user class
# maintaining user program basic info
# include:
# 1. roomserver ipv4 address and port
# 2. p2pclient listening port
# 3. user socket connecting to roomserver and
#    and socket as local server socket
# 4. username validation rules
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
		self._socketSetup(serverIP, serverPort)
	def _socketSetup(self, serverIP=None, serverPort=None, localIP=None, localPort=None):
		print("setting up user socket...")
		if (serverIP is not None and serverPort is not None):
			self._clientSocket = socket.socket()
			# connect with room server with clientsocket
			try:
				self._clientSocket.connect((serverIP, serverPort))
				print('finish setting user socket: connected to roomserver[',
					serverIP,',',serverPort,']')	
			except socket.error as errmsg:
				print('Failed to connect to roomServer: ', errmsg)
				print('try again')

				try:
					self._clientSocket.connect((serverIP, serverPort))
					print('finish setting user socket: connected to roomserver[',
						serverIP,',',serverPort,']')
				except:
					print('Failed to connect to roomServer again: ', errmsg)
					print("""p2pclient program shutdowns due to failure to connect to roomserver,
							please check if the server address and port are correct, or check if 
							the server is already working""")
					self._clientSocket.close()
					sys.exit(1)
			
		if (localPort is not None):
			self._serverSocket = socket.socket()
			try:
				self._serverSocket.bind((localIP,localPort))
				print('finish setting user socket: open server port:', localPort)
			except socket.error as emsg:
				print("Socket bind error: ", emsg)
				print("try again")
				try:
					elf._serverSocket.bind((localIP,localPort))
					print('finish setting user socket: open server port:', localPort)
				except socket.error as emsg:
					print("Socket bind error again: ", emsg)
					print("""p2pclient program shutdowns due to failure to bind the listening socket
							, please check your socket usage and try another available port""")
					self._serverSocket.close()
					sys.exit(1)
		else:
			print('Ignore binding port for the time being')
	# def resumeConnectionToServer(self):
	# 	print('conduct resuming process')
	# 	self._socketSetup(self._getip)
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


# state class
# containing current state info
# include:
# 1. current room name (default None)
# 2. current room info (a list [MSID, userAName, userAIp, userAPort,
# 								userBName, userBIp, userBPort,...])
# 3. forward Links(for stage 2)
# 4. backward Links List (for stage 2)
# 5. msgID (TODO: for stage 2)
class State():
	def __init__(self):
		self._setstate(States['STARTED'])
		self._setroomname(None)
		self._setroominfo(None)
		self._linksetup()
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
	def _linksetup(self):
		self._backwardlinks = []
		self._forwardlink = None
	def _addbackwardlinks(self, hash):
		if hash in self._backwardlinks:
			return Exceptions['BACKWARDLINK_ALREADY_EXIST']
		else:
			self._backwardlinks.append(hash)
			print('add new backward link with hash', hash)
	def _removebackwardlinks(self, hash):
		if hash not in self._backwardlinks:
			return Exceptions['BACKWARDLINK_NOT_EXIST']
		else:
			self._backwardlinks.remove(hash)
			print('remove backward link with hash', hash)
	def _getbackwardlinks(self):
		return self._backwardlinks
	def stateTransition(self, action):
		self._setstate(transition(self._getstate(),action))
	def updateRoomName(self, roomName):
		self._setroomname(roomName)
	def updateRoomInfo(self, roomInfo):
		if self._getroominfo() is None:
			self._setroominfo(roomInfo)
		elif self._getroominfo()[0] != roomInfo[0]:
			self._setroominfo(roomInfo)
		else:
			print('room member list: duplicated info, do not update')
	def isAfter(self, state):
		return self._getstate() > state
	def inRoom(self):
		return self._getroomname() is not None
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
			Actions['HANDSHAKE']: States['CONNECTED'],
			Actions['QUIT']: States['TERMINATED']}[action]

# state transition function, critical, calling should be protected by logic
def transition(currentState, action):
	return {States['STARTED']: lambda x: FromStarted(x),
	 		States['NAMED']: lambda x: FromNamed(x),
	 		States['JOINED']: lambda x: FromJoined(x),
	 		States['CONNECTED']: lambda x: FromConnected(x)}[currentState](action)


# facilitation function for handshake process in stage 2
def findMyPosition(roomInfo, name, ip, port):
	for i in range(1,len(roomInfo),3):
		if name == roomInfo[i] and ip == roomInfo[i+1] and port == roomInfo[i+2]:
			return (i-1)/3
	return None
#
# functions for socket sending and receiving with block
# similar to C and C++ marco just for reducing duplication
#
def socketOperation(socket, sendData):
	try:
		socket.send(sendData.encode('ascii'))
	except socket.error as errmsg:
		print('socket sending error: ', errmsg)
		return Exceptions['SOCKET_ERROR']
	try:
		responseData = socket.recv(BUFSIZ)
	except socket.error as errmsg:
		print('socket receving error: ', errmsg)
		return Exceptions['SOCKET_ERROR']
	return responseData.decode('ascii')


#
# functions for facilitation threads of keep alive procedure
# resend 'JOIN' request ever 20 seconds after successfully joining
#
def keepAliveThread():
	global currentState, user
	print('keep alive thread start working ... ')
	while True:
		time.sleep(20)
		userInfoLock.acquire()
		clientsocket = user._getClientSocket()
		message = ':'.join([currentState._getroomname(), user._getname(), user._getip(), str(user._getport())])
		requestMessage = 'J:' + message + PROTOCAL_END
		responseMessage = socketOperation(clientsocket, requestMessage)
		if (responseMessage[0] != 'M'):
			CmdWin.insert(1.0, "\nFailed to join: roomserver error")
			userInfoLock.release()
			return
		userInfoLock.release()
		stateLock.acquire()
		currentState.updateRoomInfo(responseMessage.replace(PROTOCAL_END,'').split(':')[1:])
		stateLock.release()
		print('Thread: keep alive action finish')



#
# TODO: thread for handshake procedure
# follow the logic of spec
#
def handShakeThread():
	# get info of chatroom
	global currentState, user
	userInfoLock.acquire()
	roomName = currentState._getroomname()
	roomInfo = currentState._getroominfo()
	backwardLinkHashList = currentState._getbackwardlinks()
	userInfoLock.release()

	# find myself position in the roomInfo
	userInfoLock.acquire()
	myName = user._getname()
	myIp = user._getip()
	myPort = user._getport()
	userInfoLock.release()
	myPosition = findMyPosition(roomInfo, myName, myIp, myPort)
	# calculate hash of each user in the chatroom
	hashList = map(lambda x: sdbm_hash(x), 
				map(lambda x: reduce(lambda m, n: m+n, x),
					[roomInfo[y:y+3] for y in range(1,len(roomInfo),3)]))
	myHash = hashList[myPosition]
	indexHashList = zip(range(len(hashList)), hashList)
	start = sorted(test, key=lambda x : x[1]).index((myPosition, myHash)) + 1

	# probe and connect
	handShakeSocket = socket.socket()
	successFlag = 0
	while 1:
		while indexHashList[start][0] != myPosition:
			if indexHashList[start][1] in backwardLinkHashList:
				print('try with one connection but find it already in backward list, try another')
				start = (start + 1) % len(indexHashList)
				continue
			else:
				realIndex = indexHashList[start][0]
				try:
					handShakeSocket.connect((roomInfo[realIndex+1], int(roomInfo[realIndex+2])))
				except socket.error as errmsg:
					print('try to connect with[', roomInfo[realIndex+1],
						',',roomInfo[realIndex+2],
						']but failed, try another')
					start = (start + 1) % len(indexHashList)
					continue
				
				try:
					#### TODO run peer to peer handshake
					####### issue how to set msgID
					message = ":".join([roomName,myName,myIp,myPort,msgID])
					requestMessage = 'P:' + message + PROTOCAL_END
					print('successfully connect with a peer through peer-to-peer handshake with [',
						roomInfo[realIndex+1], ',',roomInfo[realIndex+2],']')

					#### TODO update the state

					successFlag = 1
					break
					pass
				except:
					print('try peer-to-peer handshake with [', roomInfo[realIndex+1],
						',',roomInfo[realIndex+2],
						']but failed, try another')
					start = (start + 1) % len(indexHashList)
					continue
		if successFlag == 1:
			break
		else:
			print('failed to find a forward link with one loop, do it again 20 seconds later')
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
	if currentState.isAfter(States['NAMED']):
		CmdWin.insert(1.0, '\nFailed: ' + invalidMessage[1] + '\n')
		print('\nFailed: ' + invalidMessage[1])
		stateLock.release()
		return
	stateLock.release()
	# change the username
	userInfoLock.acquire()
	flag = user.hasUserName()
	if (user.setUserName(username) is Exceptions['INVALID_USERNAME']):
		CmdWin.insert(1.0, '\nFailed: ' + invalidMessage[0] +'\n')
		print('\nFailed: ' + invalidMessage[0])
		userInfoLock.release()
		return
	userInfoLock.release()
	# set state to named
	stateLock.acquire()
	currentState.stateTransition(Actions['USER'])
	stateLock.release()
	# clear the entry if success
	userentry.delete(0, END)
	# give some output in CmdWin
	if flag:
		CmdWin.insert(1.0, '\nSuccess: change name to '+username+' \n')
		print('\nSuccess: change name to '+username+' \n')
	else:
		CmdWin.insert(1.0, '\nSuccess: set your nickname as '+username+' \n')
		print('\nSuccess: set your nickname as '+username+' \n')

# function for debuging in the command line
def do_User_Debug(username):

	global currentState, user

	invalidMessage = ['invalid username',
					  'change username after join']
	# outstr = "\n[User] username: "+userentry.get()
	# CmdWin.insert(1.0, outstr)
	# username = userentry.get()
	# check if is joined.
	stateLock.acquire()
	if currentState.isAfter(States['JOINED']):
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
	currentState.stateTransition(Actions['USER'])
	stateLock.release()
	userentry.delete(0, END)


def do_List():

	global user, currentState

	CmdWin.insert(1.0, "\nPress List")
	userInfoLock.acquire()
	clientsocket = user._getClientSocket()
	requestMessage = 'L' + PROTOCAL_END
	print(requestMessage)
	responseMessage = socketOperation(clientsocket, requestMessage)
	userInfoLock.release()
	presentMessage = '\n'.join(responseMessage.replace(PROTOCAL_END,'').split(':')[1:])
	CmdWin.insert(1.0, "\nHere are the active chatrooms:\n"+presentMessage+'\n')
	print("\nHere are the active chatrooms:\n"+presentMessage)
	# no need actually but standard for state transition procedure
	stateLock.acquire()
	currentState.stateTransition(Actions['LIST'])
	stateLock.release()

# function for debuging in the command line
def do_List_Debug():

	global user, currentState

	CmdWin.insert(1.0, "\nPress List")
	userInfoLock.acquire()
	clientsocket = user._getClientSocket()
	requestMessage = 'L' + PROTOCAL_END
	responseMessage = socketOperation(clientsocket, requestMessage)
	userInfoLock.release()
	presentMessage = '\n'.join(responseMessage.replace(PROTOCAL_END,'').split(':')[1:])
	print("\nHere are the active chatrooms:\n"+presentMessage+'\n')

	# no need actually but stard
	stateLock.acquire()
	currentState.stateTransition(Actions['LIST'])
	stateLock.release()

def do_Join():
	global currentState, user

	CmdWin.insert(1.0, "\nPress JOIN")
	#check username
	userInfoLock.acquire()
	if not user.hasUserName():
		CmdWin.insert(1.0, "\nError: Please input username first!\n")
		print("\nError: Please input username first!\n")
		userInfoLock.release()
		return
	userInfoLock.release()
	# check if it is already in a chatroom
	stateLock.acquire()
	if currentState.inRoom():
		CmdWin.insert(1.0, "\nError: You are already in the chat room!\n")
		print("\nError: You are already in the chat room!\n")
		stateLock.release()
		return
	stateLock.release()
	# get and validate the name of chatroom
	roomName = userentry.get()
	if (re.match('^[\x00-\x7f]+$', roomName) is None) or (':' in roomName):
		CmdWin.insert(1.0, "\nFailed: invalid room name")
		print("\nFailed: invalid room name")
		return
	# send request to roomserver
	userInfoLock.acquire()
	clientsocket = user._getClientSocket()
	message = ':'.join([roomName, user._getname(), user._getip(), str(user._getport())])
	requestMessage = 'J:' + message + PROTOCAL_END
	responseMessage = socketOperation(clientsocket, requestMessage)
	userInfoLock.release()
	if (responseMessage[0] != 'M'):
		CmdWin.insert(1.0, "\nFailed to join: roomserver error")
		return
	presentMessage = '\n'.join(responseMessage.replace(PROTOCAL_END,'').split(':')[2::3])
	CmdWin.insert(1.0, '\nJoin Success!\nHere are members in the room:\n' + presentMessage+ '\n' )
	print('\nJoin Success!\nHere are members in the room:\n' + presentMessage)
	# change the state if success
	stateLock.acquire()
	currentState.updateRoomName(roomName)
	currentState.updateRoomInfo(responseMessage.replace(PROTOCAL_END,'').split(':')[1:])
	currentState.stateTransition(Actions['JOIN'])
	stateLock.release()
	# clear the entry if success
	userentry.delete(0, END)
	# open the keep alive thread
	keepAlive = threading.Thread(target=keepAliveThread, name='keepAlive')
	keepAlive.start()

# function for debuging in the command line
def do_Join_Debug(roomName):
	global currentState, user
	# send request to roomserver
	userInfoLock.acquire()
	clientsocket = user._getClientSocket()
	message = ':'.join([roomName, user._getname(), user._getip(), str(user._getport())])
	requestMessage = 'J:' + message + PROTOCAL_END
	responseMessage = socketOperation(clientsocket, requestMessage)
	userInfoLock.release()
	if (responseMessage[0] != 'M'):
		print("\nFailed to join: roomserver error")
		return
	presentMessage = '\n'.join(responseMessage.replace(PROTOCAL_END,'').split(':')[2::3])
	print("\nJoin Success!\nHere are members in the room:\n" + presentMessage + '\n')
	# change the state if success
	stateLock.acquire()
	currentState.stateTransition(Actions['JOIN'])
	stateLock.release()
	# clear the entry if success
	userentry.delete(0, END)

def do_Send():
	CmdWin.insert(1.0, "\nPress Send")

def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	cleanUp()
	sys.exit(0)

# TODO clean up procedure to close all socket fds
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

if __name__ == "__main__":
	main()

