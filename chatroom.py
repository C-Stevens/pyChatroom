import sys
import argparse
import json
import re
import socket
import threading

class ClientConnection(threading.Thread):
	def __init__(self, parent, socket, address):
		threading.Thread.__init__(self) # Load init from super class
		self.parent = parent
		self.socket = socket
		self.address = address
		self.userid = ""
	def run(self):
		print("(server) New client connection from {0}.".format(self.address))
		# Send header and ping test
		self.send("Welcome to the chatroom! Please log in or create an account now by typing either: login/newuser <username> <password>")
		# self.socket.send(b"-") # Send one character as a ping. If the socket is closed the client will be unable to receive this and will close, otherwise the client will discard this
		
		# Wait for the user to send their login credentials, then try and verify them
		self.loggedIn = False
		pattern = re.compile("(?P<command>login|newuser) (?P<username>\w*) (?P<password>\w*)")
		while not self.loggedIn:
			loginResponse = self.receive()
			match = pattern.match(loginResponse)
			if not match: # User either entered a different command, or a malformed login command
				self.send("Invalid. Please log in or create an account by typing: login/newuser <username> <password>")
				continue
			else:
				command = match.group('command')
				userid = match.group('username')
				password = match.group('password')
			uidList = []
			for user in self.parent.users: # Make a list of valid userids for faster logic
				uidList.append(user['userid'])

			if command == "login": # Handle a login attempt
				if self.parent.isRegistered(userid):
					self.send("You are already logged in.")
					continue
				if userid in uidList:
					for user in self.parent.users: # Look for the userid in the list of known users
						if userid == user['userid'] and password == user['password'] and not self.parent.isRegistered(userid):
							self.send("Successfully logged in. Welcome, {0}!".format(user['userid']))
							self.userid = user['userid']
							self.loggedIn = True # Break the while loop
					if not self.loggedIn: self.send("Invalid password. Please try again.")						
				else:
					self.send("Username not found. Please try again")
			elif command == "newuser":
				if match.group('username') in uidList: # Make sure username doesn't already exist
					self.send("A user with this username already exists. Please choose a different username.")
				elif len(match.group('username')) > 32: # Make sure username is of valid length
					self.send("Usernames cannot be longer than 32 characters. Please choose something shorter.")
				elif len(match.group('password')) not in range(4,8): # Make sure password is of valid length
					self.send("Passwords must be between 4 and 8 characters long.")
				else: # Proceed with adding this user
					self.userid = match.group('username')
					self.parent.addUser(match.group('username'), match.group('password'))
					self.send("Successfully created a new account. Welcome, {0}!".format(self.userid))
					self.loggedIn = True
					continue

		print("(server) {0} has logged in.".format(self.userid))
		self.parent.register(self.userid, self)

		pattern = re.compile("(?P<command>send|who|logout) ?(?P<args>.*)?") # Pattern used for matching commands
		sendPattern = re.compile("(?P<recepient>\w*) (?P<message>.*)") # Pattern used specifically for matching the argument of the send command
		while True: # Wait for the user to send commands
			msg = self.receive()
			match = pattern.match(msg)
			if not match:
				self.send("Unknown command. Try either send, who, or logout")
				continue
			if match.group('command') == "who": # Handle the who command
				uidList = []
				for conn in self.parent.activeConnections:
					uidList.append(conn[0])
				self.send("{0} in the chatroom right now: {1}".format(len(uidList), ", ".join(uidList)))
			elif match.group('command') == "send": # Handle the send command
				sendMatch = sendPattern.match(match.group('args'))
				if not sendMatch:
					self.send("Improper use of the send command. Please try again.")
					continue
				elif sendMatch.group('recepient') == "all": # Send a message to everyone
					self.parent.sendToAll(self.userid, sendMatch.group('message'))
				else: # See if this user is connected. If they are, send a message to them
					sent = False
					for conn in self.parent.activeConnections:
						if conn[0] == sendMatch.group('recepient'):
							self.parent.sendToUser(self.userid, sendMatch.group('recepient'), sendMatch.group('message'))
							sent = True
					if not sent: self.send("{0} doesn't appear to be in the chatroom at the moment.".format(sendMatch.group('recepient')))
			elif match.group('command') == "logout": # Handle the logout command
				break
		print("(server) Disconnecting client from {0}.".format(self.address))
		self.exit()
	def send(self, msg):
		# Encodes a string message supplied in msg and appends any necessary spaces to fill the byte length to 1024. Makes recv() on client side easier
		msg += ('\n') # Append a delimiter at the end of the message so the client knows what bytes to trim off
		self.socket.send('{payload: <{maxlen}}'.format(payload=msg, maxlen=1024).encode('utf-8'))
	def receive(self):
		# Wait until it has received an entire msg, ending with \n as a delim, then returns it
		msg = b""
		while len(msg) < 1024:
			msg += self.socket.recv(1024 - len(msg))
		return msg.decode('utf-8').split('\n', 1)[0]
	def exit(self):
		self.socket.close()
		self.parent.unregister(self.userid)

class Server():
	def __init__(self, configPath):
		self.error = False
		self.run = True
		self.activeConnections = []
		print("(server) Loading server configuration..")
		self.configPath = configPath[0]
		self.loadConfig(configPath[0])
		if not self.error:
			print("(server) Setting up server socket..")
			self.setupSocket()
	def loadConfig(self, configPath):
		try: # Attempt to open the passed config file path
			with open(configPath) as f:
				try:
					jsonConfig = json.load(f)
				except:
					print("[Error] (server) Configuration file passed is not valid json.")
					self.error = True
				try: # Attempt to read in vars from the json
					self.host = jsonConfig['host']
					self.port = jsonConfig['port']
					self.maxClients = jsonConfig['maxclients']
					self.users = jsonConfig['users']
				except KeyError:
					print("[Error] (server) Could not parse required parameters from config file at '{0}'".format(configPath))
					self.error = True
		except FileNotFoundError:
			print("[Error] (server) Could not open configuration file at '{0}' for reading.".format(configPath))
			self.error = True
	def saveConfig(self):
		# Saves off relevant server states into json format to the same file path that was passed to it at creation.
		config = {
			"host" : self.host,
			"port" : self.port,
			"maxclients" : self.maxClients,
			"users" : self.users
		}
		with open(self.configPath, 'w') as of:
			json.dump(config, of)
	def setupSocket(self):
		try: # Create socket object and set it up
			self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.server.bind((self.host, self.port))
		except:
			print("[Error] (server) Could not open server socket.")
			self.error = True
	def start(self):
		print("(server) Listening on {0}:{1} for incomming connections..".format(self.host, self.port))
		while self.run: # Listen on config host and port, spin off client threads for each incoming connection
			self.server.listen(1)
			clientSocket, clientAddress = self.server.accept()
			if len(self.activeConnections) == self.maxClients:
				clientSocket.send("The chatroom is currently full. Please try again later.".encode('utf-8'))
				clientSocket.close()
				print("(server) Refusing new connection because current connections exceeds maximum of {0}.".format(self.maxClients))
				continue
			clientThread = ClientConnection(self, clientSocket, clientAddress)
			clientThread.start()
		print("(server) Closing socket.")
		self.server.close()
	def register(self, id, objRef):
		# Add the client thread supplied in objRef to the pool of active connections.
		# But first, notify everyone already connected that someone is joining
		for user in self.activeConnections:
			user[1].send("{0} has joined the chatroom.".format(id))
		self.activeConnections.append((id, objRef))
	def unregister(self, id):
		# Removes the supplied id from the list of active connections.
		for i, ct in enumerate(self.activeConnections):
			if id == ct[0]:
				del self.activeConnections[i]
		# Now notify everyone left that this person just left.
		for user in self.activeConnections:
			user[1].send("{0} has left the chatroom.".format(id))
	def isRegistered(self, uid):
		# Returns True if the provided userid is current registered (logged in) to the server, False otherwise
		for user in self.activeConnections:
			if user[0] == uid:
				return True
		return False
	def addUser(self, uid, password):
		self.users.append({'userid': uid, 'password': password})
		self.saveConfig()
	def sendToAll(self, senderId, message):
		for conn in self.activeConnections:
			conn[1].send("{0}: {1}".format(senderId, message))
		print("(server) {0} (to all): {1}".format(senderId, message))
	def sendToUser(self, senderId, uid, message):
		for conn in self.activeConnections:
			if conn[0] == uid:
				conn[1].send("{0} says to you: {1}".format(senderId, message))
		print("(server) {0} (to {1}): {2}".format(senderId, uid, message))
	def exit(self):
		self.run = False
		return


class Client():
	def __init__(self, server, port):
		self.run = False
		self.server = server
		self.port = port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	def connect(self):
		try:
			self.socket.connect((self.server, self.port))
			return True
		except:
			print("[Error] (client) Server is not running.")
		return False
	def listen(self):
		while self.run:
			try:
				recvData = self.socket.recv(1024)
			except OSError: # Can safely catch this as we deal with the socket closing ourselves
				print("(client) Server has disconnected.")
				continue
			if recvData:
				print(">> {0}".format(recvData.decode().split('\n', 1)[0]))
			else:
				self.stop()
	def send(self, msg):
		msg += '\n'
		try:
			self.socket.sendall('{payload: <{maxlen}}'.format(payload=msg, maxlen=1024).encode('utf-8'))
		except:
			print("[Error] (client) Connection to server lost.")
			return False
		return True
	def start(self):
		self.run = True
		listenThread = threading.Thread(target=self.listen)
		listenThread.start()
	def stop(self):
		self.run = False
		self.socket.close()


if __name__ == "__main__":
	if sys.version_info[0] < 3:
		print("[Error] This program is designed to run on python 3. Please update your system, python 2 is very old.")
		sys.exit(1)
	# Set up command line arguments
	parser = argparse.ArgumentParser(description="A Basic Chatroom Application.", epilog="By default, will run in client mode.")
	parser.add_argument("-s", "--server", help="Runs the application in server mode.", action="store_true")
	parser.add_argument("-c", "--config", nargs=1, help="Specifies path to the json config information for the application.", action="store")
	args = parser.parse_args()

	# Determine what mode the program is being run in, act accordingly
	if args.server: # Start the server
		if not args.config:
			print("[Error] (server) Configuration file not specified with --config,-c.")
			sys.exit(1)
		server = Server(args.config)
		if server.error:
			print("[Error] (server) Server could not be initialized. Exiting..")
			sys.exit(1)
		server.start()
	else: # Run in client mode
		# Hardcoded defaults. Would be nice to read these in from somewhere in the future
		SERVER = "localhost"
		PORT = 16377
		client = Client(SERVER, PORT)
		if client.connect():
			client.start()
			while True:
				out = input("")
				if out == "logout":
					client.send("logout")
					client.stop()
					break
				else:
					if not client.send(out):
						break
		sys.exit()

