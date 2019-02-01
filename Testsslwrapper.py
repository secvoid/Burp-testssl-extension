# -*- coding: utf-8 -*-
try:
	from burp import IBurpExtender
	from burp import IHttpListener
	from burp import IExtensionStateListener
	from burp import ITab
	from burp import IMessageEditor
	from burp import IContextMenuFactory
	from burp import IContextMenuInvocation
	from burp import IHttpRequestResponse
	from burp import IScannerCheck
	from javax import swing
	from java.lang import Runnable
	from javax.swing import JFileChooser
	from javax.swing import JTextField
	from javax.swing import JCheckBox
	from javax.swing import BorderFactory
	from javax.swing import JOptionPane
	from javax.swing import JScrollPane
	from javax.swing import JSplitPane
	from javax.swing import JTextPane
	from javax.swing import JPanel
	from javax.swing import SwingConstants
	from javax.swing import JDialog
	from javax.swing import SwingUtilities
	from javax.swing import SwingWorker
	import java.awt.Cursor
	# from javax.swing import ScrollEvent
	from javax.swing.border import EmptyBorder
	from javax.swing import JTable
	from javax.swing.table import DefaultTableModel
	from javax.swing.filechooser import FileNameExtensionFilter
	from java.awt import BorderLayout
	from java.awt import Color
	from java.awt import Font
	from java.awt import Dimension
	from java.awt import GridLayout
	from java.awt import FlowLayout
	from java.util import ArrayList
	import java.lang as lang
	import re
	import subprocess
	import commands
	import os
	import sys
	import platform
	import urllib2
	import time
	from threading import Thread, Event
# from multiprocessing import Process
except ImportError as e:
	print e
	print "Failed to load dependencies. This issue may be caused by using the unstable Jython 2.7 beta.\n"

class BurpExtender(IBurpExtender, ITab):

	def registerExtenderCallbacks(self, callbacks):

		print('Loading MOARSSL! ... This extension requires dependencies to be installed. If the extension scan fails to run, try re-adding the Jython standalone JAR file,'
			' the version that this program was tested on was Jython 2.7.0 \n')
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self._callbacks.setExtensionName('MOARSSL!')
		self.scannerThread = None
		self.scannerThread2 = None
		self.scanningEvent = Event()

		self.OperatingSystem = platform.java_ver()[3][0]

		# main split pane
		self._splitpane = swing.JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpane.setBorder(EmptyBorder(20, 20, 20, 20))

		# sub split pane (top)
		self._topPanel = swing.JPanel(BorderLayout(10, 10))
		self._topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

		# Setup Panel
		self.titlePanel = swing.JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

		# UI Label and target input field
		self.uiLabel = swing.JLabel('Testssl.sh Burp Wrapper')
		self.uiLabel.setFont(Font('Black', Font.BOLD, 28))
		self.uiLabel.setForeground(Color(235,136,0))
		self.titlePanel.add(self.uiLabel)

		self._topPanel.add(self.titlePanel, BorderLayout.PAGE_START)

		# Target input panel
		self.targetInputPanel = swing.JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
		self.targetTitle = swing.JLabel('Target host:', SwingConstants.LEFT)
		self.targetInputPanel.add(self.targetTitle)
		self.targetInput = swing.JTextField('', 20)
		self.targetInputPanel.add(self.targetInput)
		self.targetRunButton = swing.JButton('Run regular scan', actionPerformed=self.startRegularSSLScan)
		self.targetInputPanel.add(self.targetRunButton)
		self.targetSpecificButton = swing.JCheckBox('Scan using specific flags', False)
		self.targetInputPanel.add(self.targetSpecificButton)
		self.targetSpecificFlagsInput = swing.JTextField('', 20)
		self.targetInputPanel.add(self.targetSpecificFlagsInput)
		self.targetSpecificRun = swing.JButton('Run Specific Scan', actionPerformed=self.startSpecificSSLScan)
		self.targetInputPanel.add(self.targetSpecificRun)
		self._topPanel.add(self.targetInputPanel, BorderLayout.LINE_START)

		self._splitpane.setTopComponent(self._topPanel)

		# bottom panel 
		self._bottomPanel = swing.JPanel(BorderLayout(10, 10))
		self._bottomPanel.setBorder(EmptyBorder(10, 0, 0, 0))

		self.initialText = ('<h1 style="color: red">Run at your own risk <br>'
			' For the time being, do not run scans on ports other than 80 and 443</h1>')
		self.currentText = self.initialText
		self.textPane = swing.JTextPane()

		# self.caret = swing.DefaultCaret
		self.textScrollPane = swing.JScrollPane(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
		self.textScrollPane.getViewport().setView((self.textPane))
		# self.vertical = self.textScrollPane.getVerticalScrollBar()
		# self.vertical.setValue(self.vertical.getMaximum())
		self.textPane.setContentType("text/html")
		self.textPane.setText(self.currentText)
		self.textPane.setEditable(False)
		# self.textPane.setCaretPosition(self.textPane.getDocument().getLength())

		self._bottomPanel.add(self.textScrollPane, BorderLayout.CENTER)

		self.savePanel = swing.JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

		self.clearScannedHostButton = swing.JButton('Clear output', actionPerformed=self.clearText)
		self.savePanel.add(self.clearScannedHostButton)

		self._bottomPanel.add(self.savePanel, BorderLayout.PAGE_END)

		self._splitpane.setBottomComponent(self._bottomPanel)
		callbacks.customizeUiComponent(self._splitpane)

		#### Checking for dependencies ####
		self.isWindows = False
		self.isLinux = False
		if "Windows" in self.OperatingSystem:
			self.isWindows = True
			print "Windows Operating System detected.\n"
		elif "Linux" in self.OperatingSystem:
			self.isLinux = True
			print "Linux Operating System detected.\n"
		else:
			print "Operating System name not found :( Are you an alien?\n"

		if self.isWindows:
			print "Checking for dependencies, this may take a minute...\n"
			if "wsl.exe" in subprocess.check_output(["where","wsl.exe"]):
				print "wsl.exe found.\n"
			else:
				print "wsl.exe doesn't appear to be installed. If you try and use the extension now, you're gonna have a bad time. Please install it from the Windows store.\n"
			if "testssl.sh" in subprocess.check_output(["where","/R","C:\\","testssl.sh"]):

				self.path = subprocess.check_output(["where","/R","C:\\","testssl.sh"])
				self.testSSLPathWindows = self.path.strip()
				# self.pathing = require("path")
				# self.convertedPath = "/mnt/" + p.posix.join.apply(p.posix, [].concat([self.testSSLPathWindows.split(p.win32.sep)[0].toLowerCase()], self.testSSLPathWindows.split(p.win32.sep).slice(1))).replace(":", "")
				self.convert = self.testSSLPathWindows.replace("\\", "/")
				self.convert2 = "/mnt/c/" + self.convert
				self.convert3 = str(self.convert2.replace("C:/", ""))
				self.convertedPathWindows = self.convert3.strip()
				print self.convertedPathWindows
				print "\n"
				print ["wsl",self.convertedPathWindows,"--mapping","rfc","example.com"]
				# print "\n"
				# print self.convertedPath
				print "testssl.sh found.\n"
				# self.windep2Installed = True
			else:
				print "testssl.sh doesn't appear to be installed. If you try and use the extension now, you're gonna have a bad time. Please install it from github\n"

		elif self.isLinux:
			print "Checking for dependencies, this may take a minute...\n"
			# if "testssl.sh" in subprocess.check_output(["find","/","-name","testssl.sh"]):
			if 'testssl.sh' in 'testssl.sh':
				# findPath = subprocess.check_output(["find","/","-name","testssl.sh"]).split('\n')[0]

				# self.findPathLinux = str(findPath).lstrip()
				self.findPathLinux = '/opt/testssl.sh/testssl.sh'
				#self.findPath3 = self.findPath2.split(" ")[0]
				#self.testSSLPath = self.findPath3.strip()
				#print self.testSSLPathLinux
				print self.findPathLinux
				print "testssl.sh found.\n"
			else:
				print "testssl.sh doesn't appear to be installed. If you try and use the extension now, you're gonna have a bad time. Please install it from github\n"
		else:
			print "Operating System not found :( Are you an alien?\n"
			return
		self._callbacks.addSuiteTab(self)

		self.scannerMenu = ScannerMenu(self)
		callbacks.registerContextMenuFactory(self.scannerMenu)
		print "SSL Scanner custom menu loaded"

		print 'MOARSSL! extension loaded successfully!'

	def getTabCaption(self):
		return "MOARSSL!"

	def getUiComponent(self):
		return self._splitpane  		

	def startRegularSSLScan(self,e):
		host = str(self.targetInput.text)

		self.scanningEvent.set()

		# path = str(self.testSSLPath)

		if(len(host) == 0):
			return

		p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
		m = re.search(p,host)
		a = m.group('host')
		b = m.group('port')
		if b != '':
			self.c = a + ':' + b
		else:
			self.c = a

		if b == '443':
			connectionTest = 'https://'
		else:
			connectionTest = 'http://'

		try:
			urllib2.urlopen(str(connectionTest+self.c), timeout=1)
			self.targetInputPanel.setEnabled(False)
			self.targetRunButton.setEnabled(False)
			self.targetSpecificButton.setEnabled(False)
			self.targetSpecificFlagsInput.setEnabled(False)
			self.targetSpecificRun.setEnabled(False)				
			self.updateText("<h2>Connection made</h2>")
			self.scannerProcess = Thread(target=self.runRegularSSLScan, args=(self.c,))
			self.scannerProcess2 = Thread(target=self.parseFile)
			self.scannerProcess.start()
			time.sleep(2.5)
			# SwingUtilities.invokeLater(ScannerRunnable(self.parseFile))
			self.scannerProcess2.start()
			# self.scannerThread = Thread(target=self.runRegularSSLScan, args=(self.c, ))
			# self.scannerThread.start()
		except urllib2.URLError as err:
			self.updateText("<h2>Connection not made, make sure you entered the host correctly<h2>")
			return

	def runRegularSSLScan(self,url):

# def updateResultText(text):
# 	if not usingBurpScanner:
# 		SwingUtilities.invokeLater(ScannerRunnable(self.updateText, (text, )))
		if self.targetSpecificButton.isSelected():
			# self.updateResultText("<h2>Please un-check the checkbox in order to run a regular scan<h2>")
			self.updateText("<h2>Please un-check the checkbox in order to run a regular scan<h2>")
			# self.scanningEvent.clear()
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)			
			return

		self.updateText("<h2>Host: " + str(url) + "</h2>")
		# self.updateResultText("<h2>Host: " + str(url) + "</h2>")


		self.updateText("<h2>Running scan, this may take some time..</h2>")
		# self.updateResultText("<h2>Running scan, this may take some time..</h2>")

		# command = subprocess.check_output(["/opt/testssl.sh/testssl.sh","-oH","/opt/testssl.sh/testing/result.txt","--mapping","rfc","--append",url]) ## For home computer linux vm
		if self.isWindows:
			try:
				command = subprocess.check_output(["wsl",self.convertdPathWindows,"-oH","/mnt/c/Data/Scripts/result.html","--mapping","rfc","--append",url]).replace("\n", "<br>") ## Work computer

				# self.updateText(command)
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)
				sys.exit()
			except:
				# self.updateText("<h2>An unexpected error occurred while running the regular scan (Windows) :( Please try again</h2>")
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)
				sys.exit()
		elif self.isLinux:
			try:
				command = subprocess.check_output([self.findPathLinux,"-oH","/root/Desktop/result.html","--mapping","rfc","--append",url]).replace("\n", "<br>")
				# self.updateText(command)
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)
				sys.exit()
			except:
				# self.updateText("<h2>An unexpected error occurred while runnning the regular scan (Linux) :( Please try again</h2>")
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)
				sys.exit()
		else:
			print "Operating system not detected, can't run program"
			self.updateText("<h2>An unexpected error occurred, cannot run scan:( Please try again</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)
			sys.exit()		


	def startSpecificSSLScan(self,e):
		host = self.targetInput.text

		if(len(host) == 0):
			self.updateText("<h2>Please enter a host</h2>")
			return
		p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
		m = re.search(p,host)
		a = m.group('host')
		b = m.group('port')
		if b != '':
			self.c = a + ':' + b
		else:
			self.c = a

		if b == '443':
			connectionTest = 'https://'
		else:
			connectionTest = 'http://'


		try:
			urllib2.urlopen(str(connectionTest+self.c), timeout=1)
			self.targetInputPanel.setEnabled(False)
			self.targetRunButton.setEnabled(False)
			self.targetSpecificButton.setEnabled(False)
			self.targetSpecificFlagsInput.setEnabled(False)
			self.targetSpecificRun.setEnabled(False)				
			self.updateText("<h2>Connection made</h2>")
			self.scannerProcess = Thread(target=self.runSpecificSSLScan, args=(self.c,))
			self.scannerProcess2 = Thread(target=self.parseFile)
			self.scannerProcess.start()
			time.sleep(3)
			self.scannerProcess2.start()
		except urllib2.URLError as err:
			self.updateText("<h2>Connection not made, make sure you entered the host correctly<h2>")
			return


	def runSpecificSSLScan(self,url):
		if not self.targetSpecificButton.isSelected():
			self.updateText("<h2>Please check the checkbox in order to run specific scans.<h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)
			return

		try:
			self.updateText("<h2>Host: " + str(url) + "</h2>")
			flags = list(str(self.targetSpecificFlagsInput.text).split(" "))

			moreFlags = list(filter(None, flags))

			print moreFlags

			if (len(moreFlags)==0):
				self.updateText("<h2>Please enter at least one flag that you want, separated by a space. Click the help button to see the available flags</h2>")
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)
				return

			self.updateText("<h2>Starting scan, this may take some time</h2>")

			informationOptions = ['-h',
									'--help',
									'-b',
									'--banner',
									'-v',
									'--version',
									'-V',
									'--local' ## needs to be dict to handle response'-e',
									]

			allOptions = ['-e',
							'--each-cipher',
							'-E',
							'--cipher-per-proto',
							'-f',
							'--ciphers',
							'-p',
							'--protocols',
							'y',
							'--spdy',
							'--npn',
							'-Y',
							'--http2',
							'--alpn',
							'-S',
							'--server-defaults',
							'-P',
							'--server-preference',
							'-X',
							'--single-cipher', ## needs to be dict to handle response
							'-c',
							'--client-simulation',
							'-H',
							'--header',
							'--headers',
							'-U',
							'--vulnerable',
							'-B',
							'--heartbleed',
							'-I',
							'--ccs',
							'--ccs-injection',
							'-R',
							'--renegotiaton',
							'-C',
							'--compression',
							'--crime',
							'-T',
							'--breach',
							'-O',
							'--poodle',
							'-Z',
							'--tls-fallback',
							'-F',
							'--freak',
							'-A',
							'--beast',
							'-J',
							'--logjam',
							'-D',
							'--drown',
							'-s',
							'--pfs',
							'--fs',
							'--nsa',
							'-4',
							'--rf4',
							'--appelbaum',
							'-t',
							'--starttls',
							'--xmpphost',
							'--mx',
							'--ip',
							'--file',
							'--bugs',
							'--assume-http',
							'--ssl-native',
							'--openssl',
							'--proxy',
							'-6',
							'--quiet',
							'--wide',
							'--show-each',
							'--colorblind',
							'--log',
							'--logging',
							'--json',
							'--csv',
							'--append'
							]

				### --warnings, --mapping, --color, and --debug need to be dicts to handle the responses
				### --logfile, --jsonfile, and --csvfile need to be dicts to handle the responses
			infoFlagCheck = False

			# subprocessArguments = ["/opt/testssl.sh/testssl.sh","--color",str(0)] ## Home linux vm testing
			# subprocessHelp = ["/opt/testssl.sh/testssl.sh"] ## Home linux vm testing
			if self.isWindows:
				subprocessArguments = ["wsl",self.convertedPathWindows]
				subprocessHelp = ["wsl",self.convertedPathWindows]
			elif self.isLinux:
				subprocessArguments = [self.findPathLinux,"-oH","/root/Desktop/result.html"]
				subprocessHelp = [self.findPathLinux]
			else:
				print "Can't do anything, inside specific scan function"
			# lst1 = []
			# lst2 = []

			if len(moreFlags) == 0:
				print "Nothing in list"
				self.updateText("<h1>Please enter in additional flags. See below for a list\n</h2>")
				command = subprocess.check_output(subprocessHelp).replace("\n", "<br>")

			elif len(moreFlags) == 1:

				if moreFlags[0] in informationOptions:
					print "Single item detected in information options"
					subprocessArguments.append(moreFlags[0])
					command = subprocess.check_output(subprocessArguments).replace("\n", "<br>")

				elif moreFlags[0] in allOptions:
					print "Single item detected in all options"
					subprocessArguments.append(moreFlags[0])
					subprocessArguments.append(str(url))
					print subprocessArguments
					command = subprocess.check_output(subprocessArguments).replace("\n", "<br>")


				else:
					self.updateText("<h2>The input entered is not a valid flag for testssl. Please enter input again<h2>")
					command = subprocess.check_output(subprocessHelp).replace("\n", "<br>")
					print "input entered is not part of testssl"

			else:
				print "Multiple items in list"

				for i in moreFlags:
					if i in informationOptions:
						print "Item found in information options"
						infoFlagCheck = True
						subprocessArguments.append(i)

					elif i in allOptions:
						print "Item found in all options"
						subprocessArguments.append(i)
					else:
						self.updateText("<h2>A flag that was entered is not a recognized flag for testssl, please enter again</h2>")
						command = subprocess.check_output(subprocessHelp).replace("\n", "<br>")
						print "Item was not found at all"

			if infoFlagCheck == False:
				subprocessArguments.append(str(url))
				print subprocessArguments
				command = subprocess.check_output(subprocessArguments).replace("\n", "<br>")
			else:
				print subprocessArguments
				command = subprocess.check_output(subprocessArguments).replace("\n", "<br>")

				print subprocessArguments
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			sys.exit()			

		except:
			print "An unexpected error occurred... :( NEED TO FIX SPECIFIC SCAN, THE EXCEPT STATEMENT IS RUNNING AND I DON'T KNOW WHY!! "
			# self.updateText("<h2>An unexpected error occurred... :( Please try again. Make sure if you're entering additional flags that you enter them correctly</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			sys.exit()

	# def parseFile(self, usingBurpScanner=False):
	def parseFile(self):

		# def updateResultText(text):
		# 	if not usingBurpScanner:
		# 		SwingUtilities.invokeLater(ScannerRunnable(self.updateText, (text, )))

		blacklist = ['<?','<!','<html','</html','<head','</head','<body','</body','<pre','<pre','<title','</title','<meta','</meta']
		# filePath = '/opt/testssl.sh/testing/result.txt'
		print "Inside parseFile function"
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/root/Desktop/result.html'
			print "Testing"
		else:
			print "Can't do anything, inside parseFile function"
		try:
			with open(filePath) as fileName:
				print "File found"
				timeout = time.time() + 60*5
				while time.time() < timeout:
					data = fileName.readlines()
					for line in data:
						if line == 0:
							time.sleep(.1)
							continue
						elif line.startswith(tuple(blacklist)):
							time.sleep(.1)
							continue
						else:
							newLine=line+"<br>"
							self.updateText(newLine)
							time.sleep(.1)
				if self.isWindows:
					subprocess.check_output(["del","C:\\Data\\Scripts\\result.html"], shell=True)
					sys.exit()
				elif self.isLinux:
					subprocess.check_output(["rm","/root/Desktop/result.html"], shell=True)
					sys.exit()
				else:
					print "Can't do anything, no file exists"
					sys.exit()
		except:
			print "File not found :("
			if self.isWindows:
				subprocess.check_output(["del","C:\\Data\\Scripts\\result.html"], shell=True)
			elif self.isLinux:
				subprocess.check_output(["rm","/root/Desktop/result.html"], shell=True)
			else:
				print "Can't do anything, no file exists"
				self.ResultText("<h1>An unexpected error occurred while reading and outputing the results :(")

				sys.exit()
			# self.scanningEvent2.clear()
			# updateResultText("<h1>An unexpected error occurred while reading and outputing the results :(")

	def updateText(self, stringToAppend):
		self.currentText += str(stringToAppend)
		self.textPane.setText(self.currentText)
		self.textPane.setCaretPosition(self.textPane.getDocument().getLength())

	def clearText(self, e):
		self.currentText = ('<h1 style="color: red">Run at your own risk <br>'
			' For the time being, do not run scans on ports other than 80 and 443</h1>')
		self.textPane.setText(self.currentText)

class ScannerMenu(IContextMenuFactory):
	def __init__(self, scannerInstance):
		self.scannerInstance = scannerInstance

	def createMenuItems(self, contextMenuInvocation):
		self.contextMenuInvocation = contextMenuInvocation
		sendToTestSSLWrapper = swing.JMenuItem("Send URL to TestSSLWrapper", actionPerformed=self.getSentUrl)
		menuItems = ArrayList()
		menuItems.add(sendToTestSSLWrapper)
		return menuItems

	def getSentUrl(self, event):
		for selectedMessage in self.contextMenuInvocation.getSelectedMessages():
			if (selectedMessage.getHttpService() != None):
				try:
					url = self.scannerInstance._helpers.analyzeRequest(selectedMessage.getHttpService(), selectedMessage.getRequest()).getUrl()
					print "Selected URL: " + url.toString()
					self.scannerInstance.targetInput.setText(url.toString())
				except:
					self.scannerInstance._callbacks.issueAlert("Cannot get URL from the currently selected message " + str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]))
				else:
					self.scannerInstance._callbacks.issueAlert("The selected request is not there.. :(")

# class ScannerRunnable(Runnable):
# 	def __init__(self, runFunction):
# 		self._runFunction = runFunction

# 	def run(self):
# 		self._runFunction()

# class ScannerRunnable(Runnable):
# 	def __init__(self, func, args):
# 		self.func = func
# 		self.args = args

# 	def run(self):
# 		self.func(*self.args)