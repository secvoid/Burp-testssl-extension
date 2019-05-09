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
	from burp import IScanIssue
	from java.io import PrintWriter, File, FileWriter
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
	from javax.swing import JFileChooser
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
	from java.net import URL, MalformedURLException
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
	# from modules import *

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
		self.uiLabel = swing.JLabel('Testssl.sh Wrapper')
		self.uiLabel.setFont(Font('Black', Font.BOLD, 28))
		self.uiLabel.setForeground(Color(235,136,0))
		# self.aboutButton = swing.JButton('About', actionPerformed=self.extensionDescription)
		# self.description = jLabel('')
		self.titlePanel.add(self.uiLabel)

		self._topPanel.add(self.titlePanel, BorderLayout.PAGE_START)

		# Target input panel
		self.targetInputPanel = swing.JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
		self.targetTitle = swing.JLabel('Target host:', SwingConstants.LEFT)
		self.targetInputPanel.add(self.targetTitle)
		self.targetInput = swing.JTextField('', 20)
		self.targetInputPanel.add(self.targetInput)
		self.targetRunButton = swing.JButton('Run Regular Scan', actionPerformed=self.startRegularSSLScan)
		self.targetInputPanel.add(self.targetRunButton)
		self.targetSpecificButton = swing.JCheckBox('Scan using specific flags (flags separated by a space)', False)
		self.targetInputPanel.add(self.targetSpecificButton)
		self.targetSpecificFlagsInput = swing.JTextField('', 20)
		self.targetInputPanel.add(self.targetSpecificFlagsInput)
		self.targetSpecificRun = swing.JButton('Run Specific Scan', actionPerformed=self.startSpecificSSLScan)
		self.targetInputPanel.add(self.targetSpecificRun)
		if 'Professional' in callbacks.getBurpVersion()[0]:
			self.addToSitemap = JCheckBox('Add to Site Map', False)
		else:
			self.addToSitemap = JCheckBox('Add to Site Map (requires Professional version)', False)
			self.addToSitemap.setEnabled(False)
		self.targetInputPanel.add(self.addToSitemap)

		self._topPanel.add(self.targetInputPanel, BorderLayout.LINE_START)

		self._splitpane.setTopComponent(self._topPanel)

		# bottom panel 
		self._bottomPanel = swing.JPanel(BorderLayout(10, 10))
		self._bottomPanel.setBorder(EmptyBorder(10, 0, 0, 0))

		self.initialText = ('<h1 style="color: red;">'
			' When running, you may experience crashes. Just deal with it, this is stil a work in progress<br>'
			' Make sure you have testssl installed in the /opt directory for Linux. Any location is fine for Windows<br>'
			' If you have testssl installed more than once, this extension might not work.</h1>')
		self.currentText = self.initialText
		self.textPane = swing.JTextPane()

		# self.caret = swing.DefaultCaret
		self.textScrollPane = swing.JScrollPane(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
		self.textScrollPane.getViewport().setView((self.textPane))
		self.textPane.setContentType("text/html")
		self.textPane.setText(self.currentText)
		self.textPane.setEditable(False)

		self._bottomPanel.add(self.textScrollPane, BorderLayout.CENTER)

		self.savePanel = swing.JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

		self.clearScannedHostButton = swing.JButton('Clear output', actionPerformed=self.clearText)
		self.savePanel.add(self.clearScannedHostButton)

		self.targetSaveButton = swing.JButton('Save output', actionPerformed=self.saveToFile)
		self.targetSaveButton.setEnabled(False)
		self.savePanel.add(self.targetSaveButton)

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

			self.path = subprocess.check_output(["where","/R","C:\\","testssl.sh"])
			self.testSSLPathWindows = self.path.strip()
			self.convert = self.testSSLPathWindows.replace("\\", "/")
			self.convert2 = "/mnt/c/" + self.convert
			self.convert3 = str(self.convert2.replace("C:/", ""))
			self.convertedPathWindows = self.convert3.strip()
			self.openSSLConfig = os.path.dirname(self.convertedPathWindows) + "/bin/openssl.Linux.x86_64"
			if self.convertedPathWindows != 0:
				print "testssl.sh found.\n"
			else:
				print "testssl.sh doesn't appear to be installed. If you try and use the extension now, you're gonna have a bad time. Please install it from github\n"

		elif self.isLinux:

			print "Checking for dependencies, this may take a minute...\n"
			findPath = subprocess.check_output(["find","/opt","-name","testssl.sh","-type","f"]).split('\n')[0]
			self.findPath2 = str(findPath).lstrip()
			self.findPath3 = self.findPath2.split(" ")[0]
			self.testSSLPath = self.findPath3.strip()
			print self.testSSLPath
			if self.testSSLPath != 0:
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

	# def extensionDescription(self):
	# 	self.description.text = 'This extension uses testssl to test TLS/SSL encryption and outputs any issues found to the Burp issues tab.'
	# 							'The regular scan by default uses the following format: '
	# 							'./testssl.sh --ip one --mapping rfc <URI>'		

	def startRegularSSLScan(self,e):

		self.currentText = self.initialText

		if self.targetSpecificButton.isSelected():
			self.updateText("<h2>Please un-check the checkbox in order to run a regular scan<h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			return

		host = str(self.targetInput.text)

		self.scanningEvent.set()

		if(len(host) == 0):
			self.updateText("<h2>Please enter a host to scan</h2>")
			return

		p = '(?P<protocol>http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
		m = re.search(p,host)
		self.site = m.group('host')
		self.protocol = m.group('protocol')
		self.port = m.group('port')

		if host.find("://") == -1:
			self.connectionHost = "https://" + host

		if self.protocol == 'https://':
			pass
		elif self.protocol == 'http://':
			self.updateText("<h2>regular HTTP will cause the program to crash, please enter again</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			return
		elif self.protocol == None:
			self.protocol = 'https://'
		else:
			self.updateText("<h2>Something weird happened.. Check the protocol you entered</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			return			

		if self.port != '':
			if self.port == '80':
				self.updateText("<h2>port 80 cannot be used with testssl, please enter again<h2>")
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)	
				self.addToSitemap.setEnabled(True)
				return					
			elif self.port == '443':
				self.connectionHost = "https://" + self.site + ":" + self.port
			else:
				self.connectionHost = self.site + ":" + self.port
		else:
			self.port == '443'

		try:		
			self.targetURL = URL(self.connectionHost)
			if(self.targetURL.getPort() == -1):
				self.targetURL = URL("https", self.targetURL.getHost(), 443, "/")
			self.targetInputPanel.setEnabled(False)
			self.targetRunButton.setEnabled(False)
			self.targetSpecificButton.setEnabled(False)
			self.targetSpecificFlagsInput.setEnabled(False)
			self.targetSpecificRun.setEnabled(False)
			self.addToSitemap.setEnabled(False)				
			self.updateText("<h2>Connection made</h2>")
			self.scannerProcess = Thread(target=self.runRegularSSLScan, args=(self.connectionHost,))			
			self.scannerProcess2 = Thread(target=self.parseFile)
			self.scannerProcess.start()
			time.sleep(.5)
			self.scannerProcess2.start()
		except:
			self.updateText("<h2>Connection not made, make sure you entered the host correctly<h2>")
			return

	def runRegularSSLScan(self,connectionHost):
		self.updateText("<h2>Host: " + str(connectionHost) + "</h2>")
		self.updateText("<h2>Running scan, this may take some time..</h2>")

		if self.isWindows:
			try:

				subprocess.check_output(["wsl",self.convertedPathWindows,"--ip","one","--openssl",self.openSSLConfig,"-oH","/mnt/c/Data/Scripts/result.html","--mapping","rfc",connectionHost]).replace("\n", "<br>") ## Work computer
				time.sleep(.5)
				subprocess.call("echo end >> C:\\Data\\Scripts\\result.html", shell=True)
			except:
				self.updateText("<h2>An unexpected error occurred while running the regular scan (Windows) :( Please try again</h2>")
				os.remove("C:\\Data\\Scripts\\result.html")
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)
				self.addToSitemap.setEnabled(True)
				self.targetSaveButton.setEnabled(True)
				time.sleep(.5)
		elif self.isLinux:
			try:

				subprocess.check_output([self.testSSLPath,"-oH","/dev/shm/result.html","--ip","one","--mapping","rfc",connectionHost]).replace("\n", "<br>")
				time.sleep(.5)
				subprocess.call('echo end >> /dev/shm/result.html', shell=True)
				time.sleep(.5)
			except:
				self.updateText("<h2>An unexpected error occurred while runnning the regular scan (Linux) :( Please try again</h2>")
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)
				self.addToSitemap.setEnabled(True)
				self.targetSaveButton.setEnabled(True)
				subprocess.call('rm /dev/shm/result.html', shell=True)
		else:
			self.updateText("<h2>An unexpected error occurred, cannot run scan:( Please try again</h2>")
			time.sleep(.5)
		time.sleep(.5)
		if self.addToSitemap.isSelected():
			self.addToScope()
		else:
			pass
		self.targetInputPanel.setEnabled(True)
		self.targetRunButton.setEnabled(True)
		self.targetSpecificButton.setEnabled(True)
		self.targetSpecificFlagsInput.setEnabled(True)
		self.targetSpecificRun.setEnabled(True)
		self.addToSitemap.setEnabled(True)
		self.targetSaveButton.setEnabled(True)
		time.sleep(.5)
		print "thread successfully terminated"
		sys.exit()		

	def startSpecificSSLScan(self,e):

		self.currentText = self.initialText

		if not self.targetSpecificButton.isSelected():
			self.updateText("<h2>Please check the checkbox in order to run specific scans.<h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)
			self.addToSitemap.setEnabled(True)
			return

		flags = list(str(self.targetSpecificFlagsInput.text).split(" "))

		moreFlags = list(filter(None, flags))

		if (len(moreFlags)==0):
			self.updateText("<h2>Please enter at least one flag that you want, separated by a space. </h2>")
			if self.isWindows:
				subprocessHelp = ["wsl",self.convertedPathWindows]
			elif self.isLinux:
				subprocessHelp = [self.testSSLPath]
			else:
				print "Can't do anything, inside specific scan function"
				return
			command = subprocess.check_output(subprocessHelp).replace("\n", "<br>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)
			self.addToSitemap.setEnabled(True)
			return

		host = self.targetInput.text

		if(len(host) == 0):
			return

		p = '(?P<protocol>http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
		m = re.search(p,host)
		self.site = m.group('host')
		self.protocol = m.group('protocol')
		self.port = m.group('port')

		if host.find("://") == -1:
			self.connectionHost = "https://" + host

		if self.protocol == 'https://':
			pass
		elif self.protocol == 'http://':
			self.updateText("<h2>regular HTTP will cause the program to crash, please enter again</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			return
		elif self.protocol == None:
			self.protocol = 'https://'
		else:
			self.updateText("<h2>Something weird happened.. Check the protocol you entered</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			return			

		if self.port != '':
			if self.port == '80':
				self.updateText("<h2>port 80 cannot be used with testssl, please enter again<h2>")
				self.targetInputPanel.setEnabled(True)
				self.targetRunButton.setEnabled(True)
				self.targetSpecificButton.setEnabled(True)
				self.targetSpecificFlagsInput.setEnabled(True)
				self.targetSpecificRun.setEnabled(True)	
				self.addToSitemap.setEnabled(True)
				return					
			elif self.port == '443':
				self.connectionHost = "https://" + self.site + ":" + self.port
			else:
				self.connectionHost = self.site + ":" + self.port
		else:
			self.port == '443'

		try:
			self.targetURL = URL(self.connectionHost)
			if(self.targetURL.getPort() == -1):
				self.targetURL = URL("https", self.targetURL.getHost(), 443, "/")
			self.targetInputPanel.setEnabled(False)
			self.targetRunButton.setEnabled(False)
			self.targetSpecificButton.setEnabled(False)
			self.targetSpecificFlagsInput.setEnabled(False)
			self.targetSpecificRun.setEnabled(False)
			self.addToSitemap.setEnabled(False)					
			self.updateText("<h2>Connection made</h2>")
			self.scannerProcess = Thread(target=self.runSpecificSSLScan, args=(self.connectionHost,))
			self.scannerProcess2 = Thread(target=self.parseFile)
			self.scannerProcess.start()
			time.sleep(.5)
			self.scannerProcess2.start()
		except:
			self.updateText("<h2>Connection not made, make sure you entered the host correctly<h2>")
			return

	def runSpecificSSLScan(self,connectionHost):

		flags = list(str(self.targetSpecificFlagsInput.text).split(" "))

		moreFlags = list(filter(None, flags))

		try:
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
							'-BB',
							'--robot',
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
							'-W',
							'-sweet32',
							'-L',
							'--lucky13',
							'-s',
							'--pfs',
							'--fs',
							'--nsa',
							'-4',
							'--rc4',
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
			wrongInput = False
			if self.isWindows:
	
				subprocessArguments = ["wsl",self.convertedPathWindows,"--openssl",self.openSSLConfig,"--ip","one","--mapping","rfc"]
				subprocessHelp = ["wsl",self.convertedPathWindows]

			elif self.isLinux:

				subprocessArguments = [self.testSSLPath,"--ip","one","--mapping","rfc"]
				subprocessHelp = [self.testSSLPath]
			else:
				return

			if len(moreFlags) == 0:
				self.updateText("<h2>Please enter at least one flag<h2>")
				return
			elif len(moreFlags) == 1:
				if moreFlags[0] in allOptions:
					subprocessArguments.append(moreFlags[0])
					print subprocessArguments
				else:
					wrongInput = True
					self.updateText("<h2>The input entered is not a valid flag for testssl. Please enter input again<h2>")
			else:
				for i in moreFlags:
					if i in allOptions:
						subprocessArguments.append(i)
					else:
						wrongInput = True
				if wrongInput == True:		
					self.updateText("<h2>A flag that was entered is not a recognized flag for testssl, please enter again</h2>")

			if wrongInput == True:
				print "wrong input entered"
				command = subprocess.check_output(subprocessHelp).replace("\n", "<br>")
				print "running help command"
				self.updateText(command)
			else:
				if self.isWindows:
					subprocessArguments.append("-oH")
					subprocessArguments.append("/mnt/c/Data/Scripts/result.html")
				elif self.isLinux:
					subprocessArguments.append("-oH")
					subprocessArguments.append("/dev/shm/result.html")
				else:
					print "Nothing was run"
				subprocessArguments.append(str(connectionHost))
				print subprocessArguments
				self.updateText("<h2>Host: " + str(connectionHost) + "</h2>")
				self.updateText("<h2>Starting scan, this may take some time</h2>")
				command = subprocess.check_output(subprocessArguments).replace("\n", "<br>")
				if self.isWindows:
					subprocess.call("echo end >> C:\\Data\\Scripts\\result.html", shell=True)
				elif self.isLinux:
					subprocess.check_output('echo end >> /dev/shm/result.html', shell=True)	
				else:
					print "Nothing was run"
			time.sleep(.5)
			if self.addToSitemap.isSelected():
				self.addToScope()
			else:
				pass			
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			self.targetSaveButton.setEnabled(True)
			print "Thread1 successfully terminated"
			time.sleep(.5)
		except:
			self.updateText("<h2>An unexpected error occurred... :( Please try again. Make sure if you're entering additional flags that you enter them correctly</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			self.targetSaveButton.setEnabled(True)
			time.sleep(.5)
		sys.exit()

	def parseFile(self):
		Finish = True
		blacklist = ['<?','<!','<html','</html','<head','</head','<body','</body','<pre','<pre','<title','</title','<meta','</meta']
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		try:
			with open(filePath) as fileName:
				line_found = False
				while Finish:
					for line in fileName:
						if line == 0:
							continue
						elif line.startswith(tuple(blacklist)):
							continue
						elif line.startswith('end'):
							if self.addToSitemap.isSelected():
								self.isBEAST()
								self.isHeartbleed()
								self.isCCS()
								self.isTicketBleed()
								self.isROBOT()
								self.isRenegotiation()
								self.isClientRenegotiation()
								self.isCRIME()
								self.isBREACH()
								self.isPoodle()
								self.isTLSFallback()
								self.isSweet()
								self.isFreak()
								self.isDrowning()
								self.isLogjam()
								self.isLucky13()
								self.isRC4()
							Finish = False
						else:
							newLine=line+"<br>"
							self.updateText(newLine)
				if self.isWindows:
					os.remove("C:\\Data\\Scripts\\result.html")
					print "file was deleted (windows)"
				elif self.isLinux:
					subprocess.call('rm /dev/shm/result.html', shell=True)
					print "file was deleted (linux)"
				else:
					print "Program shouldn't be running cuz the OS wasn't detected.."
					time.sleep(.5)
		except:
			print "Something went wrong in the parse statement"
			if self.isWindows:
				subprocess.call('del C:\\Data\\Scripts\\result.html', shell=True)
			elif self.isLinux:
				subprocess.call('rm /dev/shm/result.html', shell=True)
			else:
				self.ResultText("<h1>An unexpected error occurred while reading and outputing the results :(")
		print "thread2 successfully terminated"
		sys.exit()

	def isBEAST(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		extraLine = ''
		ciphers = ''
		self.beastCiphers = ''
		found_type = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2011-3389)' in line:
						found_type = True
					if found_type:
						if 'but also supports higher protocols' in line or '(CVE-2013-0169)' in line:
							found_type = False
						else:
							extraLine += str(line).rstrip('\n')
							ciphers = extraLine
				match = re.findall('(TLS_\S+)', ciphers.replace('\n',' '))
				for group in match:
					self.beastCiphers += str(group + '\n')
		except:
			print "something went wrong"

	def isHeartbleed(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.heartbleedVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2014-0160)' in line and 'not vulnerable (OK)' in line:
						self.heartbleedVulnerable = False	
					elif '(CVE-2014-0160)' in line and 'VULNERABLE (NOT ok)' in line:
						self.heartBleedVulnerable = True
					else:
						pass					
		except:
			print "something went wrong"

	def isCCS(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.CCSVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2014-0224)' in line and 'not vulnerable (OK)' in line:
						self.CCSVulnerable = False 
					elif '(CVE-2014-0224)' in line and 'VULNERABLE (NOT ok)' in line:
						self.CCSVulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isTicketBleed(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.TicketBleedVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2016-9244)' in line and 'not vulnerable (OK)' in line:
						self.TicketBleedVulnerable = False  
					elif '(CVE-2016-9244)' in line and 'VULNERABLE (NOT ok)' in line:
						self.TicketBleedVulnerable = True
					else:
						 pass
		except:
			print "something went wrong"		

	def isROBOT(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.ROBOTVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if 'ROBOT' in line and 'not vulnerable (OK)' in line:
						self.ROBOTVulnerable = False
					elif 'ROBOT' in line and 'VULNERABLE (NOT ok)' in line:
						self.ROBOTVulnerable = True
					else:
						 pass
		except:
			print "something went wrong"

	def isRenegotiation(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.RenegotiationVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2009-3555)' in line and 'not vulnerable (OK)' in line:
						self.RenegotiationVulnerable = False  
					elif '(CVE-2009-3555)' in line and 'VULNERABLE (NOT ok)' in line:
						self.RenegotiationVulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isClientRenegotiation(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.ClientRenegotiationVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if 'Secure Client-Initiated Renegotiation' in line and 'not vulnerable (OK)' in line:
						self.ClientRenegotiationVulnerable = False   
					elif 'Secure Client-Initiated Renegotiation' in line and 'VULNERABLE (NOT ok)' in line:
						self.ClientRenegotiationVulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isCRIME(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.CRIMEVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2012-4929)' in line and 'not vulnerable (OK)' in line:
						self.CRIMEVulnerable = False
					elif '(CVE-2012-4929)' in line and 'VULNERABLE (NOT ok)' in line:  
						self.CRIMEVulnerable = True
					else:
						pass
		except:
			print "something went wrong"	

	def isBREACH(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.BreachVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2013-3587)' in line and 'no HTTP compression (OK)' in line:
						self.BreachVulnerable = False  
					elif '(CVE-2013-3587)' in line and 'NOT ok' in line:
						self.BreachVulnerable = True
					else:
						pass
		except:
			print "something went wrong"	

	def isPoodle(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.PoodleVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2014-3566)' in line and 'not vulnerable (OK)' in line:
						self.PoodleVulnerable = False  
					elif '(CVE-2014-3566)' in line and 'VULNERABLE (NOT ok)' in line:
						self.PoodleVulnerable = True
					else:
						pass
		except:
			print "something went wrong"	

	def isTLSFallback(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.TLSFallbackVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(RFC 7507)' in line and 'not vulnerable (OK)' in line:
						self.TLSFallbackVulnerable = False  
					elif '(RFC 7507)' in line and 'VULNERABLE (NOT ok)' in line:
						self.TLSFallbackVulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isSweet(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.SweetVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2016-2183, CVE-2016-6329)' in line and 'not vulnerable (OK)' in line:
						self.SweetVulnerable = False  
					elif '(CVE-2016-2183, CVE-2016-6329)' in line and ', uses 64 bit block ciphers' in line:
						self.SweetVulnerable = True
					else:
						pass
		except:
			print "something went wrong"
															
	def isFreak(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.FreakVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2015-0204)' in line and 'not vulnerable (OK)' in line:
						self.FreakVulnerable = False 
					elif '(CVE-2015-0204)' in line and 'VULNERABLE (NOT ok)' in line:
						self.FreakVulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isDrowning(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.DrownVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2016-0800, CVE-2016-0703)' in line and 'not vulnerable (OK)' in line:
						self.DrownVulnerable = False  
					elif '(CVE-2016-0800, CVE-2016-0703)' in line and 'VULNERABLE (NOT ok)' in line:
						self.DrownVulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isLogjam(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.LogjamVulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2015-4000)' in line and 'not vulnerable (OK)' in line:
						self.LogjamVulnerable = False  
					elif '(CVE-2015-4000)' in line and 'VULNERABLE (NOT ok)' in line:
						self.LogjamVulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isLucky13(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		self.Lucky13Vulnerable = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2013-0169)' in line and 'not vulnerable (OK)' in line:
						self.Lucky13Vulnerable = False  
					elif '(CVE-2013-0169)' in line and 'uses cipher block chaining (CBC)' in line:
						self.Lucky13Vulnerable = True
					else:
						pass
		except:
			print "something went wrong"

	def isRC4(self):
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "OS not found"
		extraLine = ''
		ciphers = ''
		self.rc4Ciphers = ''
		found_type = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if '(CVE-2013-2566, CVE-2015-2808)' in line:
						found_type = True
					if found_type:
						if 'ordered by encryption strength' in line:
							found_type = False
						else:
							extraLine += str(line).rstrip('\n')
							ciphers = extraLine
				match = re.findall('(TLS_\S+)', ciphers.replace('\n',' '))
				for group in match:
					self.rc4Ciphers += str(group + '\n')
		except:
			print "something went wrong"

## Need to write check for PFS
	# def isPFS(self):
	# 	if self.isWindows:
	# 		filePath = 'C:\\Data\\Scripts\\result.html'
	# 	elif self.isLinux:
	# 		filePath = '/dev/shm/result.html'
	# 	else:
	# 		print "OS not found"		

	def updateText(self, stringToAppend):
		self.currentText += str(stringToAppend)
		self.textPane.setText(self.currentText)
		self.textPane.setCaretPosition(self.textPane.getDocument().getLength())

	def clearText(self, e):
		self.initialText = ('<h1 style="color: red;">'
			' When running, you may experience crashes. Just deal with it, this is still a work in progress<br>'
			' Make sure you have testssl installed in the /opt directory for Linux or ___ for Windows<br>'
			' In addition, make sure you have /dev/shm on your machine</h1>')
		self.textPane.setText(self.initialText)
		self.targetSaveButton.setEnabled(False)

	def saveToFile(self, event):
		fileChooser = JFileChooser()
		if not (self.connectionHost is None):
			fileChooser.setSelectedFile(File("Scan_Output_%s.html" \
				% (str(self.connectionHost))))
		else:
			fileChooser.setSelectedFile(File("Scan_Output.html"))
		if (fileChooser.showSaveDialog(self.getUiComponent()) == JFileChooser.APPROVE_OPTION):
			fw = FileWriter(fileChooser.getSelectedFile())
			fw.write(self.textPane.getText())
			fw.flush()
			fw.close()

	def addToScope(self):
		if self.port == '':
			self.port = "443"
		fullSiteString = self.protocol + self.site + ":" + self.port + "/"
		finalURL = URL(fullSiteString)
		newRequest = self._helpers.buildHttpRequest(finalURL)
		issueList = []
		noPriorIssues = False
		try:
			print "\r\n\r\n\r\n\r\n\r\n\r\n\r"
			requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(finalURL.getHost()), int(self.port), str(finalURL.getProtocol()) == "https"), newRequest)
			if not requestResponse.getResponse() == None:
				self.addedToSiteMap = self._callbacks.addToSiteMap(requestResponse)
				if self.beastCiphers != None and self.beastCiphers != "":
					beastIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"CBC-mode ciphers are used in conjunction with TLSv1.0, which are vulnerable to the BEAST "
						"attack, although the attack also relies on the attacker being able to force the browser "
						"to generate many thousands of chosen plaintext through a malicious applet or cross-site "
						"scripting. Additionally all modern browsers now provide mitigations for this attack.\r\n"
						"Ciphers using the Cipher Block Chaining mode of operation in TLSv1.0 and SSLv3 are vulnerable "
						"to an attack that could allow for the contents of encrypted communications to be retrieved. "
						"For the attack to succeed, an attacker must be able to inject arbitrary plaintext into "
						"communications between users and a server, e.g., using a malicious applet or a "
						"Cross-Site-Scripting (XSS) vulnerability, and then observe the corresponding cipher texts. "
						"Given several thousand requests, an attacker can then use this to determine the subsequent "
						"plaintext blocks by encrypting the same messages multiple times. The vulnerability has been "
						"fixed as of TLSv1.1 and client-side mitigations have been implemented by all current browsers."
						"<br>TLSv1 Ciphers vulnerable to BEAST: <br>" + self.beastCiphers + "",
						"The web server should be hardened to remove support for weak cipher suites. ",
						"BEAST attack",
						"Medium"
					)
					issueList.append(beastIssue)
				else:
					pass
				if self.heartbleedVulnerable == True:
					heartbleedIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The host is vulnerable to the HeartBleed vulnerability, "
						"which exposes the memory content of the host, allowing "
						"sensitive information to be stolen. ",
						"Update OpenSSL to version 1.0.1g or higher",
						"Heartbleed",
						"High"
					)
					issueList.append(heartbleedIssue)
				else:
					pass
				if self.CCSVulnerable == True:
					CCSIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The host is vulnerable to the CCS Injection vulnerability, "
						"which allows malicious intermediate nodes to intercept "
						"encrypted data and decrypt them while forcing SSL clients "
						"to use weak keys which are exposed to malicious nodes." ,
						"Update OpenSSL to version 1.0.1g or higher",
						"CCS Injection",
						"Medium"
					)
					issueList.append(CCSIssue)
				if self.TicketBleedVulnerable == True:
					TicketbleedIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The host is vulnerable to the Ticketbleed vulnerability, "
						"which exposes the memory content of the host, allowing "
						"sensitive information to be stolen. ",
						"Disable session tickets, and upgrade to a non vulnerable "
						"version. Please see the following link for more information "
						"<a href=https://support.f5.com/csp/article/K05121675</a> " ,
						"TicketBleed",
						"Medium"
					)
					issueList.append(TicketbleedIssue)
				else:
					pass
				if self.ROBOTVulnerable == True:
					RobotIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The host is vulnerable to the ROBOT (Return of Bleichenbacher " 
						"Oracle Threat vulnerability, which allows an adaptive-chosen "
						"ciphertext attack that fully breaks the confidentiality of TLS "
						"when used with RSA encryption. " ,
						"Disable RSA encryption. Most modern TLS connections use an "
						"Elliptic Curve Diffie Hellman key exchange and need RSA only "
						"for signatures. " ,
						"Robot",
						"Medium"
					)
					issueList.append(RobotIssue)
				else:
					pass	
				if self.RenegotiationVulnerable == True:
					RenegotiationIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The TLS protocol, and the SSL protocol 3.0 and possibly earlier "
						"as used in Microsoft Internet Information Services (IIS) 7.0, mod_ssl"
						"in the Apache HTTP Server 2.2.14 and earlier, OpenSSL before 0.9.8l, "
						"GnuTLS 2.8.5 and earlier, Mozilla Netowkr Security Services (NSS) 3.12.4 "
						"and earlier, multiple Cisco products, and other products, does not properly"
						"associate renegotiation handshakes with an existing connection, which allows"
						"man-in-the-middle attackers to insert data into HTTPS sessions, and possibly "
						"other types of sessions protected by TLS or SSL, by sending an unauthenticated"
						"request that is processed retroactively by a server in a post-renegotiation "
						"context." ,
						"Upgrade to the latest software version." ,
						"Secure Renegotiation",
						"Medium"
					)
					issueList.append(RenegotiationIssue)
				else:
					pass
				if self.ClientRenegotiationVulnerable == True:
					ClientRenegotiationIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The web server supports HTTPS client-initiated renegotiation which could "
						"allow an attacker to prevent legitimate users from accessing the application. "
						"The applicatoin's secure communication channel (HTTPS via SSL/TLS) offers "
						"clients the ability to renegotiate their existing secure communications sessions ."
						"Re-negotiations involve repeating the initial SSL/TLS handshake which generally "
						"requires more computational resources on the server than on the client. An "
						"attacker could therefore overwhelm the server with hundreds of renegotiation "
						"requests in order to attempt to exceed th server's computational capacity. "
						"if this occurred, legitimate application users would not be able to access "
						"the application for the duration of the attack." ,
						"Evaluate the business case for supporting all client-initiated renegotiation. "
						"If none exists, disable support for all client-initiated renegotiation." ,
						"Client-Initiated Renegotiation",
						"Medium"
					)
					issueList.append(ClientRenegotiationIssue)
				else:
					pass
				if self.CRIMEVulnerable == True:
					CRIMEIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The server offers TLS compression which can lead to a chosen plaintext attack "
						"where the attack can recover secret cookies such as authentication cookies "
						"using the size of compressed requests / responses. " ,
						"Disable TLS compression on the server." ,
						"CRIME",
						"Medium"
					)
					issueList.append(CRIMEIssue)
				else:
					pass
				if self.BreachVulnerable == True:
					breachIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The server offers HTTP compression which can lead to a chosen plaintext attack "
						"similar to CRIME where the attack can recover secret cookies such as authentication "
						"cookies using the size of compressed requests / responses." ,
						"Disable HTTP compression on the server or ignored if there is no secre in the page." ,
						"BREACH",
						"Medium"
					)
					issueList.append(breachIssue)
				else:
					pass
				if self.PoodleVulnerable == True:
					poodleIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"Padding Oracle on Downgraded Legacy Encryption (POODLE) is an attack targeting cipher "
						"suites in SSLv3 that use Cipher Block Chaining (CBC). Even if the more secure TLS "
						"protocol is enabled, backward compatibility with SSLv3 allows an attacker to force the "
						"downgrade of the encryption protocol from TLSv1.0 to SSLv3. Once the downgrade attack "
						"is complete the padding oracle attack may continue. This combination is known as the "
						"POODLE attack. The feasability of the attack is limited by several preconditions that "
						"must be met. For more details on the attack please refer to the following link: "
						"<a href=https://www.openssl.org/~bodo/ssl-poodle.pdf</a>" ,
						"Disable SSLv3 on the server." ,
						"POODLE",
						"Medium"
					)
					issueList.append(poodleIssue)	
				else:
					pass
				if self.TLSFallbackVulnerable == True:
					TLSFallbackIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The host does not support the TLS_FALLBACK_SCSV flag, which protects the connection "
						"from being downgraded to weaker encryptions, such as SSLv3." ,
						"If OpenSSL is used, update to version 1.0.1j or higher. Otherwise, update the web "
						"server and client to the latest version." ,
						"TLS Fallback ",
						"Medium"
					)
					issueList.append(TLSFallbackIssue)	
				else:
					pass
				if self.SweetVulnerable == True:
					print "SWEET IS TRUE"
					sweetIssueBro = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The TLS configuration allowed the use of Triple-DES ciphers, which are vulnerable to a "
						"birthday attack due to the increased probability of collisions as a result of 3DES's "
						"64-bit cipher block size. An attacker who is suitably positioned can monitor an extended "
						"Triple-DES encrypted HTTPS connection between a web browser and the application and recover "
						"secure HTTP cookies by capturing large volumes of data and performing cryptanalysis to detect "
						"collisions - a single cipher block collision requires approximately 32GB." ,
						"It is recommended that ciphers with small cipher blocks are not supported by the server." ,
						"Sweet32 (TripleDES Birthday Attack)",
						"Medium"
					)
					issueList.append(sweetIssueBro)
				else:
					pass
				if self.FreakVulnerable == True:
					freakIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"Factoring RSA Export Keys (FREAK) is a downgrade attack based on the so called 'RSA_EXPORT'"
						"ciphers which were introduced into the SSL standard in the 1990s to comply with US export "
						"restrictions on cryptography. These ciphers use RSA keys with key sizes of 512 bit or below, "
						"which (at the time of introduction) could only be factored very resourceful attackers such as "
						"the National Security Agency (NSA). Due to advancements in computing power and factoring algorithms, "
						"these attacks are now within reach of normal (non-nation-state) attackers. If the RSA_EXPORT ciphers"
						"are supported by the server and the attacker can downgrade the connection to use one of these ciphers, "
						"he/she can subsequently decipher the complete traffic." ,
						"Disable support for TLS export cipher suites and / or upgrade OpenSSL." ,
						"FREAK",
						"Medium"
					)
					issueList.append(freakIssue)
				else:
					pass	
				if self.DrownVulnerable == True:
					drownIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, "
						"requires a server to send a ServerVerify message before establishing that a client possesses "
						"certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext "
						"data by leveraging a Bleichenbacher RSA padding." ,
						"Disable SSLv2 on thte server. Do not reuse the certificate on SSLv2 hosts. " ,
						"DROWN",
						"Medium"
					)
					issueList.append(drownIssue)	
				else:
					pass
				if self.LogjamVulnerable == True:
					logjamIssue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"Logjam is a downgrade attack based on the so called 'DHE_EXPORT' ciphers which were introduced "
						"into the SSL standard in the 1990s to comply with the US export restrictions on cryptography. "
						"These ciphers use a weak 512 bit Diffie-Hellman group that allows an attacker to determine the key "
						"agreed upon by client and server in the Diffie-Hellman key exchange." ,
						"Disable DHE_EXPORT cipher support." ,
						"LOGJAM",
						"Medium"
					)
					issueList.append(logjamIssue)	
				else:
					pass
				if self.Lucky13Vulnerable == True:
					luckyIssueBro = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The LUCKY13 attack is a cryptographic timing attack against implementations of the Transport "
						"Layer Security (TLS) protocol that use the CBC mode of operation. LUCKY13 uses a timing side-channel "
						"attack against the message authentication code (MAC) check stage in the TLS algorithm to bypass "
						"protections previously implemented to block Vaudenay's attack" ,
						"Check the server version and update to the latest version." ,
						"Lucky13",
						"Medium"
					)
					issueList.append(luckyIssueBro)
				else:
					pass
				if self.rc4Ciphers != None and self.rc4Ciphers != "":
					RC4Issue = CustomIssue(
						requestResponse.getHttpService(),
						requestResponse.getUrl(),
						"The server uses insecure RC4 ciphers, which have known vulnerabilities. "
						"RC4 ciphers: " + self.rc4Ciphers + "" ,
						"Disable RC4 cipher support. " ,
						"RC4 Ciphers",
						"High"
					)
					issueList.append(RC4Issue)

				newIssueNames = []

				for names in issueList:
					newIssueNames.append(names.getIssueName())
				try:
					scanIssues = self._callbacks.getScanIssues(finalURL.getProtocol()+"://"+finalURL.getHost())
				except:
					noPriorIssues = True
				if noPriorIssues == True:
					for issue in issueList:
						self._callbacks.addScanIssue(issue)
				else:	
					# try:
					if not issueList:
						print "No issues were detected, very impressive"
						return
					else:
						oldIssueNames = []
						for oldIssue in scanIssues:
							oldIssueNames.append(oldIssue.getIssueName())
						missingIssueList = list(set(newIssueNames)-set(oldIssueNames))
						try:
							for issue in issueList:
								if issue.getIssueName() in missingIssueList:
									self._callbacks.addScanIssue(issue)
								else:
									print ""+ issue.getIssueName() + " was not found in missingIssueList"
						except Exception as ex:
							print ex
							raise
							print "NOTHING IS WORKING!!!!"
			else:	
				self.updateText("<h2>Unable to add site to sitemap for some reason..</h2>")
		except:
			print "error adding issue"

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
					self.scannerInstance.targetInput.setText(url.toString())
				except:
					self.scannerInstance._callbacks.issueAlert("Cannot get URL from the currently selected message " + str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]))
				else:
					self.scannerInstance._callbacks.issueAlert("The selected request is not there")

class CustomIssue(IScanIssue):
    def __init__(self, httpService, url, issueBackground, remediationBackground, name, severity):
        self._httpService = httpService
        self._url = url
        self._issueBackground = issueBackground
        self._remediationBackground = remediationBackground
        self._name = name
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return self._issueBackground

    def getRemediationBackground(self):
        return self._remediationBackground

    def getIssueDetail(self):
        pass

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        pass

    def getHttpService(self):
		return self._httpService