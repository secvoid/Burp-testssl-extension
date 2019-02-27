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

		self.initialText = ('<h1 style="color: red">'
			' When running, you may experience crashes. Just deal with it, this is stil a work in progress<br>'
			' Make sure you have testssl installed in the /opt directory for Linux or ___ for Windows<br>'
			' In addition, make sure you have /dev/shm on your machine</h2>')
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
			# if "testssl.sh" in subprocess.check_output(["find","/opt","-name","testssl.sh","-type","-f"]):
			# if 'testssl.sh' in 'testssl.sh':
			findPath = subprocess.check_output(["find","/opt","-name","testssl.sh","-type","f"]).split('\n')[0]
			self.findPath2 = str(findPath).lstrip()
			# self.findPathLinux = '/opt/testssl.sh/testssl.sh'
			self.findPath3 = self.findPath2.split(" ")[0]
			self.testSSLPath = self.findPath3.strip()
			print self.testSSLPath
				# print self.findPathLinux
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

		# self.scannedHost = []

		print 'MOARSSL! extension loaded successfully!'

	def getTabCaption(self):
		return "MOARSSL!"

	def getUiComponent(self):
		return self._splitpane  		

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

		# path = str(self.testSSLPath)

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
			print self.targetURL
			if(self.targetURL.getPort() == -1):
				self.targetURL = URL("https", self.targetURL.getHost(), 443, "/")
			self.targetInputPanel.setEnabled(False)
			self.targetRunButton.setEnabled(False)
			self.targetSpecificButton.setEnabled(False)
			self.targetSpecificFlagsInput.setEnabled(False)
			self.targetSpecificRun.setEnabled(False)
			self.addToSitemap.setEnabled(False)				
			self.updateText("<h2>Connection made</h2>")
			# self.scannerProcess = Thread(target=self.runRegularSSLScan, args=(self.url,))
			self.scannerProcess = Thread(target=self.runRegularSSLScan, args=(self.connectionHost,))			
			self.scannerProcess2 = Thread(target=self.parseFile)
			self.scannerProcess.start()
			time.sleep(3)
			self.scannerProcess2.start()
		except:
			self.updateText("<h2>Connection not made, make sure you entered the host correctly<h2>")
			return

	def runRegularSSLScan(self,connectionHost):
		# self.updateText("<h2>Host: " + str(url) + "</h2>")
		self.updateText("<h2>Host: " + str(connectionHost) + "</h2>")
		self.updateText("<h2>Running scan, this may take some time..</h2>")

		# command = subprocess.check_output(["/opt/testssl.sh/testssl.sh","-oH","/opt/testssl.sh/testing/result.txt","--mapping","rfc","--append",url]) ## For home computer linux vm
		if self.isWindows:
			try:
				command = subprocess.check_output(["wsl",self.convertdPathWindows,"-oH","/mnt/c/Data/Scripts/result.html","--mapping","rfc","--append",connectionHost]).replace("\n", "<br>") ## Work computer
				time.sleep(1)
			except:
				self.updateText("<h2>An unexpected error occurred while running the regular scan (Windows) :( Please try again</h2>")
				time.sleep(1)
		elif self.isLinux:
			try:
				subprocess.check_output([self.testSSLPath,"-oH","/dev/shm/result.html","--mapping","rfc","-A",connectionHost]).replace("\n", "<br>")
				# subprocess.check_output([self.findPathLinux,"-oH","/root/Desktop/result.html","--mapping","rfc","--append",url]).replace("\n", "<br>")
				time.sleep(1)
				subprocess.call('echo end >> /dev/shm/result.html', shell=True)
				time.sleep(1)
			except:
				self.updateText("<h2>An unexpected error occurred while runnning the regular scan (Linux) :( Please try again</h2>")
		else:
			self.updateText("<h2>An unexpected error occurred, cannot run scan:( Please try again</h2>")
			time.sleep(1)
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
		time.sleep(1)
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
			time.sleep(3)
			self.scannerProcess2.start()
		except:
			self.updateText("<h2>Connection not made, make sure you entered the host correctly<h2>")
			return

	def runSpecificSSLScan(self,connectionHost):

		flags = list(str(self.targetSpecificFlagsInput.text).split(" "))

		moreFlags = list(filter(None, flags))

		try:
			self.updateText("<h2>Host: " + str(connectionHost) + "</h2>")

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
			wrongInput = False

			# subprocessArguments = ["/opt/testssl.sh/testssl.sh","--color",str(0)] ## Home linux vm testing
			# subprocessHelp = ["/opt/testssl.sh/testssl.sh"] ## Home linux vm testing
			if self.isWindows:
				subprocessArguments = ["wsl",self.convertedPathWindows]
				subprocessHelp = ["wsl",self.convertedPathWindows]
			elif self.isLinux:
				subprocessArguments = [self.findPathLinux,"-oH","/dev/shm/result.html","--mapping","rfc"]
				subprocessHelp = [self.findPathLinux]
			else:
				print "Can't do anything, inside specific scan function"
				return

			if len(moreFlags) == 1:

				if moreFlags[0] in informationOptions:
					infoFlagCheck = True
					subprocessHelp.append(moreFlags[0])
				elif moreFlags[0] in allOptions:
					subprocessArguments.append(moreFlags[0])
					print subprocessArguments
				else:
					wrongInput = True
					self.updateText("<h2>The input entered is not a valid flag for testssl. Please enter input again<h2>")
			else:
				for i in moreFlags:
					if i in informationOptions:
						infoFlagCheck = True
						subprocessHelp.append(i)
						print subprocessHelp
					elif i in allOptions:
						subprocessArguments.append(i)
					else:
						wrongInput = True
						self.updateText("<h2>A flag that was entered is not a recognized flag for testssl, please enter again</h2>")

			if wrongInput == True:
				subprocessHelp = [self.findPathLinux]
				print subprocessHelp
				command = subprocess.check_output(subprocessHelp).replace("\n", "<br>")
				self.updateText(command)
			else:
				if infoFlagCheck == True:
					command = subprocess.check_output(subprocessHelp).replace("\n", "<br>")
					self.updateText(command)
				else:
					subprocessArguments.append(str(connectionHost))
					print subprocessArguments
					command = subprocess.check_output(subprocessArguments).replace("\n", "<br>")
					subprocess.check_output('echo end >> /dev/shm/result.html', shell=True)	
			if self.addToSitemap.isSelected():
				print "adding to sitemap"
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
			time.sleep(2)
		except:
			self.updateText("<h2>An unexpected error occurred... :( Please try again. Make sure if you're entering additional flags that you enter them correctly</h2>")
			self.targetInputPanel.setEnabled(True)
			self.targetRunButton.setEnabled(True)
			self.targetSpecificButton.setEnabled(True)
			self.targetSpecificFlagsInput.setEnabled(True)
			self.targetSpecificRun.setEnabled(True)	
			self.addToSitemap.setEnabled(True)
			self.targetSaveButton.setEnabled(True)
			time.sleep(2)
		sys.exit()

	def parseFile(self):
		Crying = True
		blacklist = ['<?','<!','<html','</html','<head','</head','<body','</body','<pre','<pre','<title','</title','<meta','</meta']
		if self.isWindows:
			filePath = 'C:\\Data\\Scripts\\result.html'
		elif self.isLinux:
			filePath = '/dev/shm/result.html'
		else:
			print "Can't do anything, inside parseFile function"
			print filePath
		try:
			with open(filePath) as fileName:
				line_found = False
				while Crying:
					for line in fileName:
						if line == 0:
							continue
						elif line.startswith(tuple(blacklist)):
							continue
						elif line.startswith('end'):
							if self.addToSitemap.isSelected():
								self.isBEAST()
							Crying = False
						else:
							newLine=line+"<br>"
							self.updateText(newLine)
				if self.isWindows:
					subprocess.call('del C:\\Data\\Scripts\\result.html', shell=True)
				elif self.isLinux:
					subprocess.call('rm /dev/shm/result.html', shell=True)
					print "file was deleted"
				else:
					print "Program shouldn't be running cuz the OS wasn't detected.."
					time.sleep(2)
		except:
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
			print "Can't do anything, inside parseFile function"
			print filePath
		extraLine = ''
		newLine = ''
		ciphers = ''
		self.beastCiphers = ''
		found_type = False
		try:
			with open(filePath) as fileName:
				for line in fileName:
					if 'BEAST' in line:
						found_type = True
						newLine = str(line)
						continue
					if found_type:
						if 'but also supports higher protocols' in line:
							found_type = False
						else:
							extraLine += str(line).rstrip('\n')
							ciphers = newLine + extraLine
				match = re.findall('(TLS_\S+)', ciphers.replace('\n',' '))
				for group in match:
					self.beastCiphers += str(group + '\n')
			# if self.beastCiphers == -1:
			# 	print "No ciphers found"
			# else:
			# 	print "Site is vulnerable to BEAST\r\n"
			# 	print "\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r"
			# 	print "Issue: Site uses ciphers that are vulnerable to BEAST attack"
			# 	print "Severity: Medium"
			# 	print "Confidence: Certain"
			# 	print "URL: " + str(self.url)
			# 	print "\r\nIssue Description: "
			# 	print "CBC-mode ciphers are used in conjunction with TLSv1.0, which are vulnerable to the BEAST "
			# 	print "attack, although the attack also relies on the attacker being able to force the browser "
			# 	print "to generate many thousands of chosen plaintext through a malicious applet or cross-site "
			# 	print "scripting. Additionally all modern browsers now provide mitigations for this attack.\r\n"
			# 	print "Ciphers using the Cipher Block Chaining mode of operation in TLSv1.0 and SSLv3 are vulnerable "
			# 	print "to an attack that could allow for the contents of encrypted communications to be retrieved. "
			# 	print "For the attack to succeed, an attacker must be able to inject arbitrary plaintext into "
			# 	print "communications between users and a server, e.g., using a malicious applet or a "
			# 	print "Cross-Site-Scripting (XSS) vulnerability, and then observe the corresponding cipher texts. "
			# 	print "Given several thousand requests, an attacker can then use this to determine the subsequent "
			# 	print "plaintext blocks by encrypting the same messages multiple times. The vulnerability has been "
			# 	print "fixed as of TLSv1.1 and client-side mitigations have been implemented by all current browsers. \r\n"
			# 	print "List of BEAST Ciphers: "
			# 	print "=========================================================\r\n"
			# 	print "TLSv1: "
			# 	print self.beastCiphers
			# 	print "========================================================="
			# 	print "\r\nIssue Remediation: "
			# 	print "Remove Support for Weak Ciphers "
			# 	print "Do something"
			# 	print "\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r"
		except:
			print "something went wrong"

	def updateText(self, stringToAppend):
		self.currentText += str(stringToAppend)
		self.textPane.setText(self.currentText)
		self.textPane.setCaretPosition(self.textPane.getDocument().getLength())

	def clearText(self, e):
		self.initialText = ('<h1 style="color: red">'
				' When running, you may experience crashes. Just deal with it, this is stil a work in progress<br>'
				' Make sure you have testssl installed in the /opt directory for Linux or ___ for Windows<br>'
				' In addition, make sure you have /dev/shm on your machine</h2>')
		self.textPane.setText(self.currentText)
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
		print "making new request"
		if self.port == '':
			self.port = "443"
		print "creating full string"
		print self.protocol
		print self.site
		print self.port
		fullSiteString = self.protocol + self.site + ":" + self.port + "/"
		print fullSiteString
		finalURL = URL(fullSiteString)
		# print finalURL
		newRequest = self._helpers.buildHttpRequest(finalURL)
		print "new request made"
		try:
			print "\r\n\r\n\r\n\r\n\r\n\r\n\r"
			print "creating requestResponse"
			requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(finalURL.getHost()), int(self.port), str(finalURL.getProtocol()) == "https"), newRequest)
			# builtService = self._helpers.buildHttpService(str(finalURL.getHost()), int(self.port), str(finalURL.getProtocol()) == "https")
			# requestResponse = self._callbacks.makeHttpRequest(builtService, newRequest)
			# print "requestResponse works"
			if not requestResponse.getResponse() == None:
				print "Something was received"
				# if not self._callbacks.(finalURL):
				# self.updateText("<h2>Adding site to sitemap<h2>")
				self.addedToSiteMap = self._callbacks.addToSiteMap(requestResponse)
				print "added to sitemap"
				if self.beastCiphers != None:
					print "There are ciphers vulnerable to BEAST, adding issue"		
					issue = CustomIssue(
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
					print type(issue)
					self._callbacks.addScanIssue(issue)
					print "issue added"
				else:
					print "No vulns were found"
			else:	
				self.updateText("<h2>Unable to add site to sitemap for some reason..</h2>")
				print "Nothing was received"
		except:
			# self.updateText("<h2>Error adding issue..</h2>")
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
					print "Selected URL: " + url.toString()
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
        # self._httpMessages = httpMessages
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
        return "Certain"

    def getIssueBackground(self):
        return self._issueBackground

    def getRemediationBackground(self):
        return self._remediationBackground

    def getIssueDetail(self):
        pass
        # return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        pass

    def getHttpService(self):
		return self._httpService