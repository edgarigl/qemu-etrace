# Depends on eu-addr2line
#
#

import os
import sys
import string
import subprocess

class addr2line(object):
	def __init__(self, elf, comp_dir = None, addr2line = "eu-addr2line"):
		cmd = [addr2line, "-f", "-e", elf]
		if comp_dir == None:
			cmd += ['-A']
#		cmd = ["cat"]
		self.cmd = cmd
		self.debugf = None

	def debug(self, str):
		if self.debugf == None:
			self.debugf = open(".debug.addr2line", 'w+')
		self.debugf.write(str)
		self.debugf.write("\n")

	def map(self, addr):
		self.p = subprocess.Popen(self.cmd,
					shell=False,
					stdin=subprocess.PIPE,
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT, bufsize=0)
		(out, err) = self.p.communicate("0x%x\n" % addr)

		lines = string.split(out, '\n')
		sym = lines[0]
		loc = lines[1].split(':')
		return [sym, loc]
