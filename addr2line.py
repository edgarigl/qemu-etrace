# Depends on eu-addr2line
#
#

import os
import sys
import subprocess

class addr2line(object):
	def __init__(self, elf, comp_dir = None, addr2line = "eu-addr2line"):
		cmd = [addr2line, "-f", "-e", elf]
		if comp_dir == None:
			cmd += ['-A']
#		cmd = ["cat"]
		self.p = subprocess.Popen(cmd,
					shell=False,
					stdin=subprocess.PIPE,
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT, bufsize=0)

	def map(self, addr):
		self.p.stdin.write("0x%x\n\n" % addr);
		sym = self.p.stdout.readline().rstrip()
		loc = self.p.stdout.readline().rstrip()
		loc = loc.split(':')
		dummy = self.p.stdout.readline()
		dummy = self.p.stdout.readline()
		return [sym, loc]
