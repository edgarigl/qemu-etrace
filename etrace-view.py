#!/usr/bin/env python
#
#

import sys
import os
import getopt
import time
import etrace

import curses

import addr2line

def usage():
	print "--help          Show help"
	print "--trace         filename of trace"

class traceview(object):

	def __init__(self, screen, e, elf_name, comp_dir, cfg):
		self.cfg = cfg
		self.fcache = {}
		self.e = e
		self.comp_dir = comp_dir
		self.screen = screen
		self.dw = None
		self.dw_loc = None
		self.record = None
		self.record_idx = 0
		self.record_pos = 0
		self.symname = ""
		self.file = ""
		self.line = -1
		self.search_sym = ""
		self.debugf = None
		self.addrloc = {}

		if elf_name != None:
			self.a2l = addr2line.addr2line(elf_name, comp_dir)

			self.screen.clear()
			self.screen.addstr(0, 0, "Processing ELF file.")
			s = self.a2l.map(0xc0005000)
			self.debug(str(s))
			s = self.a2l.map(0xff)
			self.debug(str(s))
			self.screen.refresh()
			self.screen.addstr(1, 0, "Done. Step into first src line")
			self.screen.refresh()

	def debug(self, str):
		if self.debugf == None:
			self.debugf = open(".debug", 'w+')
		self.debugf.write(str)
		self.debugf.write("\n")

	def update_file_cache(self, fname):
		try:
			lines = self.fcache[fname]["lines"]
			return lines
		except:
			pass

		# populate the entry
		full_fname = fname
		if self.comp_dir:
			full_fname = "%s/%s" % (self.comp_dir, fname)
		try:
			f = open(full_fname, 'r')
		except:
			return None

		if len(self.fcache) > 256:
			# flush it all
			self.fcache = {}

#		self.debug("update cahce %s" % fname)
		lines = f.readlines()
		self.fcache[fname] = { "lines" : lines }
		f.close()
#		self.debug("close file and got %d lines" % len(lines))
		return lines

	def show_file_contents(self, filename, line_nr):
		lines = self.update_file_cache(filename)
		if lines == None:
			self.debug("no src for %s" % filename)
			return

		(h, w) = self.screen.getmaxyx()
		h -= 4
		start = line_nr - h / 2
		if start < 0:
			start = 0
		for i in range(4, h - 1):
			try:
				str = "%4d:%s" % (start + i, lines[start + i])
			except:
				break
			if (start + i) == line_nr:
				self.screen.addstr(i, 0, str, curses.A_REVERSE)
			else:
				self.screen.addstr(i, 0, str)

	def step_end_of_subrecord(self, r):
		self.record_pos = r.all.ex.ex32[self.record_idx].end - 4
		if self.record_pos < r.all.ex.ex32[self.record_idx].start:
			self.record_pos = r.all.ex.ex32[self.record_idx].start

	def step_end_of_record(self, r):
		self.record_idx = r.all.ex.nr - 1
		self.step_end_of_subrecord(r)

	def step_start_of_record(self, r):
		self.record_idx = 0
		if r and r.hdr.type == self.e.TYPE_EXEC:
			self.record_pos = r.all.ex.ex32[self.record_idx].start

	def step_existing_record_back(self, r):
		if r == None or r.hdr.type != self.e.TYPE_EXEC:
			r = self.e.stepb()
			if r and r.hdr.type == self.e.TYPE_EXEC:
				self.step_end_of_record(r)
			return r

		# Now we know we've got an exec record.
		# Step back.
		if self.record_pos <= r.all.ex.ex32[self.record_idx].start:
			if self.record_idx == 0:
				r = self.step_existing_record_back(None)
				return r
			self.record_idx -= 1
			self.step_end_of_subrecord(r)
			return r
		self.record_pos -= 4
		return r

	def step_record(self, count):
		if self.record and count < 0:
			r = self.step_existing_record_back(self.record)
		elif self.record and count > 0:
			r = self.record

			if r.hdr.type == self.e.TYPE_EXEC:
				self.record_pos += 4

				if self.record_pos >= r.all.ex.ex32[self.record_idx].end:
					self.record_idx += 1
					self.record_pos = r.all.ex.ex32[self.record_idx].start

				if self.record_idx == r.all.ex.nr:
					self.record = None
					r = self.e.stepf()
					self.step_start_of_record(r)
			else:
				r = self.e.stepf()
				self.step_start_of_record(r)
		else:
			if count > 0:
				r = self.e.stepf()
				self.step_start_of_record(r)
			else:
				r = self.step_existing_record_back(None)
		return r

	def map_address_to_loc(self, address):
		if 'map_address' in self.cfg.keys():
			address = self.cfg['map_address'](address)

		loc = self.a2l.map(address)
		return loc


	def step_trace_record(self, count):
		goon = True
		r = self.step_record(count)
		self.record = r
		if r == None:
			return r

		if r.hdr.type == self.e.TYPE_EXEC:
			goon = True

			self.file = ""
			self.line = -1

#			self.debug("lookup %x" % self.record_pos)
			try:
				loc = self.addrloc[self.record_pos]
			except:
				loc = self.map_address_to_loc(self.record_pos)
				self.addrloc[self.record_pos] = loc
#			self.debug(str(loc))
			self.symname = loc[0]
			self.file = loc[1][0]
			if self.file == "??":
				self.file = ""
				self.line = -1
				return r
			self.line = int(loc[1][1]) - 1
#			self.debug("file=%s" % self.file)
#			self.debug("line=%s" % self.line)

		return r

	def step_new_exec(self, count = 1):
		r = None
		goon = True
		while goon:
			pfile = self.file
			pline = self.line
			r = self.step_trace_record(count)
			if not r:
				return None

			if r.hdr.type == self.e.TYPE_EXEC:
				goon = False
		return r

	def step_new_line(self, count = 1):
		r = None
		goon = True
		while goon:
			pfile = self.file
			pline = self.line
			r = self.step_trace_record(count)
			if not r:
				return None

			if pfile != self.file:
				goon = False

			if pline != self.line:
				goon = False

		return r

	def step_new_sym(self, newsymname = None, count = 1):
		r = None
		while True:
			if newsymname and newsymname == self.symname:
				break
			pname = self.symname
			r = self.step_new_line(count)
			if not r:
				return None

			if not newsymname and pname != self.symname:
				break
		return r


	def search_for_sym(self):
		(h, w) = self.screen.getmaxyx()
		curses.echo()
		self.screen.addstr(h - 1,0, "/")
		str = self.screen.getstr(h - 1, 1)
		str = str.rstrip()
		curses.noecho()
		return str

	def loop(self):
		c = curses.KEY_DOWN
		r = self.step_new_exec(count = 1)
		while True:
			if c == curses.KEY_DOWN:
				r = self.step_new_line()
			elif c == curses.KEY_RIGHT:
				r = self.step_new_sym(count = 1)
			elif c == curses.KEY_LEFT:
				r = self.step_new_sym(count = -1)
			if c == curses.KEY_UP:
				r = self.step_new_line(-1)
			elif c == ord('n'):
				if self.symname == self.search_sym:
					r = self.step_new_sym()
				r = self.step_new_sym(self.search_sym)
			elif c == ord('/'):
				old_r = self.record;
				self.search_sym = self.search_for_sym()
				r = self.step_new_sym(self.search_sym)
				if (r == None):
					r = old_r
			elif c == ord('g'):
				self.e.reset()
				r = self.step_new_exec(count = 1)
			elif c == ord('G'):
				r = True
				while r:
					r = self.step_trace_record(count = 1)
				r = self.step_new_exec(count = -1)
			elif c == ord('q'):
				return

			if r:
				self.screen.clear()
				self.screen.addstr(0, 0,
					"%d: type=%s %x len=%d PC=%x (%x-%x)" \
					% (self.e.r_idx, self.e.type_to_name(r.hdr.type),
						r.hdr.type, r.hdr.len, self.record_pos,
						r.all.ex.ex32[self.record_idx].start,
						r.all.ex.ex32[self.record_idx].end),
						curses.A_REVERSE)

				self.screen.addstr(1, 0,
					"file=%s:%s %s" \
					% (self.file, self.line, self.symname),
					curses.A_REVERSE)

				self.screen.addstr(3, 0,
					"search=%s" \
					% (self.search_sym),
					curses.A_REVERSE)

				try:
					self.show_file_contents(self.file, self.line)
				except:
					pass
				self.screen.refresh()
			else:
				self.screen.addstr(3, 0,
					"None", curses.A_REVERSE);

				self.screen.refresh()

			self.prev_file = self.file
			self.prev_line = self.line
			r = None
			c = self.screen.getch()

def main(screen):
	args_comp_dir = None
	args_trace = None
	args_elf = None

	try:
		opts, args = getopt.getopt(sys.argv[1:],
					"h",
					["help",
					 "comp-dir=",
					 "config=",
					 "trace=",
					 "elf=",
					]
					)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit(1)

	cfg = {}

	for o, a in opts:
		if o == "--trace":
			args_trace = a
		elif o == "--comp-dir":
			args_comp_dir = a
		elif o == "--config":
			execfile(a, cfg)
		elif o == "--elf":
			args_elf = a
		elif o in ("-h", "--help"):
			usage()
			sys.exit(0)
		else:
			assert False, "Unhandled option " + o

	if args_trace == None:
		print "Missing trace file"
		sys.exit(1)


	screen.clear()
	f = open(args_trace, 'rb')
	e = etrace.etrace(f)

	tv = traceview(screen, e, args_elf, args_comp_dir, cfg)

	tv.loop()

try:
	curses.wrapper(main)
except KeyboardInterrupt:
	sys.exit(0)

