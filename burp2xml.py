#!/usr/bin/env python
#Developed by Paul Haas, <phaas AT redspin DOT com> under Redspin. Inc.
#Licensed under the GNU Public License version 3.0 (2008-2009)
'''Process Burp Suite Professional's output into a well-formed XML document.

Burp Suite Pro's session file zipped into a combination of XML-like tags 
containing leading binary headers with type and length definitions followed by
the actual data.  The theory is that this allows the file to read sequentially
rather than requiring tedious XML parsing.  However, without re-writing Burp's
internal parser, we have no way to extract results from its files without
loading the results in Burp.  

This tool takes a zipped Burp file and outputs a XML document based upon the
provided arguments which allows regular XPATH queries and XSL transformations.
'''
import datetime, string, re, struct, zipfile, base64, sys

TAG = re.compile('</?(\w*)>',re.M) # Match a XML tag
# Vertical Form Field \x0b and NP Form Field \x0c are not printable, \t\n\r are okay
nvprint = string.printable.replace('\x0b','').replace('\x0c','') # Printables

def milliseconds_to_date(milliseconds):
	'''Convert milliseconds since Epoch (from Java) to Python date structure:
	See: http://java.sun.com/j2se/1.4.2/docs/api/java/util/Date.html
	
	There is no direct way to convert milliseconds since Epoch to Python object
	So we convert the milliseconds to seconds first as a POSIX timestamp which
	can be used to get a valid date, and then use the parsed values from that
	object along with converting mili -> micro seconds in a new date object.'''
	try:
		d = datetime.datetime.fromtimestamp(milliseconds/1000)
		date = datetime.datetime(d.year,d.month,d.day,d.hour,d.minute,d.second,
			(milliseconds%1000)*1000)		
	except ValueError, e: # Bad date, just return the milliseconds
		sys.stderr.write("Error converting to date '%s': %s\n" % (str(milliseconds),e))
		date = str(milliseconds)
	return date	

def burp_binary_field(field,i):
	'''Strip Burp Suite's binary format characters types from our data.	
	The first character after the leading tag describes the type of the data.'''
	encoding = ''
	if len(field) <= i:		
		#sys.stderr.write("Bad field length greater than index %i > %i\n" % (len(field),i))
		length = -1
		value = None		
	elif field[i] == '\x00': # 4 byte integer value
		length = 5
		value = str(struct.unpack('>I',field[i+1:i+5])[0])
	elif field[i] == '\x01': # Two possible unsigned long long types
		length = 9
		value = str(struct.unpack('>Q',field[i+1:i+9])[0])	
		#if field[i+1] == '\x00': # (64bit) 8 Byte Java Date	
		#	date = milliseconds_to_date(ms)
		#	try: value = date.ctime() # Use the ctime string format for date
		#	except Exception, e: value = "0"		
	elif field[i] == '\x02': # Boolean Object True/False
		length = 2
		try:
			value = str(struct.unpack('?',field[i+1:i+2])[0])					
		except Exception, e:
			sys.stderr.write("Unknown boolean value '%s'\n" % (e))
			value = "UNKNOWN"
	elif field[i] == '\x03' or field[i] == '\x04': # 4 byte length + string		
		length = struct.unpack('>I',field[i+1:i+5])[0]
		value = field[i+5:i+5+length]	
		non_printable = [v for v in value if v not in nvprint]
		if non_printable:
			value = ''
			#value = base64.b64encode(value)
			#encoding = 'binary.base64'
		elif '<' in value or '>' in value or '&' in value: # Sanatize HTML w/CDATA
			value = '<![CDATA[' + value.replace(']]>',']]><![CDATA[') + ']]>'
		try:
			value = value.encode('utf-8') # Force encoding
		except Exception, e:
			sys.stderr.write("Strange string encoding '%s'\n" % (e))
			value = '***Weird Encoding***'	
		length += 5
	else:
		sys.stderr.write("Unknown binary format: %s\n" % repr(field[i]))
		length = -1
		value = None
				
	return value,length,encoding
	
def burp_to_xml_file(filename,output):
	'''Unzip Burp's file, remove non-printable characters, CDATA any HTML,
	include a valid XML header and trailer, and write to a XML document.'''

	out = open(output, 'wb')
	out.write('<?xml version="1.0"?>\n<burp>\n')

	z = zipfile.ZipFile(filename) # Open Burp's zip file
	if sys.version_info >= (2, 6):
		burp = z.read('burp','rb') # Read-in the main burp file
	else:
		burp = z.read('burp') # Read-in the main burp file Python 2.5 compatible
	m = TAG.match(burp,0) # Match a tag at the start of the string
	while m:		
		stag = m.group()
		index = m.end()	
		etag = stag.replace('<','</') # Matching tag

		m = TAG.match(burp,index) # Attempt to get the next tag
		if m: out.write(stag)		
		if not m: # Data folows and not another tag
			# Read the type of data using Burp's binary data headers		
			value, length, encoding = burp_binary_field(burp, index)
			if value is None: 
				out.write(stag)	
				break
			# If we encoded our returned value, put the encoding here
			if encoding: stag = stag.replace('>',' dt="dt:%s">' % encoding)
			
			out.write(stag)
			out.write(value)
			out.write(etag)
			out.write("\n")
			index += length + len(etag) # Point our index to the next tag
			m = TAG.match(burp,index) # And retrieve it
		
	out.write('\n</burp>\n')
	out.close()

def main():
	'''Called if script is run from the command line.'''
	import sys
	if (len(sys.argv) < 2):
		print __doc__
		print "Usage:",sys.argv[0],"burp_session_file {output XML name}"
		exit(1)
	# Write out file to a optional argument or provided filename + xml extension
	out = sys.argv[2] if (len(sys.argv) > 2) else sys.argv[1]+'.xml'
	burp_to_xml_file(sys.argv[1],out)

if __name__ == '__main__':
	main()

