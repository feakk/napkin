#!/usr/bin/env python
# Process Set-Cookie equivalent lines obtained from a HTTP server
# Assume lines are in the 'host: cookie' format, with most fields optional
import sys, re 

if sys.stdin.isatty(): 
	print "Please pipe list of 'Set-Cookie:' equivalent lines to", __file__
	exit(1)

print "#domain\tname\tsubdomain\thttponly\tsecure\texpires"	
for line in sys.stdin.readlines():
	cookie_dict = { 'name':'', 'value':'', 'domain':'', 'subdomain':'' , 'path':'', 'expires':'', 'expires_date':'', 'secure':'', 'httponly':'' }
	
	line = line.rstrip('\r\n') # chomp
	line = re.sub('Set-Cookie: ', '', line, re.I) # remove Set-Cookie: if it was left in line
	domain_cookie = line.split(':') # assume domain is provided first	
	cookie_dict['domain'] = domain_cookie[0]
	cookie_dict['subdomain'] = False
	cookie = ':'.join(domain_cookie[1:])
	each = cookie.split('; ')
	
	name_value = each[0].split('=')
	cookie_dict['name'] = name_value[0]
	cookie_dict['value'] = "=".join(name_value[1:])
	
	for e in each[1:]:
		name_value = e.split('=')
		name = name_value[0]
		value = "=".join(name_value[1:])
		if name.lower() == 'domain':
			if value.startswith('.'):
				cookie_dict['subdomain'] = True
			else:
				cookie_dict['subdomain'] = False
			value = re.sub('^\.', '', value, re.I)
			cookie_dict['domain'] = value			
		elif name.lower() == 'expires':
			cookie_dict['expires'] = False
			cookie_dict['expires_date'] = value
		elif name.lower() == 'httponly':
			cookie_dict['httponly'] = True
		elif name.lower() == 'path':
			cookie_dict['path'] = value
		elif name.lower() == 'secure':
			cookie_dict['secure'] = True
		else:
			print "Unknown HTTP Cookie name/value pair",name,value
			exit(2)
	# Name/Value pair not provided, use defaults
	if cookie_dict['name'] == '':
		print "Cookie name not defined"
		exit(3)
	if cookie_dict['domain'] == '':
		cookie_dict['domain'] = 'UNKNOWN'
		cookie_dict['subdomain'] = 'UNKNOWN'
	if cookie_dict['expires'] == '':
		cookie_dict['expires'] = True
		cookie_dict['expires_date'] = "Session"
	if cookie_dict['httponly'] == '':
		cookie_dict['httponly'] = False
	if cookie_dict['path'] == '':
		cookie_dict['path'] == '/'
	if cookie_dict['secure'] == '':
		cookie_dict['secure'] = False
	
	#Output like: Host, Name, Subdomain, HTTPOnly, Secure, Session with tabs
	print cookie_dict['domain']+'\t'+cookie_dict['name']+'\t'+str(cookie_dict['subdomain'])+'\t'+str(cookie_dict['httponly'])+'\t'+str(cookie_dict['secure'])+'\t'+str(cookie_dict['expires'])
