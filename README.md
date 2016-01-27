ipinformation
========

ipinformation is a python package focused on combining information about an IP in JSON format.

Features
========
* whois (via https://github.com/secynic/ipwhois)
* AS Name and Number (via https://www.team-cymru.com)
* reverse/ptr address
* geo location (via https://www.maxmind.com)
* version type
* conversion to bits (if you ever want to subnet search)
* type (public,private,netmask,etc).

Please Note
===========
* Converts all timestamps to UTC.
* Currently only supports IPv4.
* Requires internet access for: querying IP whois servers; performing dns lookup against cymru; dns lookups for reverse ptr; downloading maxmind databases

Requirements
============
* Python 2.7
* pip install -U requests[security] #Install requests security
* pip install -U pygeoip; #Install legacy maxmind geoip
* pip install -U netaddr; #Install network address tool
* pip install -U ipwhois; #Install ip whois tool
* pip install -U dateutils; #Time/Date Utility

Install
=======
pip install -e git+https://github.com/neu5ron/ipinformation@master#egg=ipinformation

Usage Examples
==============
Valid IP
---------
	is_ip( ) = Return true if valid IP address return false if invalid IP address
	>>> from ipinformation import IPInformation
	>>> print IPInformation(ip_address='8.8.8.8').is_ip()
		True
	>>> print IPInformation(ip_address='NotAnIP').is_ip()
		False

Is Public IP
-------------
	is_public( ) = Return true if an IP address is publicly accessible/routable
	>>> from ipinformation import IPInformation
	>>> print IPInformation(ip_address='8.8.8.8').is_public()
		True
	>>> print IPInformation(ip_address='127.0.0.1').is_public()
		False

General Information
-------------------
	general_info( ) = Return IP in bits, ip_type (ie: private, multicast, loopback,etc..), time updated/returned and version for an IP Address
	>>> from ipinformation import IPInformation
	>>> from pprint import pprint
	>>> pprint( IPInformation(ip_address='8.8.8.8').general_info() )
	{'general': {'bits': '00001000000010000000100000001000',
				 'type': 'public',
				 'updated': datetime.datetime(2016, 1, 16, 18, 7, 4, 288512),
				 'version': '4'}}
	>>> IPInformation(ip_address='127.0.0.1').general_info()
	{'general': {'bits': '01111111000000000000000000000001',
				 'type': 'loopback',
				 'updated': datetime.datetime(2016, 1, 16, 18, 10, 6, 729149),
				 'version': '4'}}
Geo Information
---------------
	geo_info( ) = Return Geo location information (City,State,Country,etc...) for an IP Address
	>>> from ipinformation import IPInformation
	>>> from pprint import pprint
	>>> pprint( IPInformation(ip_address='8.8.8.8').geo_info() )
	{'geo': {'area_code': 650,
			 'city': u'Mountain View',
			 'continent': 'NA',
			 'coordinates': [37.3845, -122.0881],
			 'country_code': 'US',
			 'country_code3': 'USA',
			 'country_name': 'United States',
			 'dma_code': 807,
			 'latitude': 37.3845,
			 'longitude': -122.0881,
			 'metro_code': 'San Francisco, CA',
			 'postal_code': u'94040',
			 'region_code': u'CA',
			 'time_zone': 'America/Los_Angeles'}}
	>>> pprint( IPInformation(ip_address='127.0.0.1').geo_info() )
	{'geo': {'general': {'area_code': None,
						 'asname': None,
						 'asnum': None,
						 'city': None,
						 'continent': None,
						 'coordinates': [None, None],
						 'country_code': None,
						 'country_code3': None,
						 'country_name': None,
						 'dma_code': None,
						 'latitude': None,
						 'longitude': None,
						 'metro_code': None,
						 'postal_code': None,
						 'region_code': None,
						 'time_zone': None}}}
Whois Information
-----------------
	whois_info( ) = Return WhoisInfo of the IP (AS Name/Number/CIDR/etc...,Subnet, CIDR, City,State,Country,Address, etc...) for an IP Address
	>>> from ipinformation import IPInformation
	>>> from pprint import pprint
	>>> pprint( IPInformation(ip_address='8.8.8.8').whois_info() )
	{'whois': {'as': {'cidr': '8.8.8.0/24',
					  'country_code': 'US',
					  'creation_date': None,
					  'name': u'Google Inc.',
					  'number': [15169],
					  'registry': 'arin'},
			   'error': 'no',
			   'raw': '\n#\n# ARIN WHOIS data and services are subject to the Terms of Use\n# available at: https://www.arin.net/whois_tou.html\n#\n# If you see inaccuracies in the results, please report at\n# http://www.arin.net/public/whoisinaccuracy/index.xhtml\n#\n\n\n#\n# The following results may also be obtained via:\n# http://whois.arin.net/rest/nets;q=8.8.4.4?showDetails=true&showARIN=false&showNonArinTopLevelNet=false&ext=netref2\n#\n\n\n# start\n\nNetRange:       8.0.0.0 - 8.255.255.255\nCIDR:           8.0.0.0/8\nNetName:        LVLT-ORG-8-8\nNetHandle:      NET-8-0-0-0-1\nParent:          ()\nNetType:        Direct Allocation\nOriginAS:       \nOrganization:   Level 3 Communications, Inc. (LVLT)\nRegDate:        1992-12-01\nUpdated:        2012-02-24\nRef:            http://whois.arin.net/rest/net/NET-8-0-0-0-1\n\n\n\nOrgName:        Level 3 Communications, Inc.\nOrgId:          LVLT\nAddress:        1025 Eldorado Blvd.\nCity:           Broomfield\nStateProv:      CO\nPostalCode:     80021\nCountry:        US\nRegDate:        1998-05-22\nUpdated:        2012-01-30\nComment:        ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE\nRef:            http://whois.arin.net/rest/org/LVLT\n\n\nOrgTechHandle: IPADD5-ARIN\nOrgTechName:   ipaddressing\nOrgTechPhone:  +1-877-453-8353 \nOrgTechEmail:  ipaddressing@level3.com\nOrgTechRef:    http://whois.arin.net/rest/poc/IPADD5-ARIN\n\nOrgNOCHandle: NOCSU27-ARIN\nOrgNOCName:   NOC Support\nOrgNOCPhone:  +1-877-453-8353 \nOrgNOCEmail:  noc.coreip@level3.com\nOrgNOCRef:    http://whois.arin.net/rest/poc/NOCSU27-ARIN\n\nOrgAbuseHandle: APL8-ARIN\nOrgAbuseName:   Abuse POC LVLT\nOrgAbusePhone:  +1-877-453-8353 \nOrgAbuseEmail:  abuse@level3.com\nOrgAbuseRef:    http://whois.arin.net/rest/poc/APL8-ARIN\n\n# end\n\n\n# start\n\nNetRange:       8.8.4.0 - 8.8.4.255\nCIDR:           8.8.4.0/24\nNetName:        LVLT-GOGL-8-8-4\nNetHandle:      NET-8-8-4-0-1\nParent:         LVLT-ORG-8-8 (NET-8-0-0-0-1)\nNetType:        Reallocated\nOriginAS:       \nOrganization:   Google Inc. (GOGL)\nRegDate:        2014-03-14\nUpdated:        2014-03-14\nRef:            http://whois.arin.net/rest/net/NET-8-8-4-0-1\n\n\n\nOrgName:        Google Inc.\nOrgId:          GOGL\nAddress:        1600 Amphitheatre Parkway\nCity:           Mountain View\nStateProv:      CA\nPostalCode:     94043\nCountry:        US\nRegDate:        2000-03-30\nUpdated:        2015-11-06\nRef:            http://whois.arin.net/rest/org/GOGL\n\n\nOrgAbuseHandle: ABUSE5250-ARIN\nOrgAbuseName:   Abuse\nOrgAbusePhone:  +1-650-253-0000 \nOrgAbuseEmail:  network-abuse@google.com\nOrgAbuseRef:    http://whois.arin.net/rest/poc/ABUSE5250-ARIN\n\nOrgTechHandle: ZG39-ARIN\nOrgTechName:   Google Inc\nOrgTechPhone:  +1-650-253-0000 \nOrgTechEmail:  arin-contact@google.com\nOrgTechRef:    http://whois.arin.net/rest/poc/ZG39-ARIN\n\n# end\n\n\n\n#\n# ARIN WHOIS data and services are subject to the Terms of Use\n# available at: https://www.arin.net/whois_tou.html\n#\n# If you see inaccuracies in the results, please report at\n# http://www.arin.net/public/whoisinaccuracy/index.xhtml\n#\n\n',
			   'registration': [{'abuse_emails': None,
								 'address': '1025 Eldorado Blvd.',
								 'cidr': '8.0.0.0/8',
								 'city': 'Broomfield',
								 'country_code': 'US',
								 'creation_date': datetime.datetime(1992, 12, 1, 0, 0, tzinfo=<UTC>),
								 'description': 'Level 3 Communications, Inc.',
								 'handle': 'NET-8-0-0-0-1',
								 'misc_emails': None,
								 'name': 'LVLT-ORG-8-8',
								 'postal_code': '80021',
								 'range': '8.0.0.0-8.255.255.255',
								 'state': 'CO',
								 'tech_emails': None,
								 'updated': datetime.datetime(2012, 2, 24, 0, 0, tzinfo=<UTC>)},
								{'abuse_emails': None,
								 'address': '1600 Amphitheatre Parkway',
								 'cidr': '8.8.8.0/24',
								 'city': 'Mountain View',
								 'country_code': 'US',
								 'creation_date': datetime.datetime(2014, 3, 14, 0, 0, tzinfo=<UTC>),
								 'description': 'Google Inc.',
								 'handle': 'NET-8-8-8-0-1',
								 'misc_emails': None,
								 'name': 'LVLT-GOGL-8-8-8',
								 'postal_code': '94043',
								 'range': '8.8.8.0-8.8.8.255',
								 'state': 'CA',
								 'tech_emails': None,
								 'updated': datetime.datetime(2014, 3, 14, 0, 0, tzinfo=<UTC>)}],
			   'reverse_ip': 'google-public-dns-a.google.com'}}
	>>> pprint( IPInformation(ip_address='127.0.0.1').whois_info() )
	No Whois information for '127.0.0.1' because it is not a public ip

	{'whois': {'as': {'cidr': None,
					  'country_code': None,
					  'creation_date': None,
					  'name': None,
					  'number': None,
					  'registry': None},
			   'raw': None,
			   'registration': [{'abuse_emails': None,
								 'address': None,
								 'cidr': None,
								 'city': None,
								 'country_code': None,
								 'creation_date': None,
								 'description': None,
								 'handle': None,
								 'misc_emails': None,
								 'postal_code': None,
								 'state': None,
								 'tech_emails': None,
								 'updated': None}],
			   'reverse_ip': None}}
	"""
All Information / Put everything together
-----------------------------------------
	all( ) = Return general, geo, and whois information for an IP Address
	>>> from ipinformation import IPInformation
	>>> from pprint import pprint
	>>> pprint( IPInformation(ip_address='8.8.8.8').all() )
	{'general': {'bits': '00001000000010000000100000001000',
				 'type': 'public',
				 'updated': datetime.datetime(2016, 1, 16, 18, 26, 23, 487181),
				 'version': '4'},
	 'geo': {'area_code': 650,
			 'city': u'Mountain View',
			 'continent': 'NA',
			 'coordinates': [37.3845, -122.0881],
			 'country_code': 'US',
			 'country_code3': 'USA',
			 'country_name': 'United States',
			 'dma_code': 807,
			 'latitude': 37.3845,
			 'longitude': -122.0881,
			 'metro_code': 'San Francisco, CA',
			 'postal_code': u'94040',
			 'region_code': u'CA',
			 'time_zone': 'America/Los_Angeles'},
	 'whois': {'as': {'cidr': '8.8.8.0/24',
					  'country_code': 'US',
					  'creation_date': None,
					  'name': u'Google Inc.',
					  'number': [15169],
					  'registry': 'arin'},
			   'error': 'no',
			   'raw': '\n#\n# ARIN WHOIS data and services are subject to the Terms of Use\n# available at: https://www.arin.net/whois_tou.html\n#\n# If you see inaccuracies in the results, please report at\n# http://www.arin.net/public/whoisinaccuracy/index.xhtml\n#\n\n\n#\n# The following results may also be obtained via:\n# http://whois.arin.net/rest/nets;q=8.8.4.4?showDetails=true&showARIN=false&showNonArinTopLevelNet=false&ext=netref2\n#\n\n\n# start\n\nNetRange:       8.0.0.0 - 8.255.255.255\nCIDR:           8.0.0.0/8\nNetName:        LVLT-ORG-8-8\nNetHandle:      NET-8-0-0-0-1\nParent:          ()\nNetType:        Direct Allocation\nOriginAS:       \nOrganization:   Level 3 Communications, Inc. (LVLT)\nRegDate:        1992-12-01\nUpdated:        2012-02-24\nRef:            http://whois.arin.net/rest/net/NET-8-0-0-0-1\n\n\n\nOrgName:        Level 3 Communications, Inc.\nOrgId:          LVLT\nAddress:        1025 Eldorado Blvd.\nCity:           Broomfield\nStateProv:      CO\nPostalCode:     80021\nCountry:        US\nRegDate:        1998-05-22\nUpdated:        2012-01-30\nComment:        ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE\nRef:            http://whois.arin.net/rest/org/LVLT\n\n\nOrgTechHandle: IPADD5-ARIN\nOrgTechName:   ipaddressing\nOrgTechPhone:  +1-877-453-8353 \nOrgTechEmail:  ipaddressing@level3.com\nOrgTechRef:    http://whois.arin.net/rest/poc/IPADD5-ARIN\n\nOrgNOCHandle: NOCSU27-ARIN\nOrgNOCName:   NOC Support\nOrgNOCPhone:  +1-877-453-8353 \nOrgNOCEmail:  noc.coreip@level3.com\nOrgNOCRef:    http://whois.arin.net/rest/poc/NOCSU27-ARIN\n\nOrgAbuseHandle: APL8-ARIN\nOrgAbuseName:   Abuse POC LVLT\nOrgAbusePhone:  +1-877-453-8353 \nOrgAbuseEmail:  abuse@level3.com\nOrgAbuseRef:    http://whois.arin.net/rest/poc/APL8-ARIN\n\n# end\n\n\n# start\n\nNetRange:       8.8.4.0 - 8.8.4.255\nCIDR:           8.8.4.0/24\nNetName:        LVLT-GOGL-8-8-4\nNetHandle:      NET-8-8-4-0-1\nParent:         LVLT-ORG-8-8 (NET-8-0-0-0-1)\nNetType:        Reallocated\nOriginAS:       \nOrganization:   Google Inc. (GOGL)\nRegDate:        2014-03-14\nUpdated:        2014-03-14\nRef:            http://whois.arin.net/rest/net/NET-8-8-4-0-1\n\n\n\nOrgName:        Google Inc.\nOrgId:          GOGL\nAddress:        1600 Amphitheatre Parkway\nCity:           Mountain View\nStateProv:      CA\nPostalCode:     94043\nCountry:        US\nRegDate:        2000-03-30\nUpdated:        2015-11-06\nRef:            http://whois.arin.net/rest/org/GOGL\n\n\nOrgAbuseHandle: ABUSE5250-ARIN\nOrgAbuseName:   Abuse\nOrgAbusePhone:  +1-650-253-0000 \nOrgAbuseEmail:  network-abuse@google.com\nOrgAbuseRef:    http://whois.arin.net/rest/poc/ABUSE5250-ARIN\n\nOrgTechHandle: ZG39-ARIN\nOrgTechName:   Google Inc\nOrgTechPhone:  +1-650-253-0000 \nOrgTechEmail:  arin-contact@google.com\nOrgTechRef:    http://whois.arin.net/rest/poc/ZG39-ARIN\n\n# end\n\n\n\n#\n# ARIN WHOIS data and services are subject to the Terms of Use\n# available at: https://www.arin.net/whois_tou.html\n#\n# If you see inaccuracies in the results, please report at\n# http://www.arin.net/public/whoisinaccuracy/index.xhtml\n#\n\n',
			   'registration': [{'abuse_emails': None,
								 'address': '1025 Eldorado Blvd.',
								 'cidr': '8.0.0.0/8',
								 'city': 'Broomfield',
								 'country_code': 'US',
								 'creation_date': datetime.datetime(1992, 12, 1, 0, 0, tzinfo=<UTC>),
								 'description': 'Level 3 Communications, Inc.',
								 'handle': 'NET-8-0-0-0-1',
								 'misc_emails': None,
								 'name': 'LVLT-ORG-8-8',
								 'postal_code': '80021',
								 'range': '8.0.0.0-8.255.255.255',
								 'state': 'CO',
								 'tech_emails': None,
								 'updated': datetime.datetime(2012, 2, 24, 0, 0, tzinfo=<UTC>)},
								{'abuse_emails': None,
								 'address': '1600 Amphitheatre Parkway',
								 'cidr': '8.8.8.0/24',
								 'city': 'Mountain View',
								 'country_code': 'US',
								 'creation_date': datetime.datetime(2014, 3, 14, 0, 0, tzinfo=<UTC>),
								 'description': 'Google Inc.',
								 'handle': 'NET-8-8-8-0-1',
								 'misc_emails': None,
								 'name': 'LVLT-GOGL-8-8-8',
								 'postal_code': '94043',
								 'range': '8.8.8.0-8.8.8.255',
								 'state': 'CA',
								 'tech_emails': None,
								 'updated': datetime.datetime(2014, 3, 14, 0, 0, tzinfo=<UTC>)}],
			   'reverse_ip': 'google-public-dns-a.google.com'}}
	>>> pprint( IPInformation(ip_address='127.0.0.1').all() )
	No Whois information for '127.0.0.1' because it is not a public ip

	{'general': {'bits': '01111111000000000000000000000001',
				 'type': 'loopback',
				 'updated': datetime.datetime(2016, 1, 16, 18, 27, 41, 528938),
				 'version': '4'},
	 'geo': {'general': {'area_code': None,
						 'asname': None,
						 'asnum': None,
						 'city': None,
						 'continent': None,
						 'coordinates': [None, None],
						 'country_code': None,
						 'country_code3': None,
						 'country_name': None,
						 'dma_code': None,
						 'latitude': None,
						 'longitude': None,
						 'metro_code': None,
						 'postal_code': None,
						 'region_code': None,
						 'time_zone': None}},
	 'whois': {'as': {'cidr': None,
					  'country_code': None,
					  'creation_date': None,
					  'name': None,
					  'number': None,
					  'registry': None},
			   'raw': None,
			   'registration': [{'abuse_emails': None,
								 'address': None,
								 'cidr': None,
								 'city': None,
								 'country_code': None,
								 'creation_date': None,
								 'description': None,
								 'handle': None,
								 'misc_emails': None,
								 'postal_code': None,
								 'state': None,
								 'tech_emails': None,
								 'updated': None}],
			   'reverse_ip': None}}