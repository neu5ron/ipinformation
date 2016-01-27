#!/usr/bin/env python2.7
from . import GeoDBConnection
from . import time_info
import netaddr
import re
import ipwhois
from datetime import datetime

# Regex for ASN Number and Name
asn_info_regex = re.compile(r'(AS)(\d+) (.*)')

######## Call and Use Databases
geoipv4_country = GeoDBConnection.GeoIPDB().geoipv4_country()
geoipv6_country = GeoDBConnection.GeoIPDB().geoipv6_country()
geoipv4_city = GeoDBConnection.GeoIPDB().geoipv4_city()
geoipv6_city = GeoDBConnection.GeoIPDB().geoipv6_city()
geoipv4_as = GeoDBConnection.GeoIPDB().geoipv4_as()
geoipv6_as = GeoDBConnection.GeoIPDB().geoipv6_as()


class IPInformation:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        try:
            self.ip_address = self.ip_address.encode('ascii')
        except ( UnicodeEncodeError, ValueError) as error:
            print error
            print '"%s" is not valid. The IP Address should be input as an ascii string.\n'%self.ip_address.encode('utf8','replace')
            raise ValueError

    def is_ip(self):
        """is_ip( ) = Return true if valid IP address return false if invalid IP address
        >>> from ipinformation import IPInformation
        >>> print IPInformation(ip_address='8.8.8.8').is_ip()
            True
        >>> print IPInformation(ip_address='NotAnIP').is_ip()
            False
        """

        if netaddr.valid_ipv4( self.ip_address ): #IPv4 Address
            return True
        elif netaddr.valid_ipv6( self.ip_address ):
            return True
        else:
            return False

    def is_public(self):
        """is_public( ) = Return true if an IP address is publicly accessible/routable
        >>> from ipinformation import IPInformation
        >>> print IPInformation(ip_address='8.8.8.8').is_public()
            True
        >>> print IPInformation(ip_address='127.0.0.1').is_public()
            False
        """

        ip_addr = netaddr.IPAddress(self.ip_address)
        if ip_addr.is_private():
            return False
        elif ip_addr.is_multicast():
            return False
        elif ip_addr.is_loopback():
            return False
        elif ip_addr.is_netmask():
            return False
        elif ip_addr.is_reserved():
            return False
        elif ip_addr.is_link_local():
            return False
        elif ip_addr.is_unicast():
            return True
        else: #Unknown Type
            return False
            print '"%s" is an unknown IP Address.' %self.ip_address

    def general_info(self):
        """general_info( ) = Return IP in bits, ip_type (ie: private, multicast, loopback,etc..), time updated/returned and version for an IP Address
        >>> from ipinformation import IPInformation
        >>> from pprint import pprint
        >>> pprint( IPInformation(ip_address='8.8.8.8').general_info() )
        {'general': {'bits': '00001000000010000000100000001000',
                     'type': 'public',
                     'updated': datetime.datetime(2016, 1, 16, 18, 7, 4, 288512),
                     'version': '4'}}
        >>> pprint( IPInformation(ip_address='127.0.0.1').general_info() )
        {'general': {'bits': '01111111000000000000000000000001',
                     'type': 'loopback',
                     'updated': datetime.datetime(2016, 1, 16, 18, 10, 6, 729149),
                     'version': '4'}}
        """
        if not self.is_ip():
            print '"%s" is not a valid IP Address.' %self.ip_address
            return False

        if netaddr.valid_ipv4( self.ip_address ): #IPv4 Address
            data = { 'general': {} }
            ip_version = '4'
            data['general'].update({'version':ip_version})
            ip_bits = netaddr.IPAddress( self.ip_address ).bits().replace( '.', '' ) #Set the IP bits for searching by subnet
            data['general'].update({'bits':ip_bits})
            ip_addr = netaddr.IPAddress(self.ip_address)

            if ip_addr.is_private():
                ip_type = 'private'
            elif ip_addr.is_multicast():
                ip_type = 'multicast'
            elif ip_addr.is_loopback():
                ip_type = 'loopback'
            elif ip_addr.is_netmask():
                ip_type = 'netmask'
                print '"%s" is a netmask.' %self.ip_address
            elif ip_addr.is_reserved():
                ip_type = 'reserved'
            elif ip_addr.is_link_local():
                ip_type = 'link_local'
            elif ip_addr.is_unicast():
                ip_type = 'public'
            else: #Unknown Type
                ip_type = 'unknown'
                print '"%s" is an unknown IP Address.' %self.ip_address
        elif netaddr.valid_ipv6( self.ip_address ): #IPv6 Address#TODO:Finish IPv6
            ip_version = '6'
            print 'Is IPv6'
            return False

        data['general'].update( { 'type': ip_type } )
        data['general'].update( { 'updated': datetime.utcnow() } )
        return data

    def geo_info(self):
        """geo_info( ) = Return Geo location information (City,State,Country,etc...) for an IP Address
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
        """

        if not self.is_ip():
            print '"%s" is not a valid IP Address.' %self.ip_address
            return False

        data = { 'geo': {} }
        if self.is_public():
            city_information = geoipv4_city.record_by_addr(self.ip_address)
            data['geo'].update(city_information)
            # longitude = float(city_information.get('longitude'))#TODO:TEST
            longitude = city_information.get('longitude')
            # latitude = float(city_information.get('latitude'))#TODO:TEST
            latitude = city_information.get('latitude')
            coordinates = [ latitude, longitude  ]
            data['geo'].update( { 'coordinates': coordinates } )
        # Assign all null values if not public IP
        else:
            geoip_info = { 'general': { "city": None, "region_code": None, "asnum": None, "area_code": None, "time_zone": None, "dma_code": None, "metro_code": None, "country_code3": None, "country_name": None, "postal_code": None, "longitude": None, "country_code": None, "asname": None, "latitude": None, "coordinates": [ None, None ], "continent": None } }
            data['geo'].update(geoip_info)

        #TODO:Finish IPv6

        return data

    def whois_info(self):
        """whois_info( ) = Return WhoisInfo of the IP (AS Name/Number/CIDR/etc...,Subnet, CIDR, City,State,Country,Address, etc...) for an IP Address
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
        def null_whois_info():
            data = {'whois': { 'as': {'cidr': None,
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
                                             'updated': None} ],
                           'reverse_ip': None } }
            return data

        if self.is_public():#TODO:Other stats with \n... for k,v in dict.items(): value=v.replace('\n','') dict[k]=value
            #TODO:What about noc, tech, and abuse information
            data = { 'whois': { 'as': {} } }
            try:
                d = ipwhois.IPWhois( self.ip_address ).lookup(inc_raw=True)
            except ipwhois.HTTPLookupError:
                print "No Whois information for '%s' because HTTPLookupError" %(self.ip_address)
                data = null_whois_info()
                data['whois'].update( { 'error': 'yes' } )
                return data
            except ipwhois.WhoisLookupError:
                print "No Whois information for '%s' because WhoisLookupError" %(self.ip_address)
                data = null_whois_info()
                data['whois'].update( { 'error': 'yes' } )
                return data
            except (ipwhois.ASNLookupError, ipwhois.ASNRegistryError):
                print "No Whois information for '%s' because ASNLookupError" %(self.ip_address)
                data = null_whois_info()
                data['whois'].update( { 'error': 'yes' } )
                return data

            # AS Number
            try:
                asn = [ int(a) for a in d.get('asn').split(' ') ]
                data['whois']['as'].update( { 'number':  asn } )
            except (ValueError, TypeError):
                data['whois']['as'].update( { 'number':  None } )
            # AS Country Code
            data['whois']['as'].update( { 'country_code': d.get('asn_country_code') } )
            # AS Registry
            data['whois']['as'].update( { 'registry': d.get('asn_registry') } )
            # AS CIDR
            as_cidr = d.get('asn_cidr')
            if as_cidr != 'NA':
                data['whois']['as'].update( { 'cidr': as_cidr } )
            else:
                 data['whois']['as'].update( { 'cidr': None } )
            #AS Creation Date
            data['whois']['as'].update( { 'creation_date': time_info.convert_time( d.get('asn_date') ).convert_to_utc() } )
            # AS Name
            asn_response = geoipv4_as.asn_by_addr( self.ip_address )
            if asn_response:
                asn_info = re.search( asn_info_regex, asn_response.decode('utf-8', "replace") )
                try:
                    # asnum = int ( asn_info.group(2) ) #Do not need, because grabbed via Cyrmu lookup
                    name = asn_info.group(3)
                    data['whois']['as'].update( { 'name': name } )
                except (ValueError, TypeError):
                    print 'Error grabbing AS Name for %s', self.ip_address
                    data['whois']['as'].update( {'name': None} )
            else:
                print 'No AS Name result for %s' %self.ip_address
                data['whois']['as'].update( {'name': None} )

            # Registration Information by Subnet
            for registration in d.get('nets'):
                reg = dict()
                # Country Code
                reg.update( { 'country_code': registration.get('country') } )
                # City
                reg.update( { 'city': registration.get('city') } )
                # State
                reg.update( { 'state': registration.get('state') } )
                # CIDR
                cidr = registration.get('cidr')
                reg.update( { 'cidr': cidr } )
                #Range
                try:
                    range = '%s-%s'%(netaddr.IPNetwork(cidr).network, netaddr.IPNetwork(cidr).broadcast)
                    reg.update( { 'range': range } )
                except ValueError:
                    reg.update( { 'range': None } )
                # Description
                reg.update( { 'description': registration.get( 'description' ) } )
                # Name
                reg.update( { 'name': registration.get('name') } )
                # Handle
                reg.update( { 'handle': registration.get('handle') } )
                # Updated
                reg.update( { 'updated': time_info.convert_time( registration.get('updated') ).convert_to_utc() } )
                # Created
                reg.update( { 'creation_date': time_info.convert_time( registration.get('created') ).convert_to_utc() } )
                # Postal Code
                reg.update( { 'postal_code': registration.get('postal_code') } )
                # Address
                reg.update( { 'address': registration.get('address') } )
                # Abuse Emails
                abuse_emails = registration.get('abuse_emails')
                if abuse_emails:
                    abuse_emails = abuse_emails.split('\n')
                reg.update( { 'abuse_emails': abuse_emails } )
                # Miscellaneous Emails
                misc_emails = registration.get('misc_emails')
                if misc_emails:
                    misc_emails = misc_emails.split('\n')
                reg.update( { 'misc_emails': misc_emails } )
                # Tech Emails
                tech_emails = registration.get('tech_emails')
                if tech_emails:
                    tech_emails = tech_emails.split('\n')
                reg.update( { 'tech_emails': tech_emails } )
                #TODO:Sub referrals

                # Update reg information
                data['whois'].setdefault('registration', []).append(reg)

            # Add Raw WhoIs
            data['whois'].update( { 'raw': d.get('raw') } )

            # Reverse IP
            try:
                reverse_ip = ipwhois.Net(self.ip_address).get_host()[0]
                data['whois'].update( { 'reverse_ip': reverse_ip } )

            except (ipwhois.HostLookupError, IndexError):
               data['whois'].update( { 'reverse_ip': None } )

            #Assign error status
            data['whois'].update( { 'error': 'no' } )

        # Assign all null values if not public IP
        else:
            print 'No Whois information for "%s" because it is not a public IP Address.' %self.ip_address
            data = null_whois_info()
        return data

    def all(self):
        """all( ) = Return general, geo, and whois information for an IP Address
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
                   'raw': '\n#\n# ARIN WHOIS data and services are subject to the Terms of Use\n# available at: https://www.arin.net/whois_tou.html\n#\n# If you see inaccuracies in the results, please report at\n# http://www.arin.net/public/whoisinaccuracy/index.xhtml\n#\n\n\n#\n# The following results may also be obtained via:\n# http://whois.arin.net/rest/nets;q=8.8.4.4?showDetails=true&showARIN=false&showNonArinTopLevelNet=false&ext=netref2\n#\n\n\n# start\n\nNetRange:       8.0.0.0 - 8.255.255.255\nCIDR:           8.0.0.0/8\nNetName:        LVLT-ORG-8-8\nNetHandle:      NET-8-0-0-0-1\nParent:          ()\nNetType:        Direct Allocation\nOriginAS:       \nOrganization:   Level 3 Communications, Inc. (LVLT)\nRegDate:        1992-12-01\nUpdated:        2012-02-24\nRef:            http://whois.arin.net/rest/net/NET-8-0-0-0-1\n\n\n\nOrgName:        Level 3 Communications, Inc.\nOrgId:          LVLT\nAddress:        1025 Eldorado Blvd.\nCity:           Broomfield\nStateProv:      CO\nPostalCode:     80021\nCountry:        US\nRegDate:        1998-05-22\nUpdated:        2012-01-30\nComment:        ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE\nRef:            http://whois.arin.net/rest/org/LVLT\n\n\nOrgTechHandle: IPADD5-ARIN\nOrgTechName:   ipaddressing\nOrgTechPhone:  +1-877-453-8353 \nOrgTechEmail:  ipaddressing@level3.com\nOrgTechRef:    http://whois.arin.net/rest/poc/IPADD5-ARIN\n\nOrgNOCHandle: NOCSU27-ARIN\nOrgNOCName:   NOC Support\nOrgNOCPhone:  +1-877-453-8353 \nOrgNOCEmail:  noc.coreip@level3.com\nOrgNOCRef:    http://whois.arin.net/rest/poc/NOCSU27-ARIN\n\nOrgAbuseHandle: APL8-ARIN\nOrgAbuseName:   Abuse POC LVLT\nOrgAbusePhone:  +1-877-453-8353 \nOrgAbuseEmail:  abuse@level3.com\nOrgAbuseRef:    http://whois.arin.net/rest/poc/APL8-ARIN\n\n# end\n\n\n# start\n\nNetRange:       8.8.4.0 - 8.8.4.255\nCIDR:           8.8.4.0/24\nNetName:        LVLT-GOGL-8-8-4\nNetHandle:      NET-8-8-4-0-1\nParent:         LVLT-ORG-8-8 (NET-8-0-0-0-1)\nNetType:        Reallocated\nOriginAS:       \nOrganization:   Google Inc. (GOGL)\nRegDate:        2014-03-14\nUpdated:        2014-03-14\nRef:            http://whois.arin.net/rest/net/NET-8-8-4-0-1\n\n\n\nOrgName:        Google Inc.\nOrgId:          GOGL\nAddress:        1600 Amphitheatre Parkway\nCity:           Mountain View\nStateProv:      CA\nPostalCode:     94043\nCountry:        US\nRegDate:        2000-03-30\nUpdated:        2015-11-06\nRef:            http://whois.arin.net/rest/org/GOGL\n\n\nOrgAbuseHandle: ABUSE5250-ARIN\nOrgAbuseName:   Abuse\nOrgAbusePhone:  +1-650-253-0000 \nOrgAbuseEmail:  network-abuse@google.com\nOrgAbuseRef:    http://whois.arin.net/rest/poc/ABUSE5250-ARIN\n\nOrgTechHandle: ZG39-ARIN\nOrgTechName:   Google Inc\nOrgTechPhone:  +1-650-253-0000 \nOrgTechEmail:  arin-contact@google.com\nOrgTechRef:    http://whois.arin.net/rest/poc/ZG39-ARIN\n\n# end\n\n\n\n#\n# ARIN WHOIS data and services are subject to the Terms of Use\n# available at: https://www.arin.net/whois_tou.html\n#\n# If you see inaccuracies in the results, please report at\n# http://www.arin.net/public/whoisinaccuracy/index.xhtml\n#\n\n',
                   'error': 'no',
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
        """
        if not self.is_ip():
            print '"%s" is not a valid IP Address.' %self.ip_address
            return None
        data = dict()
        data.update(self.general_info())
        data.update(self.geo_info())
        data.update(self.whois_info())
        return data