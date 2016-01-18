from datetime import datetime
import os
import getpass
import requests
import gzip
import io
import pygeoip
import sys
from dateutil import parser

######################################## # Edit If Need Be
base_directory = os.path.join( '/home/', getpass.getuser() ) #Directory where folders will be created
hours_to_pull_new_geoip_db = 48 #Use this variable in hours to determine how often to download and update the local databases
########################################

geoip_directory = os.path.join( base_directory, 'GeoIP' )


if not os.path.exists(geoip_directory):
    print '%s does not exist. Creating it now.\n'%geoip_directory
    try:
        os.mkdir(geoip_directory)
    except OSError as error:
        print 'Failed to create %s'%geoip_directory
        print '%s'%error
        print 'Exiting Script!'
        sys.exit(1)

class GeoIPDB():
    #Doucmentation: https://pythonhosted.org/pygeoip/
    def __init__(self):
        pass

    def geoipv4_country(self):
        return self.download_and_update_geoip( 'GeoIPv4_Country.dat', 'geoipv4_country', 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz' )

    def geoipv6_country(self):
        return self.download_and_update_geoip( 'GeoIPv6_Country.dat', 'geoipv6_country', 'http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz' )

    def geoipv4_city(self):
        return self.download_and_update_geoip( 'GeoIPv4_City.dat', 'geoipv4_city', 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz' )

    def geoipv6_city(self):
       return self.download_and_update_geoip( 'GeoIPv6_City.dat', 'geoipv6_city', 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz' )

    def geoipv4_as(self):
        return self.download_and_update_geoip( 'GeoIP_ASv4.dat', 'geoipv4_as', 'http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz' )

    def geoipv6_as(self):
        return self.download_and_update_geoip( 'GeoIP_ASv6.dat', 'geoipv6_as', 'http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz' )

    def download_and_update_geoip( self, filename, variable_name, download_url ):
        """download_and_update_geoip(  ) = Update Or Download GeoIP information from MaxMind and return it for use"""

        current_time = datetime.utcnow()
        need_to_download = False
        file_last_downloaded = os.path.join( geoip_directory, 'last_downloaded_%s.txt' )%filename # File that will be used to determine the last time the DBs were downloaded

        if os.path.exists( '%s/%s' %( geoip_directory, filename) ):

            # Check to see if download timestamp exists and if it does see time diff since download
            if os.path.exists(file_last_downloaded):
                last_downloaded = open(file_last_downloaded, 'r').read().strip()
                time_diff = (current_time - parser.parse(last_downloaded)).total_seconds()
                if time_diff > hours_to_pull_new_geoip_db*3600:
                    need_to_download = True

            else:
                # Set download timestamp if it was not downloaded using this script and this is the first time the script is ran
                open(file_last_downloaded, 'w+').write(str(current_time))

        else:
            need_to_download = True

        if need_to_download:
            print '%s file needs to be updated or does not exist!\nTrying to download it to %s/%s\n'%( variable_name, geoip_directory, filename )
            try:
                response = requests.get( download_url,timeout=10)
                compressed_content = io.BytesIO(response.content)
                decompressed_content = gzip.GzipFile(fileobj=compressed_content)
                with open( '%s/%s' %(geoip_directory, filename), 'wb' ) as downloaded_file:
                    downloaded_file.write(decompressed_content.read())
                    open(file_last_downloaded, 'w+').write(str(current_time))

            except IOError as error:
                print 'Could not download and write GeoIP database due to %s.\n'%error
                sys.exit(1)

            except requests.HTTPError as error:
                print 'Could not download and write GeoIP database due to %s.\n'%error
                sys.exit(1)

            except requests.Timeout as error:
                print 'Could not download and write GeoIP database due to %s.\n'%error
                sys.exit(1)

            except requests.TooManyRedirects as error:
                print 'Could not download and write GeoIP database due to %s.\n'%error
                sys.exit(1)

            except requests.ConnectionError as error:
                print 'Could not download and write GeoIP database due to %s.\n'%error
                sys.exit(1)

        return pygeoip.GeoIP( '%s/%s' %( geoip_directory, filename ) )