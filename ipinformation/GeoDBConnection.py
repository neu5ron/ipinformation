#!/usr/bin/env python2.7
from datetime import datetime
import os, sys
import requests
import gzip
import io
import pygeoip
from dateutil import parser
import logging
from logging import handlers

######################################## # Edit If Need Be
base_directory = os.path.expanduser("~") #Base directory where 'GeoIP' directory will be created (currently home directory)
hours_to_pull_new_geoip_db = 336 #Use this variable in hours to determine how often to download and update the local databases. Default is 14 days
geoip_directory = os.path.join( base_directory, 'GeoIP' )
########################################

# Set logging
log_file = os.path.join ( os.path.realpath( os.path.join( __file__, '..' ) ), 'ipinformation.log' )
logging_file = logging.getLogger(__name__)
logging_file.setLevel(logging.DEBUG)
logging_file_handler = handlers.RotatingFileHandler( log_file, maxBytes=5, backupCount=0  )
info_format = logging.Formatter('%(asctime)s - %(filename)s - %(levelname)s - Function: %(funcName)s - LineNumber: %(lineno)s - %(message)s')
logging_file_handler.setFormatter(info_format)
logging_file.addHandler(logging_file_handler)


if not os.path.exists(geoip_directory):
    # print '%s does not exist. Creating it now.\n'%geoip_directory
    logging_file.info( '{0} does not exist. Creating it now.'.format(geoip_directory) )

    try:
        os.mkdir(geoip_directory)

    except OSError as error:
        # print 'Failed to create %s'%geoip_directory
        # print '%s'%error
        # print 'Exiting Script!'
        logging_file.error( 'Failed to create {0}. Due to:\n{1}'.format( geoip_directory, error ) )
        sys.exit(1)


class GeoIPDB():
    #Doucmentation: https://pythonhosted.org/pygeoip/
    def __init__(self):
        pass

    def geoipv4_country(self):
        return self.download_and_update_geoip( 'GeoIPv4_Country.dat', 'geoipv4_country', 'https://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz' )

    def geoipv6_country(self):
        return self.download_and_update_geoip( 'GeoIPv6_Country.dat', 'geoipv6_country', 'https://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz' )

    def geoipv4_city(self):
        return self.download_and_update_geoip( 'GeoIPv4_City.dat', 'geoipv4_city', 'https://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz' )

    def geoipv6_city(self):
       return self.download_and_update_geoip( 'GeoIPv6_City.dat', 'geoipv6_city', 'https://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz' )

    def geoipv4_as(self):
        return self.download_and_update_geoip( 'GeoIP_ASv4.dat', 'geoipv4_as', 'https://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz' )

    def geoipv6_as(self):
        return self.download_and_update_geoip( 'GeoIP_ASv6.dat', 'geoipv6_as', 'https://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz' )

    def download_and_update_geoip( self, filename, variable_name, download_url ):
        """
        Update Or Download GeoIP information from MaxMind and return it for use
        :param filename:
        :param variable_name:
        :param download_url:
        :return:
        """

        current_time = datetime.utcnow()
        need_to_download = False
        file_last_downloaded = os.path.join( geoip_directory, 'last_downloaded_%s.txt'%filename ) # File that will be used to determine the last time the DBs were downloaded

        if os.path.exists( os.path.join( geoip_directory, filename ) ):

            # Check to see if download timestamp exists and if it does see time diff since download
            if os.path.exists(file_last_downloaded):
                with open( file_last_downloaded, 'r' ) as f:
                    last_downloaded = f.read().strip()
                f.close()
                time_diff = (current_time - parser.parse(last_downloaded)).total_seconds()
                if time_diff > hours_to_pull_new_geoip_db*3600:
                    need_to_download = True

            else:
                # Set download timestamp if it was not downloaded using this script and this is the first time the script is ran
                with open( file_last_downloaded, 'w+' ) as f:
                    f.write(str(current_time))
                f.close()

        else:
            need_to_download = True

        if need_to_download:
            # print '%s file needs to be updated or does not exist!\nTrying to download it to %s/%s\n'%( variable_name, geoip_directory, filename )
            logging_file.info( '{0} file needs to be updated or does not exist! Trying to download it to "{1}/{2}"'.format( variable_name, geoip_directory, filename ) )
            try:
                requests.packages.urllib3.disable_warnings()
                response = requests.get( download_url,timeout=(10,2), verify=False )
                compressed_content = io.BytesIO(response.content)
                decompressed_content = gzip.GzipFile(fileobj=compressed_content)
                with open( os.path.join( geoip_directory, filename ), 'wb' ) as downloaded_file:
                    downloaded_file.write(decompressed_content.read())
                    with open( file_last_downloaded, 'w+' ) as f:
                        f.write(str(current_time))
                    f.close()
                downloaded_file.close()

            except IOError as error:
                # print 'Could not download and write GeoIP database due to %s.\n'%error
                logging_file.error( 'Could not download and write GeoIP database. Due to:\n{0}'.format( error ) )
                sys.exit(1)

            except requests.HTTPError as error:
                # print 'Could not download and write GeoIP database due to %s.\n'%error
                logging_file.error( 'Could not download and write GeoIP database. Due to:\n{0}'.format( error ) )
                sys.exit(1)

            except requests.Timeout as error:
                # print 'Could not download and write GeoIP database due to %s.\n'%error
                logging_file.error( 'Could not download and write GeoIP database. Due to:\n{0}'.format( error ) )
                sys.exit(1)

            except requests.TooManyRedirects as error:
                # print 'Could not download and write GeoIP database due to %s.\n'%error
                logging_file.error( 'Could not download and write GeoIP database. Due to:\n{0}'.format( error ) )
                sys.exit(1)

            except requests.ConnectionError as error:
                # print 'Could not download and write GeoIP database due to %s.\n'%error
                logging_file.error( 'Could not download and write GeoIP database. Due to:\n{0}'.format( error ) )
                sys.exit(1)

        return pygeoip.GeoIP( os.path.join( geoip_directory, filename ) )