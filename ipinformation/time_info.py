from dateutil import parser
from pytz import timezone, UTC, exceptions, FixedOffset
from datetime import datetime
import sys

# http://www.worldtimeserver.com/current_time_in_US-NY.aspx#
time_ordinals = [ 32, 43, 45, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58 ]

timezone_deltas = [ '+0000', '+0100', '+0200', '+0300', '+0400', '+0500', '+0600', '+0700', '+0800', '+0900', '+1000', '+1100', '+1200', '-0000', '-0100', '-0200', '-0300', '-0400', '-0500', '-0600', '-0700', '-0800', '-0900', '-1000', '-1100', '-1200' ]
#Should ever use offsets '+1300' or '+1400' ?

class convert_time(object):
    def __init__( self, time_to_convert ):
        self.time_to_convert = time_to_convert
        if not time_to_convert:
            self.time_to_convert = None

    def convert_to_utc( self, utc_offset='+0000', is_dst=True  ):
        """convert_to_utc( ) = Converts a timestamp to UTC/GMT.
        If the timestamp has the timezone offset than it will use that instead of the utc_offset variable passed.
        >>> from ipinformation import time_info
        >>> non_offset_aware_time = '2014/09/26 17:05:22'
        >>> tz = '-0500'
        >>> utc_time = time_info.convert_time(non_offset_aware_time).convert_to_utc(utc_offset=tz)
        Original Time: 2014/09/26 17:05:22
        UTC Time: 2014-09-26 22:05:22+00:00
        >>> from ipinformation import time_info
        >>> offset_aware_time = '2014/09/26 17:05:22-0500'
        >>> utc_time = time_info.convert_time(non_offset_aware_time).convert_to_utc()
        Original Time: 2014/09/26 17:05:22
        UTC Time: 2014-09-26 22:05:22+00:00
        """
        #TODO:Make OffSet Dynamic and With DayLightSavings or Not
        if self.time_to_convert is None:
            return None

        date_str =  parser.parse(self.time_to_convert)

        # Timezone not found convert to UTC with offset passed
        if date_str.tzinfo is None:
            # Return if already UTC
            if utc_offset == '+0000' or utc_offset == '-0000':
                return timezone('UTC').localize( date_str, is_dst )
            tz = self.convert_offset_to_timezone_aware(utc_offset)
            # Invert timezone to convert to appropriate UTC time
            tz_num = tz.replace('Etc/GMT','')
            if tz_num[0] == '-': #Convert to positive offset
                tz_flipped = 'Etc/GMT+%s'%tz_num[1:]
            else: #Convert to negative offset:
                tz_flipped = 'Etc/GMT-%s'%tz_num[1:]
            try:
                date_str = timezone(tz_flipped).localize(date_str, is_dst)
                return timezone('UTC').normalize( date_str, is_dst )
            except (ValueError, exceptions.UnknownTimeZoneError) as e:
                print '%s for %s with variable utc_offset:%s\n'%(e,self.time_to_convert,utc_offset)
                # print 'Try one of these timezone offsets/deltas%s\n'%timezone_deltas
                sys.exit(0)
        # Timezone found in timestamp use that instead
        else:
            return timezone('UTC').normalize( date_str, is_dst )


    def time_in_between( self, first_time, is_utc=False ):
        """time_in_between( ) = returns the days in between two timestamps"""
        # time_to_convert = def utc_conversion( self, utc_offset=None  )#TODO:Maybe use this for non utc time_in_between
        days_in_between = (self.time_to_convert - first_time).days
        # if is_utc == 'yes':#TODO:use or delete...Need to use in case ever used with non offset aware or non parsed timestamp
        #     print self.time_to_convert, first_time
        #     days_in_between = ( self.time_to_convert - first_time ).days
        #
        # else:
        #     utc = pytz.UTC
        #     days_in_between = ( self.time_to_convert - utc.localize(first_time) ).days
        return days_in_between

    def convert_offset_to_timezone_aware(self, tz_number):
        """convert_offset_to_timezone_aware( ) = take an offset and make it into the pyzt aware GMT timezone"""
        if tz_number in timezone_deltas:
            if tz_number[1:3] == '00':
                tz_info = 'Etc/GMT0'
                return tz_info
            elif tz_number[1] == '0':
                tz_info = 'Etc/GMT%s'%tz_number[0:3].replace('0','')
                return tz_info
            else:
                tz_info = 'Etc/GMT%s'%tz_number[0:3]
                return tz_info
        else:
            print '%s is an Unknown UTC offset/delta\n'%tz_number
            print 'Try one of these timezone offsets/deltas%s\n'%timezone_deltas
            sys.exit(0)