Changelog
=========
1.0.9 (2016-03-22)
-------------------
-Some IPs returning none for geoip

1.0.8 (2016-03-17)
-------------------
-FML...array geo-points are [longitude,latitude]—the opposite order!

1.0.7 (2016-03-14)
-------------------
-With ipwhois version 0.11.2 allows to not use whois for cyrmu and only dns in order to not get blacklisted and if it fails.
-Set Maxmind DBs to only update second tuesday of every month. Technically just looks to see if its greater than 14 days since download
-Added ability to grab AS Name & Number from Maxmind DB instead of having to do an online lookup
-Added logging and removed prints
-Using HTTPs maxmind database now

1.0.6 (2016-01-27)
-------------------
-Using with open file instead of just open.

1.0.5 (2016-01-26)
-------------------
-Added whois raw information

1.0.4 (2016-01-18)
-------------------
-Minor changes

1.0.3 (2016-01-18)
-------------------
-Fixed home directory for windows or linux

1.0.2 (2016-01-18)
-------------------
-Added pprint for examples

1.0.1 (2016-01-18)
-------------------
-GD unicode returns from MongoDB
-removed some unnecessary print newlines

1.0.0 (2016-01-18)
-------------------
-initial commit