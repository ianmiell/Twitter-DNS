import tweepy
import urllib2
import re
import argparse
import time

def setupArgs():
	parser = argparse.ArgumentParser(description='Twitter DNS Updater')
	parser.add_argument('-u', '--username', nargs=1, help='username of account to update', required=True)
	parser.add_argument('-s', '--sleep', nargs=1, help='switch on daemon mode (ie, set the IP address on twitter); time to sleep is in seconds. absence of this will get the current IP address from twitter.', type=int, required=False)
	parser.add_argument('--consumer_key', nargs=1, help='oauth consumer key', required=True)
	parser.add_argument('--consumer_secret', nargs=1, help='oauth consumer secret', required=True)
	parser.add_argument('--access_token', nargs=1, help='oauth access token', required=True)
	parser.add_argument('--access_token_secret', nargs=1, help='oauth access token secret', required=True)
	parser.add_argument('--verbose', help='print debug', action='store_true', required=False)
	parser.add_argument
	args = parser.parse_args()
	return args

def getPublicIp():
	# Set up request object.
	url = 'http://checkip.dyndns.com/'
	response = urllib2.urlopen(url)
	data = str(response.read())
	# data = '<html><head><title>Current IP Check</title></head><body>Current IP Address: 65.96.168.198</body></html>\r\n'
	return re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(str(data)).group(1)

def do_auth(consumer_key, consumer_secret, access_token, access_secret):
	# https://dev.twitter.com/apps/1869297/show
	# Set up with read/write access.
	# key and secret from https://dev.twitter.com/apps/
	# See here for more info: https://dev.twitter.com/docs/auth/authorizing-request
	auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
	# access token and secret (make sure you generate these with the right permission in the url above)
	auth.set_access_token(access_token, access_secret)
	# Construct the API instance
	api = tweepy.API(auth)
	return api


# Daemon/update mode.
# 
# username - Username to update.
# api      - Twitter api object.
# sleep    - Number of seconds to sleep between updates.
def daemon_mode(username, api, sleep):
	ip = ''
	while True:
		newip = getPublicIp()
		if debug:
			print "New IP: " + newip + ", old IP: " + ip
		if newip != ip:
			try:
				if debug:
					print "Updating"
				# TODO: what to do with s?
				s = api.update_status("@%s %s" % (username, newip))
			except Exception as e:
				if debug:
					print e
				ip = newip
			else:
				ip = newip
				if debug:
					print "Target http://twitter.com/#!/%s, ip: %s" % (username, ip)
		time.sleep(sleep)


# Set up data.
args = setupArgs()
username            = args.username[0]
consumer_key        = args.consumer_key[0]
consumer_secret     = args.consumer_secret[0]
access_token        = args.access_token[0]
access_token_secret = args.access_token_secret[0]
debug               = args.verbose
if args.sleep != None:
	sleep = args.sleep[0]
else:
	sleep = None

# Set up api object.
api = do_auth(consumer_key, consumer_secret, access_token, access_token_secret)

if sleep == None:
	statuses = api.user_timeline(count=1)
	for status in statuses:
		# TODO: validate the output for the case where the status is not set, or not set correctly
		print re.compile(r'.* (\d+\.\d+\.\d+\.\d+)').search(str(status.text)).group(1):
else:
	daemon_mode(username,api,sleep)
