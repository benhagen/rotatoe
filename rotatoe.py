#!/usr/bin/env python

"""rotatoe

Usage:
  rotatoe.py [--days=<days_inactive>] [--commit] [--regex=<regex>] [--regex_exclude=<regex>]

Options:
  -h --help                   Show this screen
  --version                   Show version
  -v --verbose                More verbose logging
  -c --commit                 Commit changes
  --days=<days_inactive>      Days since last activity [default: 30]
  --regex=<regex>             Regular expression to match usernames [default: .*]
  --regex_exclude=<regex>     Regular expression to disregard matched usernames
"""

import botocore
import boto3
import string
import random
import sys
from datetime import datetime, tzinfo, timedelta
import pytz
import re

CREDENTIAL_REPORT = {}


class IAMUserClass(object):

	def __init__(self, *args, **kwargs):
		self.iam_client = Session.client("iam")
		super(IAMUserClass, self).__init__(*args, **kwargs)

	@property
	def has_mfa(self):
		# if user.name in CREDENTIAL_REPORT:
		# 	return report[user.name]['mfa_active']
		if len([user.mfa_devices.all()]) > 0:
			return True
		return False

	@property
	def has_password(self):
		# if user.name in CREDENTIAL_REPORT:
		# 	return CREDENTIAL_REPORT[user.name]['password_enabled']:
		try:
			login_profile = self.iam_client.get_login_profile(UserName=self.name)
			return True
		except:
			return False

	@property
	def password_last_changed(self):
		if user.name not in CREDENTIAL_REPORT:
			return None

	@property
	def password_last_date(self):
		if self.password_last_changed and self.password_last_change > self.password_last_used:
			return self.password_last_changed
		if not self.password_last_used:
			return self.create_date
		return self.password_last_used


def add_custom_iamuser_class(base_classes, **kwargs):
	base_classes.insert(0, IAMUserClass)


def json_serializer(obj):
	if isinstance(obj, datetime):
		return int((obj.replace(tzinfo=None) - datetime(1970, 1, 1)).total_seconds())
	if isinstance(obj, set):
		return list(obj)


Session = boto3.Session()
Session.events.register('creating-resource-class.iam.User', add_custom_iamuser_class)


if __name__ == '__main__':
	from docopt import docopt
	import json

	arguments = docopt(__doc__, version='rotatoe 1.0')
	# print arguments

	iam_client = Session.client("iam")
	iam_resource = Session.resource("iam")

	if arguments['--commit']:
		print "WARNING: You will be changing user accounts/keys that have not be used in more than {} days. Are you sure you want to do this?".format(arguments['--days'])
		response = raw_input("Type 'HELL YES' to continue: ")
		if response != "HELL YES":
			print "Exiting like the coward you are ... no changes have been made.\n"
			sys.exit()

	# Turn the credential report into a useful format
	try:
		report_raw = iam_client.get_credential_report()
	except botocore.exceptions.ClientError as e:
		result = iam_client.get_credential_report()
		print result
		sys.exit()

	report_raw = report_raw['Content'].split("\n")
	report_keys = report_raw[0].split(",")
	for line in report_raw[1:]:
		parts = line.split(",")
		line_dict = {}
		for offset in range(len(report_keys)):
			if "+00" in parts[offset]:
				parts[offset] = datetime.strptime(parts[offset], '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=pytz.UTC)
			if parts[offset] == "N/A":
				parts[offset] = None
			if parts[offset] == "false":
				parts[offset] = False
			if parts[offset] == "true":
				parts[offset] = True
			line_dict[report_keys[offset]] = parts[offset]
		CREDENTIAL_REPORT[line_dict['user']] = line_dict

	now = datetime.now(pytz.UTC)

	print "User Name                                 API KEY               Date Created               Date Last Used/Rotated     Days"
	print "----------------------------------------  --------------------  -------------------------  -------------------------  ----  ------"

	for user in iam_resource.users.all():
		if re.match(arguments['--regex'], user.name) and (not arguments['--regex_exclude'] or (arguments['--regex_exclude'] and not re.match(arguments['--regex_exclude'], user.name))):
			if user.has_password:
				days_since = (now - user.password_last_date).days
				if days_since > int(arguments['--days']) or not user.has_mfa:
					print "{: <40}  {: <20}  {: <25}  {: <25}  {: >4}  MFA:{}".format(user.name, "<Console User>", str(user.create_date), str(user.password_last_date), days_since, user.has_mfa)
					if arguments['--commit']:
						password = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%^&*()_+-=[]{}|'") for _ in range(32))
						iam_client.update_login_profile(UserName=user.name, Password=password)
						print "[!] Password rotated to a random string!"

			for key in user.access_keys.all():
				if key.status == "Active":
					result = iam_client.get_access_key_last_used(AccessKeyId=key.access_key_id)
					if "LastUsedDate" in result['AccessKeyLastUsed']:
						last_used = result['AccessKeyLastUsed']['LastUsedDate']
						days_since = (now - last_used).days
					else:
						last_used = None
						days_since = (now - key.create_date).days

					if days_since > int(arguments['--days']):
						print "{: <40}  {: <20}  {: <25}  {: <25}  {: >4}  {}".format(user.name, key.access_key_id, str(key.create_date), str(last_used), days_since, key.status)
						if arguments['--commit']:
							iam_client.update_access_key(UserName=result['UserName'], AccessKeyId=key.access_key_id, Status="Inactive")
							print "[!] Deactivated key!"
