#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Basic statistics tool for WMF github audit log analysis
    - Basic user table statsuser table
    - 2fa-enabled for users (non-implemented programmatically)
    - Number of non-attributable log entrie
    - Percent of Owners who performed Owner actions
Author: sbassett@wikimedia.org
License: Apache 2.0
References: T179462, https://git.io/JJYY6
"""

import argparse
import csv
import os
import re
import requests
import sys
from datetime import datetime, timedelta
from dotenv import load_dotenv


class GithubUserAudit():
    """ Class to generate basic github owner account statistics """
    def __init__(self, audit_log_file_path, date_range, all_actions):
        """ constructor """
        self.audit_log_file_path = audit_log_file_path
        self.date_range = date_range
        self.date_start = None
        self.date_end = None
        self.all_actions = all_actions

        load_dotenv()
        self.api_base_url = os.getenv('GH_API_BASE_URL')
        self.api_members_endpoint = os.getenv('GH_API_MEMBERS_ENDPOINT')
        self.api_token = os.getenv('GH_API_TOKEN')

        self.wm_gh_members = []
        self.wm_gh_owners = []
        self.audit_log_data = []
        self.non_attributed_log_entries = []
        self.owners_performed_owner_actions = [0, 0, 0]
        self.absent_owners = []

        if(self.validate_audit_log_file_path() and
           self.validate_and_process_request_date_range()):

            self.get_audit_log_file_data()
            self.get_member_data_from_api()
            self.get_member_data_from_api(True)
            self.calc_percent_owners_performed_owner_actions()

            self.find_non_attributed_log_entries()
            self.get_owners_who_have_not_performed_an_owner_action()
            self.generate_all_stats()
        else:
            print("ERROR: the date range or audit log file appears invalid.")
            sys.exit(1)

    def validate_audit_log_file_path(self):
        check_value = False
        if os.path.exists(self.audit_log_file_path):
            check_value = True

        return check_value

    def get_audit_log_file_data(self):
        data = None
        processed_data = []
        with open(self.audit_log_file_path, newline='') as f:
            csv_reader = csv.reader(f, delimiter=',')
            next(csv_reader)
            data = list(csv_reader)
            if(self.date_start and self.date_end):
                for i in range(len(data)):
                    """ prune if date range is specified """
                    if(re.search(r'^\d+$', data[i][5])):
                        log_time = datetime.fromtimestamp(
                            int(data[i][5]) / 1e3)
                        if(log_time >= self.date_start and
                           log_time <= self.date_end):
                            if(not self.all_actions and
                               data[i][0] in
                               self.get_github_non_owner_actions()):
                                continue
                            else:
                                processed_data.append(
                                    [data[i][1], data[i][0], data[i][5]])
            else:
                """ default: no date specified """
                for i in range(len(data)):
                    processed_data.append(
                        [data[i][1], data[i][0], data[i][5]])
        self.audit_log_data = processed_data

    def calc_percent_owners_performed_owner_actions(self):
        owners = []
        for item in self.audit_log_data:
            if(item[0] in self.wm_gh_owners and
               item[0] not in owners):
                owners.append(item[0])
        self.owners_performed_owner_actions = [float("{:.1f}".format(
            len(owners) / len(self.wm_gh_owners) * 100)),
            len(owners),
            len(self.wm_gh_owners)]

    def get_owners_who_have_not_performed_an_owner_action(self):
        """ sets as phab markdown for now for convenience """
        owners_in_log = []
        absent_owners = ''
        for item in self.audit_log_data:
            if(item[0] in self.wm_gh_owners and
               item[0] not in owners_in_log):
                owners_in_log.append(item[0])
        for username in self.wm_gh_owners:
            if(username not in owners_in_log):
                absent_owners = ''.join([
                   absent_owners,
                   "* [[ ",
                   "https://github.com/",
                   username,
                   " | ",
                   username,
                   " ]] \n"])
        self.absent_owners = absent_owners

    def find_non_attributed_log_entries(self):
        non_attributed_entries = []
        for item in self.audit_log_data:
            if (item[0] == ''):
                non_attributed_entries.append(item)
        self.non_attributed_log_entries = non_attributed_entries

    def validate_and_process_request_date_range(self):
        """ validate arg: validate stats request dates """
        """ supported: Xh, Xd, YYYY-MM-DD, YYYY-MM-DD-YYYY-MM-DD, """
        check_value = False
        ucnow = datetime.now()
        if self.date_range is None:
            """ allow None (default) as an acceptable value """
            check_value = True
        else:
            m = re.match(r'^(\d{1,3})([d|h])$', self.date_range)
        if (check_value is False and m and m is not None
                and m.group(1) is not None and
                m.group(2) is not None):
            this_timedelta = timedelta(hours=int(m.group(1)))
            if m.group(2) == 'd':
                this_timedelta = timedelta(days=int(m.group(1)))
            self.date_start = ucnow - this_timedelta
            self.date_end = ucnow
            check_value = True
        if (check_value is False):
            m = re.match(r'^(0?[1-9]|1[0-9]|2[0-5])([h])$', self.date_range)
            if (m is not None and m.group(1) is not None and
                    m.group(2) is not None):
                self.date_start = ucnow - \
                                  timedelta(hours=int(m.group(1)))
                self.date_end = ucnow
                check_value = True
        if (check_value is False):
            m = re.match(r'^(\d{4}\-\d{2}\-\d{2})(\-\d{4}\-\d{2}\-\d{2})?$',
                         self.date_range)
            if (m is not None and m.group(1) is not None):
                self.date_start = datetime.strptime(m.group(1), "%Y-%m-%d")
                if (m.group(2) is not None):
                    self.date_end = datetime.strptime(
                        m.group(2)[1:], "%Y-%m-%d")
                else:
                    self.date_end = ucnow
                check_value = True
        if (check_value is False):
            error_msg = ("Invalid date argument supplied.\n\n"
                         "Supported date formats:\n\n"
                         " * Xd\n"
                         " * Xh\n"
                         " * YYYY-MM-DD\n"
                         " * YYYY-MM-DD-YYYY-MM-DD")
            print(error_msg)
            sys.exit(1)

        """ misc sanity checks """
        if (self.date_start is not None and
           self.date_end is not None):
            if (self.date_end < self.date_start):
                tmp = self.date_end
                self.date_end = self.date_start
                self.date_start = tmp
            if (self.date_end > ucnow):
                self.date_end = ucnow
        return check_value

    def get_member_data_from_api(self, owners=False):
        """ get list of wm members and owners from github api """
        """ (requires valid personal access token) """
        per_page = 'per_page=50'
        flag_owners = ''
        if owners:
            flag_owners = '&role=admin'
        members = []

        api_url = ''.join([
            self.api_base_url,
            self.api_members_endpoint,
            '?',
            per_page,
            flag_owners])
        resp = requests.head(
            api_url,
            headers={'Authorization': ''.join(['token ', self.api_token])})
        if resp.status_code != 200:
            print("Response Error, status code = {}".format(
                resp.status_code))
            sys.exit(1)
        else:
            pag_urls_re = []
            pag_url_max_page = 0
            if ('Link' in resp.headers):
                pag_urls_re = re.findall(r'\<(.*?)\>', resp.headers['Link'])
                if pag_urls_re and len(pag_urls_re):
                    pag_url_max_page = int(pag_urls_re[-1].split("&page=")[-1])

        # any additional paginated pages
        if len(pag_urls_re):
            for i in range(1, pag_url_max_page + 1, 1):
                api_url_pag = ''.join([api_url, '&page=', str(i)])
                resp = requests.get(
                    api_url_pag,
                    headers={'Authorization': ''.join([
                        'token ', self.api_token])})
                if resp.status_code != 200:
                    print("Response Error, status code = {}".format(
                        resp.status_code))
                    sys.exit(1)
                else:
                    for item in resp.json():
                        if (isinstance(item, dict) and
                           len(item['login'])):
                            members.append(item['login'])
        # assign member/owner list
        if owners:
            self.wm_gh_owners = members
        else:
            self.wm_gh_members = members

    def get_github_non_owner_actions(self):
        """ see also: https://git.io/JJYY6, https://git.io/JJipj """
        """ we retrieve non-owner actions here, as it's a smaller list """
        """ and these lists do not have a 1-1 correspondence. """
        """ assume all actions not listed here require owner rights. """
        return [
            'repo.create',
            'team.create',
            'commit_comment.update',
            'issue_comment.update'
        ]

    def generate_all_stats(self):
        """ generate statistics/info in Phabricator remarkup"""
        """ user table """
        """ 2fa-enabled """
        """ non-attributable log entries """
        """ percent owner operations """
        """ TODO: clean up and possibly support more output options """
        people_url = "https://github.com/orgs/wikimedia/people"
        member_fil = "?utf8=%E2%9C%93&query=role%3Amember"
        owner_fil = "?utf8=%E2%9C%93&query=role%3Aowner"
        num_people = len(self.wm_gh_members)
        num_owners = len(self.wm_gh_owners)
        num_members = num_people - num_owners

        print("!!**User Statistics**!!\n")
        print("| {icon info-circle color=blue} **User Statistics** |  ")
        print("| --- | ---")
        print(f"| [[ {people_url} | Total Collaborators ]] | {num_people}")
        print(f"| [[ {people_url}{member_fil} | Members ]] | {num_members}")
        print(f"| [[ {people_url}{owner_fil} | Owners ]] | {num_owners}")

        print("\n!!**2fa-Enabled**!!\n")
        print("{icon info-circle color=blue} Have a github admin ", end='')
        print("filter for 'two-factor:disabled' on all org members.")

        print("\n!!**Owner / Operations Statistics**!!\n")
        print("{icon exclamation-triangle color=red} "
              "Number of non-attributed log entries: "
              f"{len(self.non_attributed_log_entries)}.\n")
        print("{icon exclamation-triangle color=red} "
              f"{self.owners_performed_owner_actions[0]}% "
              "of the owners performed Owner actions ("
              f"{self.owners_performed_owner_actions[1]} of "
              f"{self.owners_performed_owner_actions[2]}).\n")
        print("Owners who have not performed any owner actions:\n\n"
              f"{self.absent_owners}")


""" cli args/control """
parser = argparse.ArgumentParser()
parser.add_argument('audit_log_file_path', help='A valid Github \
                    audit log file path (csv format)',
                    type=str)
parser.add_argument('-d', '--date', default=None,
                    help='A date interval for the request: \
                    [see validate_request_date_range for examples]',
                    type=str)
parser.add_argument('-a', '--all_actions', action='store_true',
                    help='Treat all actions in audit log as "owner" actions, \
                    including those defined within \
                    get_github_non_owner_actions')
args, unknown = parser.parse_known_args()

""" Instantiate and run """
gt = GithubUserAudit(
    args.audit_log_file_path,
    args.date,
    args.all_actions
)
