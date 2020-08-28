# GithubUserAudit

A python3 script to automate the creation of certain statistics used for github
user audits of the wikimedia organization.  See also:
* https://phabricator.wikimedia.org/T179462
* https://phabricator.wikimedia.org/T245526

## Prerequisites

```
python3
argparse
csv
datetime
os
re
requests
sys
datetime (datetime, timedelta)
dotenv (load_dotenv)
```

## Installing

2. ```git clone "https://gerrit.wikimedia.org/r/wikimedia/security/github-user-audit"```

## Usage

1. You'll need to at least be a "member" of the wikimedia github organization to run this script with any success.  You should likely know [whether or not you are](https://github.com/orgs/wikimedia/people).  If you are not, you'll need to seek out an owner to add you.  Once that's completed, you'll want to create a [github personal access token](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token) to use within the .env file.
2. Configure the rest of the .env file to your liking and then run something like: ```eval $(cat .env | sed 's/^/export /')``` - example values provided within sample.env.
3. Have a wikimedia organization owner download the [audit log](https://github.com/organizations/wikimedia/settings/audit-log) in csv format for you.  If you're an owner yourself, great! 
2. Run the script: ```chmod +x GithubUserAudit.py && ./GithubUserAudit.py {file name} {args...}``` and use the relevant output to create a protected Phabricator task for review, e.g. https://phabricator.wikimedia.org/T245526.
3. GithubUserAudit.py has a few arguments:
	1. audit_log_file_path   A valid Github audit log file path in csv format
	2. -h, --help            show this help message and exit
	3. -d DATE, --date DATE  A date interval for the request: [see validate_request_date_range() for examples]
	4. -a, --all_actions     Treat all actions in audit log as "owner" actions, including those defined within get_github_non_owner_actions

## TODO

1. From https://phabricator.wikimedia.org/T179462, it's still not entirely clear to me what the difference is between "owners performed Owner actions" and "owners used their Owner rights".  I think the latter might have something to do with teams.  Anyhow, the former is the only version implemented for now and simply checks whether or not a user has performed any non-Owner action (or any action with the ```-a``` option) within the audit log during a provided time period.
2. Owner rights or actions seem difficult to properly define based upon existing Github documentation.  I attempted to create a block list of confirmed non-owner actions within ```get_github_non_owner_actions``` (see also: github documentation links in function comment) as the simplest way to programmatically define these.  This likely needs further review and input.
3. The 2FA-enabled check (likely the information we care about most for an audit from a security perspective) is not included within the script (see: 2FA-Enabled block within ```enerate_all_stats```).  One would need owner credentials for the wikimedia organization for that information and I do not believe it's available through the github API.  I do not have a great way of working around this for now, sadly.
4. Should we have an option to display the raw data for non-attributed audit log entries?  These can be kind of lengthy for a given time period and if they are of concern, I'd imagine further manual digging within the audit log would happen.
5. Tests?

## Authors

* **Scott Bassett** [sbassett@wikimedia.org]

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](../LICENSE) file for details.
