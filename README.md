# Dependabot Scraper to Slack

Dependabot Information scraper for Github


## Introduction

This script scrapes and parses information regarding
dependabot alerts for Github repositories belonging to an organization.

Primary data points parsed are open, fixed, dismissed vulnerabilities, and
ecosystem (aka programming language) type of vulnerability.

This script provides flexible options for execution:
* from the Bash/Zsh command line and send summary results to a Slack channel
* from the Bash/Zsh command line and save detailed json/text/csv files locally
* as an AWS Lambda and send summary results to a Slack channel

NOTE: While this script _works_, it is far from ideal.  Things to be aware of:
* The script should be refactored!
* The Repo class structure should be refactored for better organization.
* Consider vectorization via [Pandas](https://github.com/pandas-dev/pandas) for improved performance and maintenance.
* Consider using [pygithub](https://github.com/PyGithub/PyGithub) module in lieu of direct API calls with urllib3.


## Prerequisites

* Bash or ZSH Shell
* A [Github token](https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28) with _security_events_ scope to read private repositories is
required.
* [uv](https://github.com/astral-sh/uv) package manager to ensure urllib3 is installed
* Python 3 - This was developed and tested with Python 3.10.  Likely to work
with Python 3.6 and above.  (f-strings used in print statements)
* Optional: [GitHub GH CLI](https://cli.github.com/) - used to execute GH CLI commands


## Quick Start

1. Set the following environment variables:\
    a. GH_TOKEN - Github API key\
        eg: `export GH_TOKEN=ghp_XXXXXXXXX`\
        Note: GH_TOKEN was chosen to match the name of the environment variable
        used for the [GitHub GH CLI command](https://cli.github.com/manual/gh_help_environment),
        which enables GH CLI to be authenticated to Github. View login status
        via: `gh auth status`
    b. GH_ORG - Github organization to query\
        eg: `export GH_ORG=procurify`\
    c. SLACK_URL - slack url to the slack webhook\
        eg: `export SLACK_URL="https://hooks.slack.com/services/XXX"`\
       _Disregard SLACK_URL environment variable if local data is preferred,
       refer to Step 2. below_.

2. `uv run ./dependabot_slack.py` alternatively, if sending to a Slack
channel is not required, save the data locally:\
`uv run ./dependabot_slack.py local`

* CSV output files are written to the current folder under ./data and
org_data/ folder.
* JSON files for each repo is saved to the current folder under ./json_output,
in the event manual review is needed.  Note, this data can also be viewed via
Github, within the reposistory, under the security tab, assuming appropriate
permissions are granted.
* The aforementioned folders are in the .gitignore file to prevent potentially
uploading sensitive information to github.


## Service Level Objectives (SLO)

This script output provides SLO percentage numbers as defined by "the
objectives your team must hit to meet that agreement".

Based on CVSSv3 Score, below is the SLO calculations the Slack output
are based on.

| CVSSv3 Score   | Time to Redmediate (Days) |
|---|---|
| 9.0-10.0 (Critical)  | 15  |
| 7.-8.9 (High)  | 30  |
| 4.0-6.9 (Medium)  | 90  |
| 0.1-3.9 (Low)  | 180  |


## AWS Lambda

In the lambda/ folder, is a drop-in working copy of this script for
AWS Lambda service.

* The script is amended to enable global variables, due to the entry point
of the lambda execution.  In other words this will (should) just work.

* The environment variables GH_TOKEN and SLACK_URL are moved to AWS Systems
Manager Parameter Store, due to sensitivity.  Note the code to
retrieve these values from Parameter Store.  Naturally, Parameter Store will
require these key/values populated for the script to work.

* GH_ORG remains as a environment variable.

* Configure AWS EventBridge as required to trigger this lambda at a
desired schedule.

* Execution time will vary depending on number of repos associated with an
organization.  Recommend setting the lambda execution time limit to the maximum
of five minutes to avoid potential timeout errors.


## Slack Webhook

To configure a slack webhook refer to this [page](https://api.slack.com/messaging/webhooks)


## Notes

1. Optimization considerations:
    * Query Github via [GraphQL](https://github.blog/changelog/2022-06-29-dependabot-alerts-dependency-scope-filter-via-graphql-api/)
    * Vectorization via [NumPy](https://numpy.org/) or [Pandas](https://pandas.pydata.org/)

2. Slack output (presentation) is limited.  Consequently, the output is less
   than ideal.

3. This script is maintained within a single file, for convenient
   deployment to AWS Lambda.  While there are options to facilitate multiple
   files or utilize Lambda Layers, a single file deployment is most convenient.

4. Minimal use of external modules was intentional - again to minimize
   complexity for potential deployment to an AWS Lambda.  Additionally, local
   testing is simplified with reduced third-party dependency.


## TODO

1. Add Docstrings and type hints to the Repo Class, as well as to methods and
functions.

2. Possibly refactor the script to modules. (too large of a script!)


## References

[List organization repos](https://docs.github.com/en/rest/repos/repos#list-organization-repositories)\
[List dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)\
[Working with Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot)\
[Github Dependabot Blog](https://github.blog/2020-06-01-keep-all-your-packages-up-to-date-with-dependabot/)


## License

Released under the [MIT](https://opensource.org/licenses/MIT) License


## Contributing

Concerns/Questions, open an issue.  Improvements, please submit a pull request.
