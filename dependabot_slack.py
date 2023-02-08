#!/usr/bin/python

import urllib3
import json
import os
import sys
import re
import pprint
import csv
from datetime import datetime
from pathlib import Path


class Repo:
    """parse data for the repo and return dictionary of relevant information

    Args:
        None

    Returns:
        dict: returns information for open,fixed,dismissed state of repos,
              including severity levels, ecosystems, and service level
              objectives (SLO) and priority level.

              Priority level is calculated by sum of critical plus high
              vulnerabilities.  The intent here to provide organizations
              (or development teams) a priority of which repos to remediate
              first based on volume of criticals and high.  Naturally critical
              and high vulnerabilities typically a take higher precedent over
              medium and low alerts.

              SLO definitions: critical - 15 days
                               high - 30 days
                               medium - 90 days
                               low - 180 days

    """

    def __init__(self, name, repo_dict):

        self.repo_dict = repo_dict

        (
            state_open,
            state_fixed,
            state_dismissed,
            slos,
        ) = self.get_state_data()

        combined_data = {
            **state_open,
            **state_fixed,
            **state_dismissed,
            **slos,
        }

        # returned the parsed data as a single large dictionary
        self.parsed_data = {"Name": name}
        self.parsed_data.update(combined_data)

    def get_slo(self):
        """Calculate age of vulnerability (dependabaot alert) based on
        published date and current date/time when script is executed
        SLO = Service Level Objective.
        Below SLO age are target SLOs to maintain.
        """

        CRIT_MAX_SLO_DAYS = 15
        HIGH_MAX_SLO_DAYS = 30
        MED_MAX_SLO_DAYS = 90
        LOW_MAX_SLO_DAYS = 180

        slo = {
            "Crit Exceeded": 0,
            "High Exceeded": 0,
            "Med Exceeded": 0,
            "Low Exceeded": 0,
        }

        for item in self.repo_dict:
            if item["state"] == "open":
                if item["security_advisory"]["severity"] == "critical":
                    temp_date = item["security_advisory"]["published_at"]
                    temp_date_obj = datetime.strptime(
                        temp_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                    crit_age = current_time - temp_date_obj
                    if crit_age.days >= CRIT_MAX_SLO_DAYS:
                        slo["Crit Exceeded"] += 1

                elif item["security_advisory"]["severity"] == "high":
                    temp_date = item["security_advisory"]["published_at"]
                    temp_date_obj = datetime.strptime(
                        temp_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                    high_age = current_time - temp_date_obj
                    if high_age.days >= HIGH_MAX_SLO_DAYS:
                        slo["High Exceeded"] += 1

                elif item["security_advisory"]["severity"] == "medium":
                    temp_date = item["security_advisory"]["published_at"]
                    temp_date_obj = datetime.strptime(
                        temp_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                    medium_age = current_time - temp_date_obj
                    if medium_age.days >= MED_MAX_SLO_DAYS:
                        slo["Med Exceeded"] += 1

                elif item["security_advisory"]["severity"] == "low":
                    temp_date = item["security_advisory"]["published_at"]
                    temp_date_obj = datetime.strptime(
                        temp_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                    low_age = current_time - temp_date_obj
                    if low_age.days >= LOW_MAX_SLO_DAYS:
                        slo["Low Exceeded"] += 1

        return slo

    def get_state_data(self):
        """Parse state severity data from repos.  See below state_template
        dictionary for respective open, fixed, dismissed information that
        is obtained.
        """
        # template dictionary keys; allows reuse of nested parse_data function
        state_template = {
            "Total": 0,
            "Crit": 0,
            "High": 0,
            "Med": 0,
            "Low": 0,
            "Date": "",
            "Npm": 0,
            "Pip": 0,
            "Rubygems": 0,
            "Nuget": 0,
            "Maven": 0,
            "Composer": 0,
            "Rust": 0,
            "Unknown": 0,
        }
        state_open = dict(state_template)
        date_list_open = []

        state_fixed = dict(state_template)
        date_list_fixed = []

        state_dismissed = dict(state_template)
        date_list_dismissed = []

        def parse_data(item_dict, parsed_dict):
            """parse ecosystem data with respect to critical,high,medium,low
            findings

            Args:
                parsed_dict: dictionary of json dependabot information

            Returns:
                parsed_dict: dictionary, with ecoysystem count for each
                             severity level
            """

            parsed_dict["Total"] += 1

            if item_dict["security_advisory"]["severity"] == "critical":
                parsed_dict["Crit"] += 1
            elif item_dict["security_advisory"]["severity"] == "high":
                parsed_dict["High"] += 1
            elif item_dict["security_advisory"]["severity"] == "medium":
                parsed_dict["Med"] += 1
            else:
                parsed_dict["Low"] += 1

            if item_dict["dependency"]["package"]["ecosystem"] == "npm":
                parsed_dict["Npm"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "pip":
                parsed_dict["Pip"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "rubygems":
                parsed_dict["Rubygems"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "nuget":
                parsed_dict["Nuget"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "maven":
                parsed_dict["Maven"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "composer":
                parsed_dict["Composer"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "rust":
                parsed_dict["Rust"] += 1
            else:
                parsed_dict["Unknown"] += 1

            return parsed_dict

        for item in self.repo_dict:
            if item["state"] == "open":
                state_open = parse_data(item, state_open)

                # keep only first reported open alert date
                temp_pub_at_date = item["security_advisory"]["published_at"]
                date_list_open.append(
                    datetime.strptime(temp_pub_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_open["Date"] = str(min(date_list_open))

            elif item["state"] == "fixed":
                state_fixed = parse_data(item, state_fixed)

                # keep only most recent fixed alert date
                temp_fixed_at_date = item["fixed_at"]
                date_list_fixed.append(
                    datetime.strptime(temp_fixed_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_fixed["Date"] = str(max(date_list_fixed))

            elif item["state"] == "dismissed":
                state_dismissed = parse_data(item, state_dismissed)

                # keep only most recent dismissed alert date
                temp_dismissed_at_date = item["dismissed_at"]
                date_list_dismissed.append(
                    datetime.strptime(
                        temp_dismissed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                )
                state_dismissed["Date"] = str(max(date_list_dismissed))

        # amend the dictionaries keys to reflect the state data
        state_open = {
            f"Open {key}": value for key, value in state_open.items()
        }
        state_fixed = {
            f"Fixed {key}": value for key, value in state_fixed.items()
        }
        state_dismissed = {
            f"Dismissed {key}": value for key, value in state_dismissed.items()
        }

        # set a priority level for remediation for open alerts
        priority = state_open["Open Crit"] + state_open["Open High"]
        state_open["Priority"] = priority
        slo_info = self.get_slo()

        if state_open["Open Crit"] > 0:
            slo_info["Crit Percentage"] = round(
                slo_info["Crit Exceeded"] / state_open["Open Crit"] * 100, 2
            )
        else:
            slo_info["Crit Percentage"] = 0.0

        if state_open["Open High"] > 0:
            slo_info["High Percentage"] = round(
                slo_info["High Exceeded"] / state_open["Open High"] * 100, 2
            )
        else:
            slo_info["High Percentage"] = 0.0

        if state_open["Open Med"] > 0:
            slo_info["Med Percentage"] = round(
                slo_info["Med Exceeded"] / state_open["Open Med"] * 100, 2
            )
        else:
            slo_info["Med Percentage"] = 0.0

        if state_open["Open Low"] > 0:
            slo_info["Low Percentage"] = round(
                slo_info["Low Exceeded"] / state_open["Open Low"] * 100, 2
            )
        else:
            slo_info["Low Percentage"] = 0.0

        return state_open, state_fixed, state_dismissed, slo_info


def get_repo_list():
    """Retrieve list of all repos for the organization designated by the
    environment variable GH_ORG.

    Returns:
       list of non-archived repos.
       list of archived repos.
    """
    http = urllib3.PoolManager()
    # set args for http request
    all_repo_list = []
    page = 1
    url = f"https://api.github.com/orgs/{org}/repos"
    req_fields = {"per_page": 100, "page": page}
    req_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": auth,
    }
    resp = http.request("GET", url, fields=req_fields, headers=req_headers)
    json_resp = json.loads(resp.data.decode("utf-8"))
    all_repo_list.append(json_resp)

    # continue querying until all repos are returned
    if len(json_resp) == 100:
        while len(json_resp) == 100:
            page += 1
            req_fields = {"per_page": 100, "page": page}
            resp = http.request(
                "GET", url, fields=req_fields, headers=req_headers
            )
            json_resp = json.loads(resp.data.decode("utf-8"))
            all_repo_list.append(json_resp)

    # flatten the list of json lists to a single list
    final_list = sum(all_repo_list, [])

    # create separate lists for archived and non-archived repos
    archived = []
    non_archived = []
    for item in final_list:
        if item["archived"] is False:
            non_archived.append(item["name"])
        else:
            archived.append(item["name"])

    return non_archived, archived


def get_dependabot_alerts(non_archived):
    """Retrieve all dependabot data for active repos.

       Returns json data for all repos, in separate lists.  The data returned
       is for future implementation. (Saved data to local disk to be
       read instead of querying the Github API repeatedly)

    Args:
        non_archived(list): list of non-archived repos

    Returns:
        repos_no_vulns: list of repos without dependabot alerts
        repos_with_vulns: list of repos with dependabot alerts
        repos_disabled: list of repos with dependabot alerts disabled
        no_vulns_json_data: json data of repos without depabot alerts
        disabled_json_data: json data of repos that are disabled dependabot
        vulns_json_data: json data of repos with dependabot alerts

    """
    repos_no_vulns = []
    repos_with_vulns = []
    repos_disabled = []
    repo_vulns = []
    no_vulns_json_data = []
    disabled_json_data = []
    vulns_json_data = []

    http = urllib3.PoolManager()
    # set args for http request
    req_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": auth,
    }

    for repo_name in non_archived:
        page = 1
        temp_vulns = []

        print(f"Getting Dependabot alert info for: {repo_name}")

        url = (
            f"https://api.github.com/repos/{org}/{repo_name}/dependabot/alerts"
        )
        # custom field headers are not added to the initial request
        # this determines the total number of pages in the response via the
        # link header; link header only present if response requires pagination
        resp = http.request("GET", url, headers=req_headers)
        json_resp_header = dict(resp.headers)

        # if 30 or more items, response will be paginated,
        # determine the last page to query
        if "Link" in json_resp_header:
            pages_regex = re.findall(r"page=\d+", json_resp_header["Link"])
            lastpage_regex = re.findall(r"\d+", pages_regex[1])
            lastpage = int(lastpage_regex[0])
            repos_with_vulns.append(repo_name)

            for query in range(lastpage):
                req_fields = {"page": page}
                resp = http.request(
                    "GET", url, fields=req_fields, headers=req_headers
                )
                json_resp = json.loads(resp.data.decode("utf-8"))
                temp_vulns.append(json_resp)
                page += 1
            # flatten the list of lists, then add it as single list to a
            # list - each item in the final list representing
            # a single repo of dependabot information
            repo_vulns = sum(temp_vulns, [])
            vulns_json_data.append(repo_vulns)

        else:
            json_resp = json.loads(resp.data.decode("utf-8"))
            if len(json_resp) == 0:
                # no dependabot alerts associated with the repo
                repos_no_vulns.append(repo_name)
                no_vulns_json_data.append(json_resp)
            elif "message" in json_resp:
                # dependabot alerts disabled for the repo
                repos_disabled.append(repo_name)
                disabled_json_data.append(json_resp)
            else:
                # less than 30 dependabot alerts associated with the repo
                repos_with_vulns.append(repo_name)
                vulns_json_data.append(json_resp)
    # TODO: Fix this ugliness; multiple returned items is generally bad practice
    return (
        repos_no_vulns,
        repos_with_vulns,
        repos_disabled,
        no_vulns_json_data,
        disabled_json_data,
        vulns_json_data,
    )


def get_org_data(
    repos_no_vulns, repos_with_vulns, repos_disabled, parsed_data
):
    """Calculate organizational data.

    Args:
        repos_no_vulns: list of repos without dependabot alerts
        repos_with_vulns: list of repos with dependabot alerts
        repos_disabled: list of repos with dependabot alerts disabled
        parsed_data: list of parsed data from each repo

    Return:
        org_data: dictionary of organization data
    """
    num_no_vulns = len(repos_no_vulns)
    num_with_vulns = len(repos_with_vulns)
    num_disabled = len(repos_disabled)
    total_repos = num_no_vulns + num_with_vulns + num_disabled

    org_data = {
        "Total Number of Repos": total_repos,
        "Repos with alerts": num_with_vulns,
        "Repos without alerts": num_no_vulns,
        "Repos disabled alerts": num_disabled,
        "Open Total": 0,
        "Open Crit": 0,
        "Open High": 0,
        "Open Med": 0,
        "Open Low": 0,
        "Open Npm": 0,
        "Open Pip": 0,
        "Open Rubygems": 0,
        "Open Nuget": 0,
        "Open Maven": 0,
        "Open Composer": 0,
        "Open Rust": 0,
        "Open Unknown": 0,
    }

    for data in range(len(parsed_data)):
        org_data["Open Crit"] += parsed_data[data]["Open Crit"]
        org_data["Open High"] += parsed_data[data]["Open High"]
        org_data["Open Med"] += parsed_data[data]["Open Med"]
        org_data["Open Low"] += parsed_data[data]["Open Low"]
        org_data["Open Npm"] += parsed_data[data]["Open Npm"]
        org_data["Open Pip"] += parsed_data[data]["Open Pip"]
        org_data["Open Rubygems"] += parsed_data[data]["Open Rubygems"]
        org_data["Open Nuget"] += parsed_data[data]["Open Nuget"]
        org_data["Open Maven"] += parsed_data[data]["Open Maven"]
        org_data["Open Composer"] += parsed_data[data]["Open Composer"]
        org_data["Open Rust"] += parsed_data[data]["Open Rust"]
        org_data["Open Unknown"] += parsed_data[data]["Open Unknown"]

    org_data["Open Total"] = (
        org_data["Open Crit"]
        + org_data["Open High"]
        + org_data["Open Med"]
        + org_data["Open Low"]
    )

    return org_data


def write_org_csv_data(data):

    header = data.keys()
    org_data_dir = "./org_data/"
    org_data_csv = "org_data.csv"

    if not Path(org_data_dir).exists():
        Path(org_data_dir).mkdir(exist_ok=True)

    with open(
        f"{org_data_dir}{org_data_csv}-{time_stamp}", "w"
    ) as org_data_file:
        writer = csv.DictWriter(org_data_file, fieldnames=header)
        writer.writeheader()
        writer.writerow(data)

    print()
    print(f"Org data written to {org_data_dir}{org_data_csv}-{time_stamp}")


def write_csv_data(data):

    header = data[0].keys()
    parsed_data_dir = "./data/"
    parsed_data_csv = "parsed_data.csv"

    if not Path(parsed_data_dir).exists():
        Path(parsed_data_dir).mkdir(exist_ok=True)

    with open(
        f"{parsed_data_dir}{parsed_data_csv}-{time_stamp}", "w"
    ) as parsed_data_file:
        writer = csv.DictWriter(parsed_data_file, fieldnames=header)
        writer.writeheader()
        writer.writerows(data)

    print()
    print(
        f"Repo CSV data written to {parsed_data_dir}{parsed_data_csv}-{time_stamp}"
    )


def write_txt_data(sorted_data):

    parsed_data_dir = "./data/"
    parsed_data_txt = "parsed_data.txt"

    if not Path(parsed_data_dir).exists():
        Path(parsed_data_dir).mkdir(exist_ok=True)

    with open(
        f"{parsed_data_dir}{parsed_data_txt}-{time_stamp}", "w"
    ) as parsed_data_file:
        pp = pprint.PrettyPrinter(
            depth=4, sort_dicts=False, stream=parsed_data_file
        )
        pp.pprint(sorted_data)

    print()
    print(
        f"Text file of all dependabot repos written to {parsed_data_dir}{parsed_data_txt}-{time_stamp}"
    )


def add_text_data(info):
    """Create code block to send to slack channel.

    Args:
        info: dictionary of information to be displayed

    Returns:
        repo_text: text block to send to slack
    """

    repo_text = f"```"
    repo_text += f'{info["Name"]}\t\t\t\t{"Number of alerts exceeding SLO".rjust(1)}\n\n'
    repo_text += f'{"Critical"}\t\t\t{str(info["Open Crit"])}\t\t\t{str(info["Crit Exceeded"])+" ("+str(info["Crit Percentage"])+"%)"}\n'
    repo_text += f'{"High"}\t\t\t\t{str(info["Open High"])}\t\t\t{str(info["High Exceeded"])+" ("+str(info["High Percentage"])+"%)"}\n'
    repo_text += f'{"Medium"}  \t\t\t{str(info["Open Med"])}\t\t\t{str(info["Med Exceeded"])+" ("+str(info["Med Percentage"])+"%)"}\n'
    repo_text += f'{"Low"} \t\t\t\t{str(info["Open Low"])}\t\t\t{str(info["Low Exceeded"])+" ("+str(info["Low Percentage"])+"%)"}\n\n'
    repo_text += f'{"Total Open"}   \t\t{str(info["Open Total"])}\n'
    repo_text += f"```"
    repo_text += f"\n"

    return repo_text


def add_text_org_data(info):
    """Create code block to send to slack channel.
    This function is slightly different from add_text_data function,
    as this is organization information, consquently has a different format.

    Args:
        info: dictionary of information to be displayed

    Returns:
        repo_text: text block to send to slack
    """

    repo_text = f"```"
    repo_text += f'{"Active"} {org} {"Github Repositories"}\t\t{str(current_time.strftime("%Y-%m-%d %H:%M:%S"))}\n\n'
    repo_text += f'{"Critical"}\t\t\t{str(info["Open Crit"])}\n'
    repo_text += f'{"High"}\t\t\t\t{str(info["Open High"])}\n'
    repo_text += f'{"Medium"}  \t\t\t{str(info["Open Med"])}\n'
    repo_text += f'{"Low"}  \t\t\t\t{str(info["Open Low"])}\n\n'
    repo_text += f'{"Total Open"}  \t\t{str(info["Open Total"])}\n'
    repo_text += f"```"
    repo_text += f"\n"

    return repo_text


def send_to_slack(text, text_type):
    """Final http request & message to send to slack to display in
    the appropriate channel via Operating System Environment variable SLACK_URL

    Args:
        text_type: data type - determines header value of the output

    Returns:
        Null

    """
    headertext = ""
    if text_type == "repo_data":
        headertext = "Top Five Repos - Dependabot Alerts Severity"
    elif text_type == "org_data":
        headertext = "All Dependabot Alerts"

    http = urllib3.PoolManager()
    repo_data = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": headertext,
                    # "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": text,
                },
            },
            {"type": "divider"},
        ]
    }

    r = http.request(
        "POST",
        slack_webhook,
        body=json.dumps(repo_data),
        headers={"Content-type": "application/json"},
    )
    # print(r.status)


def main():

    parsed_data = []
    non_archived, archived = get_repo_list()

    (
        repos_no_vulns,
        repos_with_vulns,
        repos_disabled,
        no_vulns_json_data,
        disabled_json_data,
        vulns_json_data,
    ) = get_dependabot_alerts(non_archived)

    # create object for every repo with respective alert information
    for repo in range(len(vulns_json_data)):
        repo = Repo(repos_with_vulns[repo], vulns_json_data[repo])
        parsed_data.append(repo.parsed_data)

    # sort rows based on "priority" column
    sorted_data = sorted(
        parsed_data, key=lambda d: d["Priority"], reverse=True
    )

    org_data = get_org_data(
        repos_no_vulns, repos_with_vulns, repos_disabled, sorted_data
    )

    # report top five 'worst' repos only, change NUM_REPOS_REPORT as required
    # send to slack channel by default, else write to local disk
    if local_save is False:
        if len(sorted_data) >= 5:
            NUM_REPOS_REPORT = 5
        else:
            NUM_REPOS_REPORT = len(sorted_data)

        text = ""
        for number in range(NUM_REPOS_REPORT):
            text += add_text_data(sorted_data[number])
        text_type = "repo_data"
        send_to_slack(text, text_type)

        text_type = "org_data"
        text = add_text_org_data(org_data)
        send_to_slack(text, text_type)
    else:
        write_csv_data(sorted_data)
        write_txt_data(sorted_data)
        write_org_csv_data(org_data)
        JSON_OUTPUT_FOLDER = "./json_output/"
        print()
        print(f"Saving JSON dependabot data to {JSON_OUTPUT_FOLDER}")

        if not Path(JSON_OUTPUT_FOLDER).exists():
            Path(JSON_OUTPUT_FOLDER).mkdir(exist_ok=True)

        for repo in range(len(vulns_json_data)):
            json_object = json.dumps(vulns_json_data, indent=4)
            with open(
                f"{JSON_OUTPUT_FOLDER}{repos_with_vulns[repo]}.json", "w"
            ) as output_file:
                output_file.write(json_object)

        for repo in range(len(no_vulns_json_data)):
            json_object = json.dumps(no_vulns_json_data, indent=4)
            with open(
                f"{JSON_OUTPUT_FOLDER}{repos_no_vulns[repo]}.json", "w"
            ) as output_file:
                output_file.write(json_object)

        for repo in range(len(disabled_json_data)):
            json_object = json.dumps(disabled_json_data, indent=4)
            with open(
                f"{JSON_OUTPUT_FOLDER}{repos_disabled[repo]}.json", "w"
            ) as output_file:
                output_file.write(json_object)


if __name__ == "__main__":

    local_save = False
    current_time = datetime.now()
    time_stamp = current_time.strftime("%Y-%m-%d-T%H-%M")

    try:
        apikey = os.environ["GH_API_KEY"]
        auth = "Bearer " + apikey
    except KeyError:
        print("GH_API_KEY environment variable not set")
        print("Please set the Github API via environment variable.")
        print("Eg: export GH_API_KEY=ghp_XXXXXXXXX")
        sys.exit(1)

    try:
        org = os.environ["GH_ORG"]
    except KeyError:
        print("GH_ORG environment variable not set")
        print("Please set the Github Organization via environment variable.")
        print("Eg: export GH_ORG=google")
        sys.exit(1)

    # require SLACK_URL (webhook) if not writing to local disk -
    # default is to send to slack
    if len(sys.argv) == 2 and sys.argv[1] == "local":
        local_save = True
        print("Saving data to local disk")
        print()
    else:
        try:
            slack_webhook = os.environ["SLACK_URL"]
        except KeyError:
            print("SLACK_URL environment variable not set")
            print("Please set the SLACK_URL via environment variable.")
            print("Eg: export SLACK_URL=https://hooks.slack.com/services/XXX")
            sys.exit(1)

    main()
