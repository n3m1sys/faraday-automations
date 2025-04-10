#!/usr/bin/env python3
import os
import sys
import argparse
import json


def check_faraday_cli():
    if os.system("which faraday-cli > /dev/null 2>&1") != 0:
        print("Error: Faraday CLI is not installed. Please install it and try again.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Run nmap scans.")
    parser.add_argument("-w", "--workspace", required=True, help="Faraday workspace name")
    parser.add_argument("-l", "--list", required=True, help="List of hosts to upload")
    parser.add_argument("-d", "--description", required=False, help="Description for the hosts")
    args = parser.parse_args()
    workspace = args.workspace
    description = args.description
    list_file = args.list
    data = []
    for host in open(list_file):
        data.append({
            "ip": host.strip(),
            "description": description,
        })
    print(f"Uploading {len(data)} hosts to Faraday workspace {workspace}...")
    os.system(f"echo '{json.dumps(data)}' | faraday-cli host create -w {workspace} --stdin")
    print(f"Hosts uploaded to Faraday workspace {workspace}.")
        

if __name__ == "__main__":
    main()