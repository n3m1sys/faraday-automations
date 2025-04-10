#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys 
import argparse
import json


def check_nmap_installed():
    if os.system("which nmap > /dev/null 2>&1") != 0:
        print("Error: nmap is not installed. Please install it and try again.")
        sys.exit(1)


def check_faraday_cli():
    if os.system("which faraday-cli > /dev/null 2>&1") != 0:
        print("Error: Faraday CLI is not installed. Please install it and try again.")
        sys.exit(1)

def get_hosts_from_workspace(workspace):
    r = []
    try:
        command = f"faraday-cli host list -w {workspace} -j"
        result = os.popen(command).read()
        result = json.loads(result)
        for host in result:
            host_data = {}
            try:
                value = host['value']
                ip = value['name']
                service_sumaries = value['service_summaries']
                host_data['ip'] = ip
                host_data['tcp'] = []
                host_data['udp'] = []
                for service in service_sumaries:
                    protocol = service.split('/')[1].split(')')[0].strip()
                    port = int(service.split('(')[1].split('/')[0].strip())
                    if protocol in ['tcp', 'udp']:
                        host_data[protocol].append(port)
                    else:
                        print(f"Unknown protocol: {protocol}")
                r.append(host_data)
            except KeyError as e:
                print(f"KeyError: {e} in host data: {host}")
                continue
            except ValueError as e:
                print(f"ValueError: {e} in host data: {host}")
                continue
    except Exception as e:
        print(f"Error retrieving hosts from workspace: {e}")
        sys.exit(1)
    return r


def run_nmap_scan(host, tcp_ports, udp_ports, workspace, output_dir):
    if not tcp_ports and not udp_ports:
        print(f"No TCP or UDP ports found for host {host}. Skipping scan.")
        return
    if tcp_ports:
        tcp_ports_str = ','.join(map(str, tcp_ports))
        print(f"Running TCP scan on host {host} for ports: {tcp_ports_str}")
        output_file = f"{output_dir}nmap_{workspace}_{host}_tcp.xml"
        nmap_command = f"nmap -sT -sCV --script vuln -p {tcp_ports_str} -oX {output_file} {host} --privileged"
        upload_command = f"faraday-cli tool report -w {workspace} {output_file}"
        os.system(nmap_command)
        os.system(upload_command)
    if udp_ports:
        udp_ports_str = ','.join(map(str, udp_ports))
        print(f"Running UDP scan on host {host} for ports: {udp_ports_str}")
        output_file = f"{output_dir}nmap_{workspace}_{host}_udp.xml"
        nmap_command = f"nmap -sT -sCV --script vuln -p {udp_ports_str} -oX {output_file} {host} --privileged"
        upload_command = f"faraday-cli tool report -w {workspace} {output_file}"
        os.system(nmap_command)
        os.system(upload_command)
    print(f"Scan completed for host {host}. Results uploaded to Faraday.")
           
    
def main():
    check_nmap_installed()
    check_faraday_cli()
    parser = argparse.ArgumentParser(description="Run nmap scans.")
    parser.add_argument("-w", "--workspace", required=True, help="Faraday workspace name")
    parser.add_argument("-o", "--output", required=True, help="Output file name", default="/tmp/")
    args = parser.parse_args()
    workspace = args.workspace
    output_dir = args.output
    if not output_dir.endswith('/'):
        output_dir += '/'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.access(output_dir, os.W_OK):
        print(f"Error: Output directory {output_dir} is not writable.")
        sys.exit(1)
    print(f"Running scans for workspace: {workspace}")
    print(f"Output directory: {output_dir}")
    print("Fetching hosts from Faraday...")
    hosts = get_hosts_from_workspace(workspace)
    if not hosts:
        print("No hosts found in the specified workspace.")
        sys.exit(1)
    print(f"Found {len(hosts)} hosts in workspace {workspace}.")
    print("Starting scans...")
    for host in hosts:
        run_nmap_scan(host['ip'], host['tcp'], host['udp'], workspace, output_dir=output_dir)
    print("All scans completed.")
    


if __name__ == "__main__":
    main()