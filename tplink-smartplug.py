#!/usr/bin/env python
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
import socket
import argparse
#import json
import time

version = 0.1

# Check if IP is valid
def validIP(ip):
        try:
                socket.inet_pton(socket.AF_INET, ip)
        except socket.error:
                parser.error("Invalid IP Address.")
        return ip

# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
#### spankywetfish : Added 'synctime' command to sync time with local system (location index 39=UK) ####
commands = {'info'     : '{"system":{"get_sysinfo":{}}}',
                        'on'       : '{"system":{"set_relay_state":{"state":1}}}',
                        'off'      : '{"system":{"set_relay_state":{"state":0}}}',
                        'cloudinfo': '{"cnCloud":{"get_info":{}}}',
                        'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
                        'time'     : '{"time":{"get_time":{}}}',
                        'synctime' : time.strftime('{"time":{"set_timezone":{"year":%Y,"month":%m,"mday":%d,"wday":%w,"hour":%H,"min":%M,"sec":%S,"index":39}}}'),
                        'schedule' : '{"schedule":{"get_rules":{}}}',
                        'countdown': '{"count_down":{"get_rules":{}}}',
                        'antitheft': '{"anti_theft":{"get_rules":{}}}',
                        'reboot'   : '{"system":{"reboot":{"delay":1}}}',
                        'reset'    : '{"system":{"reset":{"delay":1}}}'
}

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
        key = 171
        result = "\0\0\0\0"
        for i in string:
                a = key ^ ord(i)
                key = a
                result += chr(a)
        return result

def decrypt(string):
        key = 171
        result = ""
        for i in string:
                a = key ^ ord(i)
                key = ord(i)
                result += chr(a)
        return result

# Parse commandline arguments
#### spankywetfish : Added -n switch to allow hostname use instead of IP address ####
parser = argparse.ArgumentParser(description="TP-Link Wi-Fi Smart Plug Client v" + str(version))
hostgoup = parser.add_mutually_exclusive_group(required=True)
hostgoup.add_argument("-t", "--target", metavar="<ip>", help="Target IP Address", type=validIP)
hostgoup.add_argument("-n", "--name", metavar="<hostname>", help="Target Hostname")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(commands), choices=commands)
group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")
args = parser.parse_args()

# Set target IP, port and command to send
if args.target is None:
        ip = args.name
else:
        ip = args.target
port = 9999
if args.command is None:
        cmd = args.json
else:
        cmd = commands[args.command]



# Send command and receive reply
try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.connect((ip, port))
        sock_tcp.send(encrypt(cmd))
        data = sock_tcp.recv(2048)
        sock_tcp.close()

#        print "\nSent_enc        : ", encrypt(cmd)
        print "\nSent            : ", cmd
#        print "\nReceived_enc    : ", data
#        print "\nReceived_enc    : ", data[4:]
        print "\nReceived        : ", decrypt(data[4:])
#        print "\nReceived        : ", json.stringify(decrypt(data[4:]), indent=4, sort_keys=True)
except socket.error:
        quit("Cound not connect to host " + ip + ":" + str(port))



