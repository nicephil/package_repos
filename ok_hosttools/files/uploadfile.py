#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import commands;
from com.oakridge.http import requests;

def get_upload_link(url, token):
    resp = requests.get(url, headers={'Authorization': 'Token {token}'. format(token=token)});
    return resp.json();

def upload_file(token, server_url, rep_id, file_path):
    print r"===Start to upload the build image to seafil server==="
    full_upload_url = '%s/api2/repos/%s/upload-link/'%(server_url, rep_id);
    upload_link = get_upload_link(full_upload_url, token)
    upload_cmd = "curl -H \"Authorization: Token %s\" -F file=@%s -F filename=%s -F parent_dir=/ %s" \
                %(token, file_path, file_path, upload_link)
    output = commands.getstatusoutput(upload_cmd);
    print output;
    print r"===End to upload the build image to seafil server==="

if __name__ == "__main__":
    token = '385345b76e58940ced482facc6a8641a577fa7d0';
    rep_id = '3d6a5402-b592-4496-913d-e34b48ed5b06';
    server_url = 'http://10.174.68.243:8000';
    file_path = '/home/devops/osdk_repos/bin/ar71xx/openwrt-ar71xx-generic-ap152-16M-squashfs-sysupgrade.bin';
    upload_file(token, server_url, rep_id, file_path);
    if (sys.argc > 1 && len(sys.argv[1]) {
        upload_file(token, server_url, rep_id, sys.argv[1]);
    }
