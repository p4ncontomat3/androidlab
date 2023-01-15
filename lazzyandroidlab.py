#!/usr/bin/python3
import subprocess
import requests
import json
import lzma
import sys
import os

def push_file_adb(file_path, device_path):
    try:
        subprocess.check_call(["adb", "push", file_path, device_path])
        print("[+] File successfully pushed to device")
    except subprocess.CalledProcessError as e:
        return "Error occured while pushing the file: ", e

def change_permission(device_path, permission):
    print("[+] Permission", permission, "to file", device_path)
    subprocess.check_call(["adb", "shell", "chmod", permission, device_path])
    return "Execution permission successfully given to the file"

def decompress_xz(filename):
    
    # Define the input and output file names
    input_file = filename
    output_file = filename.split(".")[0]
    print("[+] Uncompressing", input_file, "as outfile:", output_file)

    # Open the input file in binary mode
    with lzma.open(input_file, "rb") as f_in:
        # Open the output file in binary mode
        with open(output_file, "wb") as f_out:
            # Copy the data from the input file to the output file
            f_out.write(f_in.read())

def check_frida_server():

    # Check if Frida server exists in the /data/local/tmp/ directory
    output = subprocess.run(["adb", "shell", "ls", "-l", "/data/local/tmp/frida-server*"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    if output.returncode == 0:
        # Frida server exists
        print("[+] Frida server exists in /data/local/tmp/")
        # Get the version of Frida server
        version = subprocess.check_output(["adb", "shell", "/data/local/tmp/frida-server", "--version"])
        version = version.strip().split()[-1].decode("utf-8")
        print("[*] Frida Server version:", version)
    else:
        # Frida server does not exist
        print("[-] Frida server does not exist in /data/local/tmp/")
        print("[+] Downloading latest frida server for android x86")
        download_frida_server()

def download_frida_server():
    # Get the latest version of Frida server for Android x86 from GitHub
    print("[+] Looking for latest Frida version")
    response = requests.get("https://api.github.com/repos/frida/frida/releases/latest")
    latest_release = json.loads(response.text)

    # Extract the version number from the release tag
    version = latest_release["tag_name"]
    print("[+] Latest version:",version)
    frida_server_version = "frida-server-%s-android-x86" % (version)

    # Get the download URL for the Android x86 version of Frida server
    asset = next(a for a in latest_release["assets"] if frida_server_version in a["name"] )
    download_url = asset["browser_download_url"]

    print("[+] Downloading as frida-server.xz")
    # Download the Frida server to the current directory
    response = requests.get(download_url, stream=True)
    with open("frida-server.xz", "wb") as f:
        for chunk in response.iter_content(1024):
            f.write(chunk)

    decompress_xz("frida-server.xz")
    push_file_adb("frida-server","/data/local/tmp/")
    change_permission("/data/local/tmp/frida-server","+x")

def check_and_update_frida():
    try:
        import frida
    except ImportError:
        print("[-] Frida not installed")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "frida"])
        print("[+] Frida installed successfully")
    else:
        current_version = frida.__version__
        latest_version = subprocess.check_output([sys.executable, "-m", "pip", "show", "frida"]).decode().split("\n")[1].split(" ")[1]
        if current_version != latest_version:
            print("[-] Frida version outdated")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "frida"])
            print("[+] Frida updated successfully")
        else:
            print("[+] Frida is already the latest version")

def push_cacert(cacert_file):
    #Convert DER to PEM
    subprocess.check_call(["openssl", "x509", "-inform", "DER", "-in", cacert_file, "-out", "cacert.pem"])
    #Hash the PEM file
    hash_output = subprocess.check_output(["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", "cacert.pem"])
    #Extract hash value
    file_hash = hash_output.splitlines()[0].decode()
    #Rename the PEM file
    os.rename("cacert.pem", file_hash + ".0")
    #Check if cacert is in cacerts
    cert_path = "/system/etc/security/cacerts/" + file_hash +".0"
    output = subprocess.run(["adb", "shell", "ls", "-l", cert_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    if output.returncode == 0:
        # Cacert exists
        print("[+] Cacert exists in  /system/etc/security/cacerts/")
    else:
        # Cacert does not exist
        #Remount the system partition as read-write
        subprocess.check_call(["adb", "shell", "mount", "-o", "rw,remount", "/system"])
        #Push the file to the device
        subprocess.check_call(["adb", "push", file_hash + ".0", "/system/etc/security/cacerts/"])
        filename = "/system/etc/security/cacerts/" + file_hash + ".0"
        change_permission(filename,"644")
        print("[+] Burp cacert.der converted and pushed successfully")

def print_banner():
    banner ='''
 _                        
| |    __ _ _________   _ 
| |   / _` |_  /_  / | | |
| |__| (_| |/ / / /| |_| |
|_____\__,_/___/___|\__, |
                    |___/ 
    _              _           _     _ _          _     
   / \   _ __   __| |_ __ ___ (_) __| | |    __ _| |__  
  / _ \ | '_ \ / _` | '__/ _ \| |/ _` | |   / _` | '_ \ 
 / ___ \| | | | (_| | | | (_) | | (_| | |__| (_| | |_) |
/_/   \_\_| |_|\__,_|_|  \___/|_|\__,_|_____\__,_|_.__/ 

    '''

    print(banner)
    print("\t\t\t\t\tby @p4ncontomat3")

print_banner()
check_and_update_frida()
check_frida_server()
push_cacert("cacert.der")


print("[+] All seems to be right, happy hacking <3")