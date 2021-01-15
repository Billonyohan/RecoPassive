#!/usr/bin/python3
from scapy.all import sys
import os
from os import path


class bcolors:
    Red = "\033[31m"
    Green = "\033[32m"
    Yellow = "\033[33m"
    Blue = "\033[34m"
    Magenta = "\033[35m"
    Cyan = "\033[36m"
    LightGray = "\033[37m"
    DarkGray = "\033[90m"
    LightRed = "\033[91m"
    LightGreen = "\033[92m"
    LightYellow = "\033[93m"
    LightBlue = "\033[94m"
    LightMagenta = "\033[95m"
    LightCyan = "\033[96m"
    BackgroundBlack = "\033[40m"
    White = "\033[97m"
    Bold = "\033[1m"
    Dim = "\033[2m"
    ENDC = '\033[0m'


def the_harvester(domain, sys_args, len_sys_args, domain_split):
    os.system('theHarvester '+domain+' > '+directory_domain+'/theHarvester_'+domain_split[0]+'.txt')
    if len_sys_args >= 1:
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print(f"{bcolors.Red}Operation End")


def dig(domain, sys_args, len_sys_args, domain_split):
    os.system('dig '+domain+' > '+directory_domain+'/dig_'+domain_split[0]+'.txt')
    if len_sys_args >= 1:
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print(f"{bcolors.Red}Operation End")


def host(domain, sys_args, len_sys_args, domain_split):
    os.system('host '+domain+' > '+directory_domain+'/host_'+domain_split[0]+'.txt')
    if len_sys_args >= 1:
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print(f"{bcolors.Red}Operation End")


def whois(domain, sys_args, len_sys_args, domain_split):
    os.system('whois '+domain+' > '+directory_domain+'/whois_'+domain_split[0]+'.txt')
    if len_sys_args >= 1:
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print(f"{bcolors.Red}Operation End")


def nslookup(domain, sys_args, len_sys_args, domain_split):
    os.system('nslookup '+domain+' > '+directory_domain+'/nslookup_'+domain_split[0]+'.txt')
    if len_sys_args >= 1:
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print(f"{bcolors.Red}Operation End")


def recon_ng(domain, sys_args, len_sys_args, domain_split):
    file = open(directory_domain+'/reconNG-'+domain_split, "w")
    command_recon = ('workspaces create '+domain_split[0]+'\n', 'workspaces load '+domain_split[0]+'\n', 'db insert domains\n', domain+'\n',
                    '\n', 'modules load whois_pocs\n', 'run\n', 'modules load google_site_web\n', 'run\n', 'modules load bing_domain_web\n',
                    'run\n', 'modules load certificate_tr\n', 'run\n', 'modules load shodan_ip\n', 'run\n', 'modules load resolve\n', 'run\n',
                    'modules load reporting/html\n', 'options set CREATOR Yohan Billon\n', 'options set CUSTOMER '+domain_split[0]+'\n',
                    'options set FILE domain /root/rapport-'+domain_split[0]+'.html\n', 'run\n')
    file.writelines(command_recon)
    file.close()
    os.system('recon-ng -r '+directory_domain+'/reconNG-'+domain_split+' > '+directory_domain+'/reconNG_'+domain_split[0]+'.txt')
    os.remove(file)
    if len_sys_args >= 1:
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print(f"{bcolors.Red}Operation End")


def chooseOptions(domain, sys_args, len_sys_args, domain_split):
    try:
        if sys_args[0] == "-h" or sys_args[0] == "--help":
            print(f"""{bcolors.LightBlue}
        *********************************
        *                               *
        *     RecoPassive 1.0           *
        *     Coded by Billon Yohan     *
        *                               *
        *********************************
                """)
            print(f"{bcolors.Blue}		*****", f"{bcolors.White}*****", f"{bcolors.Red}*****")
            print(f"{bcolors.Blue}		*****", f"{bcolors.White}*****", f"{bcolors.Red}*****")
            print(f"{bcolors.Blue}		*****", f"{bcolors.White}*****", f"{bcolors.Red}*****")
            print(f"{bcolors.Blue}		*****", f"{bcolors.White}*****", f"{bcolors.Red}*****")
            print(f"{bcolors.Blue}		*****", f"{bcolors.White}*****", f"{bcolors.Red}*****")
            print(f"{bcolors.Blue}		*****", f"{bcolors.White}*****", f"{bcolors.Red}*****")
            print(f"{bcolors.Blue}		*****", f"{bcolors.White}*****", f"{bcolors.Red}*****\n{bcolors.ENDC}")
            print(f"""{bcolors.LightBlue}	RecoPassive is used to gather data.


        Usage : RecoPassive.py [Args]

        If you want to launch several applications add up the number of commands :

        1   TheHarvester
        2   Dig
        3   Host
        4   Whois
        5   Nslookup
        6   Recon-ng

        example : Dig & Nslookup = RecoPassive.py 2 5
              TheHarvester & Whois = RecoPassive.py 1 4


                """)
        elif len_sys_args >= 1:
            for i in range(len_sys_args):
                if "1" in sys_args:
                    sys_args.remove("1")
                    len_sys_args -= 1
                    host(domain, sys_args, len_sys_args, domain_split)

                elif "2" in sys_args:
                    sys_args.remove("2")
                    len_sys_args -= 1
                    host(domain, sys_args, len_sys_args, domain_split)

                elif "3" in sys_args:
                    sys_args.remove("3")
                    len_sys_args -= 1
                    host(domain, sys_args, len_sys_args, domain_split)

                elif "4" in sys_args:
                    sys_args.remove("4")
                    len_sys_args -= 1
                    whois(domain, sys_args, len_sys_args, domain_split)

                elif "5" in sys_args:
                    sys_args.remove("5")
                    len_sys_args -= 1
                    nslookup(domain, sys_args, len_sys_args, domain_split)

                elif "6" in sys_args:
                    sys_args.remove("6")
                    len_sys_args -= 1
                    recon_ng(domain, sys_args, len_sys_args, domain_split)

    except:
        print(f"""{bcolors.LightBlue}\nUse the following arguments (If you want to launch several applications add up the number of commands ):

    example : Dig & Nslookup = RecoPassive.py 2 5

    1   TheHarvester
    2   Dig
    3   Host
    4   Whois
    5   Nslookup
    6   Recon-ng

            """)
        print(f"{bcolors.White}{bcolors.BackgroundBlack}{bcolors.Bold}Use the option -h or --help for more information")
        sys.exit()


if __name__ == '__main__':
    domain = input(f"{bcolors.LightBlue}please enter a domain name (example: google.com) : ")
    domain_split = str(domain.split('.')[0])
    current_directory = os.getcwd()
    directory_result = current_directory + '/Result'
    last_current_directory = current_directory.split("/")
    current_directory_with_result_exist = path.exists(directory_result)
    directory_domain = directory_result + "/" + domain_split
    current_directory_with_domain_exist = path.exists(directory_domain)
    if current_directory_with_result_exist is True:
        if current_directory_with_domain_exist is True:
            print(f"{bcolors.LightGreen}\nRemember that the results are saved in the folder ( Path = "+current_directory+"/Result )\n")
        else:
            os.mkdir(directory_domain)
            print(f"{bcolors.LightGreen}\nRemember that the results are saved in the folder ( Path = "+current_directory+"/Result )\n")
    else:
        os.mkdir(current_directory + "/Result")
        os.mkdir(directory_domain)
        print(f"{bcolors.LightGreen}\nWe have just created a 'Result' folder in which you will find the result ( Path = "+current_directory+"/Result )\n")
    sys_args = sys.argv
    sys_args = sys_args[1:]
    len_sys_args = len(sys_args)
    chooseOptions(domain, sys_args, len_sys_args, domain_split)
