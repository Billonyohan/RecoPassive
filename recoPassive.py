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


def whois(domain, sys_args, len_sys_args, domain_split, arguments):
    if arguments.lower() == "y":
        print("Whois in progress .....")
        os.system('whois '+domain+' -H > '+directory_domain+'/whois_'+domain_split+'.txt')
    elif arguments.lower() == "n":
        new_arguments = input(f"{bcolors.LightBlue}\nPlease enter your options for Whois (-h or --help for show the options): {bcolors.LightGreen}")
        if new_arguments == "-h" or new_arguments == "--help":
            print("""
Usage: whois [OPTION]... OBJECT...

-h HOST, --host HOST   connect to server HOST
-p PORT, --port PORT   connect to PORT
-I                     query whois.iana.org and follow its referral
-H                     hide legal disclaimers
      --verbose        explain what is being done
      --help           display this help and exit
      --version        output version information and exit

These flags are supported by whois.ripe.net and some RIPE-like servers:
-l                     find the one level less specific match
-L                     find all levels less specific matches
-m                     find all one level more specific matches
-M                     find all levels of more specific matches
-c                     find the smallest match containing a mnt-irt attribute
-x                     exact match
-b                     return brief IP address ranges with abuse contact
-B                     turn off object filtering (show email addresses)
-G                     turn off grouping of associated objects
-d                     return DNS reverse delegation objects too
-i ATTR[,ATTR]...      do an inverse look-up for specified ATTRibutes
-T TYPE[,TYPE]...      only look for objects of TYPE
-K                     only primary keys are returned
-r                     turn off recursive look-ups for contact information
-R                     force to show local copy of the domain object even
                       if it contains referral
-a                     also search all the mirrored databases
-s SOURCE[,SOURCE]...  search the database mirrored from SOURCE
-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST
-t TYPE                request template for object of TYPE
-v TYPE                request verbose template for object of TYPE
-q [version|sources|types]  query specified server info

                """)
            whois(domain, sys_args, len_sys_args, domain_split, arguments)
        elif len(new_arguments) >= 1:
            print("Whois in progress .....")
            os.system('whois '+domain+' '+new_arguments+' > '+directory_domain+'/whois_'+domain_split+'.txt')
        else:
            print("Bad arguments, Try again !")
            whois(domain, sys_args, len_sys_args, domain_split, arguments)
    if len_sys_args >= 1:
        print("Whois Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)
    else:
        print("Whois Done !")
        print(f"{bcolors.Red}Operation End")


def dig(domain, sys_args, len_sys_args, domain_split, arguments):
    if arguments.lower() == "y":
        print("Dig in progress .....")
        os.system('dig '+domain+' any @8.8.8.8 > '+directory_domain+'/dig_'+domain_split+'.txt')
    elif arguments.lower() == "n":
        new_arguments = input(f"{bcolors.LightBlue}\nPlease enter your options for Dig (-h or --help for show the options): {bcolors.LightGreen}")
        if new_arguments == "-h" or new_arguments == "--help":
            print("""
Where:  domain    is in the Domain Name System
        q-class  is one of (in,hs,ch,...) [default: in]
        q-type   is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...) [default:a]
                 (Use ixfr=version for type ixfr)
        q-opt    is one of:
                 -4                  (use IPv4 query transport only)
                 -6                  (use IPv6 query transport only)
                 -b address[#port]   (bind to source address/port)
                 -c class            (specify query class)
                 -f filename         (batch mode)
                 -k keyfile          (specify tsig key file)
                 -m                  (enable memory usage debugging)
                 -p port             (specify port number)
                 -q name             (specify query name)
                 -r                  (do not read ~/.digrc)
                 -t type             (specify query type)
                 -u                  (display times in usec instead of msec)
                 -x dot-notation     (shortcut for reverse lookups)
                 -y [hmac:]name:key  (specify named base64 tsig key)
        d-opt    is of the form +keyword[=value], where keyword is:
                 +[no]aaflag         (Set AA flag in query (+[no]aaflag))
                 +[no]aaonly         (Set AA flag in query (+[no]aaflag))
                 +[no]additional     (Control display of additional section)
                 +[no]adflag         (Set AD flag in query (default on))
                 +[no]all            (Set or clear all display flags)
                 +[no]answer         (Control display of answer section)
                 +[no]authority      (Control display of authority section)
                 +[no]badcookie      (Retry BADCOOKIE responses)
                 +[no]besteffort     (Try to parse even illegal messages)
                 +bufsize[=###]      (Set EDNS0 Max UDP packet size)
                 +[no]cdflag         (Set checking disabled flag in query)
                 +[no]class          (Control display of class in records)
                 +[no]cmd            (Control display of command line -
                                      global option)
                 +[no]comments       (Control display of packet header
                                      and section name comments)
                 +[no]cookie         (Add a COOKIE option to the request)
                 +[no]crypto         (Control display of cryptographic
                                      fields in records)
                 +[no]defname        (Use search list (+[no]search))
                 +[no]dnssec         (Request DNSSEC records)
                 +domain=###         (Set default domainname)
                 +[no]dscp[=###]     (Set the DSCP value to ### [0..63])
                 +[no]edns[=###]     (Set EDNS version) [0]
                 +ednsflags=###      (Set EDNS flag bits)
                 +[no]ednsnegotiation (Set EDNS version negotiation)
                 +ednsopt=###[:value] (Send specified EDNS option)
                 +noednsopt          (Clear list of +ednsopt options)
                 +[no]expandaaaa     (Expand AAAA records)
                 +[no]expire         (Request time to expire)
                 +[no]fail           (Don't try next server on SERVFAIL)
                 +[no]header-only    (Send query without a question section)
                 +[no]identify       (ID responders in short answers)
                 +[no]idnin          (Parse IDN names [default=on on tty])
                 +[no]idnout         (Convert IDN response [default=on on tty])
                 +[no]ignore         (Don't revert to TCP for TC responses.)
                 +[no]keepalive      (Request EDNS TCP keepalive)
                 +[no]keepopen       (Keep the TCP socket open between queries)
                 +[no]mapped         (Allow mapped IPv4 over IPv6)
                 +[no]multiline      (Print records in an expanded format)
                 +ndots=###          (Set search NDOTS value)
                 +[no]nsid           (Request Name Server ID)
                 +[no]nssearch       (Search all authoritative nameservers)
                 +[no]onesoa         (AXFR prints only one soa record)
                 +[no]opcode=###     (Set the opcode of the request)
                 +padding=###        (Set padding block size [0])
                 +[no]qr             (Print question before sending)
                 +[no]question       (Control display of question section)
                 +[no]raflag         (Set RA flag in query (+[no]raflag))
                 +[no]rdflag         (Recursive mode (+[no]recurse))
                 +[no]recurse        (Recursive mode (+[no]rdflag))
                 +retry=###          (Set number of UDP retries) [2]
                 +[no]rrcomments     (Control display of per-record comments)
                 +[no]search         (Set whether to use searchlist)
                 +[no]short          (Display nothing except short
                                      form of answers - global option)
                 +[no]showsearch     (Search with intermediate results)
                 +[no]split=##       (Split hex/base64 fields into chunks)
                 +[no]stats          (Control display of statistics)
                 +subnet=addr        (Set edns-client-subnet option)
                 +[no]tcflag         (Set TC flag in query (+[no]tcflag))
                 +[no]tcp            (TCP mode (+[no]vc))
                 +timeout=###        (Set query timeout) [5]
                 +[no]trace          (Trace delegation down from root [+dnssec])
                 +tries=###          (Set number of UDP attempts) [3]
                 +[no]ttlid          (Control display of ttls in records)
                 +[no]ttlunits       (Display TTLs in human-readable units)
                 +[no]unexpected     (Print replies from unexpected sources
                                      default=off)
                 +[no]unknownformat  (Print RDATA in RFC 3597 "unknown" format)
                 +[no]vc             (TCP mode (+[no]tcp))
                 +[no]yaml           (Present the results as YAML)
                 +[no]zflag          (Set Z flag in query)
        global d-opts and servers (before host name) affect all queries.
        local d-opts and servers (after host name) affect only that lookup.
        -h                           (print help and exit)
        -v                           (print version and exit)

                """)
            dig(domain, sys_args, len_sys_args, domain_split, arguments)

        elif len(new_arguments) >= 1:
            print("Dig in progress .....")
            os.system('dig '+domain+' any @8.8.8.8 '+new_arguments+'> '+directory_domain+'/dig_'+domain_split+'.txt')
        else:
            print("Bad arguments, Try again !")
            dig(domain, sys_args, len_sys_args, domain_split, arguments)
    if len_sys_args >= 1:
        print("Dig Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)
    else:
        print("Dig Done !")
        print(f"{bcolors.Red}Operation End")


def host(domain, sys_args, len_sys_args, domain_split):
    print("Host in progress .....")
    os.system('host '+domain+' > '+directory_domain+'/host_'+domain_split+'.txt')
    if len_sys_args >= 1:
        print("Host Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print("Host Done !")
        print(f"{bcolors.Red}Operation End")


def the_harvester(domain, sys_args, len_sys_args, domain_split):
    print("TheHarvester in progress .....")
    print("TheHarvester take some time .....")
    os.system('theHarvester -d '+domain+' -b all > '+directory_domain+'/theHarvester_'+domain_split+'.txt')
    if len_sys_args >= 1:
        print("TheHarvester Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print("TheHarvester Done !")
        print(f"{bcolors.Red}Operation End")


def nslookup(domain, sys_args, len_sys_args, domain_split):
    print("Nslookup in progress .....")
    os.system('nslookup '+domain+' > '+directory_domain+'/nslookup_'+domain_split+'.txt')
    if len_sys_args >= 1:
        print("Nslookup Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print("Nslookup Done !")
        print(f"{bcolors.Red}Operation End")


def dnsenum(domain, sys_args, len_sys_args, domain_split):
    print("Dnsenum in progress .....")
    os.system('dnsenum --noreverse '+domain+' > '+directory_domain+'/dnsenum_'+domain_split+'.txt')
    os.system('mv '+current_directory+'/'+domain+'_ips.txt '+directory_domain+'/'+domain_split+'_ips.txt')
    if len_sys_args >= 1:
        print("Dnsenum Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split)
    else:
        print("Dnsenum Done !")
        print(f"{bcolors.Red}Operation End")


def chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments):
    try:
        if len_sys_args >= 1:
            for i in range(len_sys_args):
                if "1" in sys_args:
                    sys_args.remove("1")
                    len_sys_args -= 1
                    whois(domain, sys_args, len_sys_args, domain_split, arguments)

                elif "2" in sys_args:
                    sys_args.remove("2")
                    len_sys_args -= 1
                    dig(domain, sys_args, len_sys_args, domain_split, arguments)

                elif "3" in sys_args:
                    sys_args.remove("3")
                    len_sys_args -= 1
                    host(domain, sys_args, len_sys_args, domain_split, arguments)

                elif "4" in sys_args:
                    sys_args.remove("4")
                    len_sys_args -= 1
                    the_harvester(domain, sys_args, len_sys_args, domain_split, arguments)

                elif "5" in sys_args:
                    sys_args.remove("5")
                    len_sys_args -= 1
                    nslookup(domain, sys_args, len_sys_args, domain_split, arguments)

                elif "6" in sys_args:
                    sys_args.remove("6")
                    len_sys_args -= 1
                    dnsenum(domain, sys_args, len_sys_args, domain_split, arguments)

    except:
        print(f"""{bcolors.LightBlue}\nUse the following arguments (If you want to launch several applications add up the number of commands ):

    example : Dig & Nslookup = RecoPassive.py 2 5

    1   Whois
    2   Dig
    3   Host
    4   TheHarvester
    5   Nslookup
    6   Dnsenum

            """)
        print(f"{bcolors.White}{bcolors.BackgroundBlack}{bcolors.Bold}Use the option -h or --help for more information")
        sys.exit()


if __name__ == '__main__':
    sys_nbArgs = sys.argv
    sys_args = sys_nbArgs[1:]
    len_sys_args = len(sys_args)
    if len(sys_nbArgs) == 1:
        print(f"{bcolors.Blue}\nPlease add an arguments or use the option -h for help\n")
    elif sys_args[0] == "-h" or sys_args[0] == "--help":
        print(f"""{bcolors.LightBlue}
    *********************************
    *                               *
    *     RecoPassive 1.0           *
    *     Coded by Billon Yohan     *
    *                               *
    *********************************
            """)
        print(f"{bcolors.Blue}      *********", f"{bcolors.White}*********", f"{bcolors.Red}*********")
        print(f"{bcolors.Blue}      *********", f"{bcolors.White}*********", f"{bcolors.Red}*********")
        print(f"{bcolors.Blue}      *********", f"{bcolors.White}*********", f"{bcolors.Red}*********")
        print(f"{bcolors.Blue}      *********", f"{bcolors.White}*********", f"{bcolors.Red}*********")
        print(f"{bcolors.Blue}      *********", f"{bcolors.White}*********", f"{bcolors.Red}*********")
        print(f"{bcolors.Blue}      *********", f"{bcolors.White}*********", f"{bcolors.Red}*********")
        print(f"{bcolors.Blue}      *********", f"{bcolors.White}*********", f"{bcolors.Red}*********\n{bcolors.ENDC}")
        print(f"""{bcolors.LightBlue}   RecoPassive is used to gather data.


    Usage : RecoPassive.py [Args]

    If you want to launch several applications add up the number of commands :

    1   Whois
    2   Dig
    3   Host
    4   TheHarvester
    5   Nslookup
    6   Dnsenum

    example : Dig & Nslookup = RecoPassive.py 2 5
              TheHarvester & Whois = RecoPassive.py 1 4


            """)
        sys.exit()
    else:
        domain = input(f"{bcolors.LightBlue}\nPlease enter a domain name (example: google.com) : ")
        arguments = input(f"{bcolors.LightBlue}\nDo you want to use the default arguments ? (Y/n): ")
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
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)

