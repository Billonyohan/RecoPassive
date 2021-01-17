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
    new_arguments = ""
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
        print(f"{bcolors.Red}End Operation")


def dig(domain, sys_args, len_sys_args, domain_split, arguments):
    new_arguments = ""
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
            os.system('dig '+domain+' '+new_arguments+'> '+directory_domain+'/dig_'+domain_split+'.txt')
        else:
            print("Bad arguments, Try again !")
            dig(domain, sys_args, len_sys_args, domain_split, arguments)
    if len_sys_args >= 1:
        print("Dig Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)
    else:
        print("Dig Done !")
        print(f"{bcolors.Red}End Operation")


def host(domain, sys_args, len_sys_args, domain_split, arguments):
    new_arguments = ""
    if arguments.lower() == "y":
        print("Host in progress .....")
        os.system('host '+domain+' > '+directory_domain+'/whois_'+domain_split+'.txt')
    elif arguments.lower() == "n":
        new_arguments = input(f"{bcolors.LightBlue}\nPlease enter your options for Host (-h or --help for show the options): {bcolors.LightGreen}")
        if new_arguments == "-h" or new_arguments == "--help":
            print("""
Usage: host [-aCdilrTvVw] [-c class] [-N ndots] [-t type] [-W time]
            [-R number] [-m flag] [-p port] hostname [server]
       -a is equivalent to -v -t ANY
       -A is like -a but omits RRSIG, NSEC, NSEC3
       -c specifies query class for non-IN data
       -C compares SOA records on authoritative nameservers
       -d is equivalent to -v
       -l lists all hosts in a domain, using AXFR
       -m set memory debugging flag (trace|record|usage)
       -N changes the number of dots allowed before root lookup is done
       -p specifies the port on the server to query
       -r disables recursive processing
       -R specifies number of retries for UDP packets
       -s a SERVFAIL response should stop query
       -t specifies the query type
       -T enables TCP/IP mode
       -U enables UDP mode
       -v enables verbose output
       -V print version number and exit
       -w specifies to wait forever for a reply
       -W specifies how long to wait for a reply
       -4 use IPv4 query transport only
       -6 use IPv6 query transport only

                """)
            host(domain, sys_args, len_sys_args, domain_split, arguments)
        elif len(new_arguments) >= 1:
            print("Host in progress .....")
            os.system('host '+domain+' '+new_arguments+' > '+directory_domain+'/host_'+domain_split+'.txt')
        else:
            print("Bad arguments, Try again !")
            host(domain, sys_args, len_sys_args, domain_split, arguments)
    if len_sys_args >= 1:
        print("Host Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)
    else:
        print("Host Done !")
        print(f"{bcolors.Red}End Operation")


def the_harvester(domain, sys_args, len_sys_args, domain_split, arguments):
    new_arguments = ""
    if arguments.lower() == "y":
        print("TheHarvester in progress .....")
        print("TheHarvester take some time .....")
        os.system('theHarvester -d '+domain+' -b all > '+directory_domain+'/theHarvester_'+domain_split+'.txt')
    elif arguments.lower() == "n":
        new_arguments = input(f"{bcolors.LightBlue}\nPlease enter your options for TheHarvester (-h or --help for show the options): {bcolors.LightGreen}")
        if new_arguments == "-h" or new_arguments == "--help":
            print("""
optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Company name or domain to search.
  -l LIMIT, --limit LIMIT
                        Limit the number of search results, default=500.
  -S START, --start START
                        Start with result number X, default=0.
  -g, --google-dork     Use Google Dorks for Google search.
  -p, --proxies         Use proxies for requests, enter proxies in proxies.yaml.
  -s, --shodan          Use Shodan to query discovered hosts.
  --screenshot SCREENSHOT
                        Take screenshots of resolved domains specify output directory: --screenshot output_directory
  -v, --virtual-host    Verify host name via DNS resolution and search for virtual hosts.
  -e DNS_SERVER, --dns-server DNS_SERVER
                        DNS server to use for lookup.
  -t DNS_TLD, --dns-tld DNS_TLD
                        Perform a DNS TLD expansion discovery, default False.
  -r, --take-over       Check for takeovers.
  -n, --dns-lookup      Enable DNS server lookup, default False.
  -c, --dns-brute       Perform a DNS brute force on the domain.
  -f FILENAME, --filename FILENAME
                        Save the results to an HTML and/or XML file.
  -b SOURCE, --source SOURCE
                        baidu, bing, bingapi, bufferoverun, certspotter, crtsh, dnsdumpster, duckduckgo, exalead, github-
                        code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, netcraft, otx, pentesttools,
                        projectdiscovery, qwant, rapiddns, securityTrails, spyse, sublist3r, threatcrowd, threatminer,
                        trello, twitter, urlscan, virustotal, yahoo

                """)
            the_harvester(domain, sys_args, len_sys_args, domain_split, arguments)
        elif len(new_arguments) >= 1:
            print("TheHarvester in progress .....")
            print("TheHarvester take some time .....")
            os.system('theHarvester '+domain+' '+new_arguments+' > '+directory_domain+'/theHarvester_'+domain_split+'.txt')
        else:
            print("Bad arguments, Try again !")
            the_harvester(domain, sys_args, len_sys_args, domain_split, arguments)
    if len_sys_args >= 1:
        print("TheHarvester Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)
    else:
        print("TheHarvester Done !")
        print(f"{bcolors.Red}End Operation")


def nslookup(domain, sys_args, len_sys_args, domain_split, arguments):
    print("Nslookup in progress .....")
    os.system('nslookup '+domain+' > '+directory_domain+'/nslookup_'+domain_split+'.txt')
    if len_sys_args >= 1:
        print("Nslookup Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)
    else:
        print("Nslookup Done !")
        print(f"{bcolors.Red}End Operation")


def dnsenum(domain, sys_args, len_sys_args, domain_split, arguments):
    if arguments.lower() == "y":
        print("Dnsenum in progress .....")
        os.system('dnsenum --noreverse '+domain+' > '+directory_domain+'/dnsenum_'+domain_split+'.txt')
    elif arguments.lower() == "n":
        new_arguments = input(f"{bcolors.LightBlue}\nPlease enter your options for Dnsenum (-h or --help for show the options): {bcolors.LightGreen}")
        if new_arguments == "-h" or new_arguments == "--help":
            print("""
GENERAL OPTIONS:
  --dnsserver   <server>
                        Use this DNS server for A, NS and MX queries.
  --enum                Shortcut option equivalent to --threads 5 -s 15 -w.
  -h, --help            Print this help message.
  --noreverse           Skip the reverse lookup operations.
  --nocolor             Disable ANSIColor output.
  --private             Show and save private ips at the end of the file domain_ips.txt.
  --subfile <file>      Write all valid subdomains to this file.
  -t, --timeout <value> The tcp and udp timeout values in seconds (default: 10s).
  --threads <value>     The number of threads that will perform different queries.
  -v, --verbose         Be verbose: show all the progress and all the error messages.
GOOGLE SCRAPING OPTIONS:
  -p, --pages <value>   The number of google search pages to process when scraping names,
                        the default is 5 pages, the -s switch must be specified.
  -s, --scrap <value>   The maximum number of subdomains that will be scraped from Google (default 15).
BRUTE FORCE OPTIONS:
  -f, --file <file>     Read subdomains from this file to perform brute force. (Takes priority over default dns.txt)
  -u, --update  <a|g|r|z>
                        Update the file specified with the -f switch with valid subdomains.
        a (all)         Update using all results.
        g               Update using only google scraping results.
        r               Update using only reverse lookup results.
        z               Update using only zonetransfer results.
  -r, --recursion       Recursion on subdomains, brute force all discovered subdomains that have an NS record.
WHOIS NETRANGE OPTIONS:
  -d, --delay <value>   The maximum value of seconds to wait between whois queries, the value is defined randomly, default: 3s.
  -w, --whois           Perform the whois queries on c class network ranges.
                         **Warning**: this can generate very large netranges and it will take lot of time to perform reverse lookups.
REVERSE LOOKUP OPTIONS:
  -e, --exclude <regexp>
                        Exclude PTR records that match the regexp expression from reverse lookup results, useful on invalid hostnames.
OUTPUT OPTIONS:
  -o --output <file>    Output in XML format. Can be imported in MagicTree (www.gremwell.com)


                """)
            dnsenum(domain, sys_args, len_sys_args, domain_split, arguments)
        elif len(new_arguments) >= 1:
            print("Dnsenum in progress .....")
            os.system('dnsenum '+domain+' '+new_arguments+' > '+directory_domain+'/dnsenum_'+domain_split+'.txt')
        else:
            print("Bad arguments, Try again !")
            dnsenum(domain, sys_args, len_sys_args, domain_split, arguments)
    if len_sys_args >= 1:
        print("Dnsenum Done !")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)
    else:
        current_directory = os.getcwd()
        os.system('mv '+current_directory+'/'+domain+'_ips.txt '+directory_domain)
        print("Dnsenum Done !")
        print(f"{bcolors.Red}End Operation")


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

    example : Dig & Nslookup = recoPassive.py 2 5

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
    *     recoPassive 1.0           *
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
        print(f"""{bcolors.LightBlue}    RecoPassive is very simple to use, effective tool builded to be used by
    pentester or red team for passive recognition. The tool gathers many data
    like emails, names, subdomains, IPs, URLs, registrar ...


    Usage : recoPassive.py [Args]

    If you want to launch several applications add up the number of commands :

    1   Whois (Default option : -H)
    2   Dig (Default option : any @8.8.8.8)
    3   Host
    4   TheHarvester (Default option : -d [domain] -b all)
    5   Nslookup
    6   Dnsenum (Default option : --noreverse)

    example : Dig & Nslookup = recoPassive.py 2 5
              TheHarvester & Whois = recoPassive.py 1 4


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
                print(f"{bcolors.LightGreen}\nRemember that the results are saved in the folder (Path = "+current_directory+"/Result)\n")
            else:
                os.mkdir(directory_domain)
                print(f"{bcolors.LightGreen}\nRemember that the results are saved in the folder (Path = "+current_directory+"/Result)\n")
        else:
            os.mkdir(current_directory + "/Result")
            os.mkdir(directory_domain)
            print(f"{bcolors.LightGreen}\nWe have just created a 'Result' folder in which you will find the result ( Path = "+current_directory+"/Result )\n")
        chooseOptions(domain, sys_args, len_sys_args, domain_split, arguments)

