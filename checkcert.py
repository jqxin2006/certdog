"""
This script is leveraging the function provided by
https://www.ssllabs.com/ssltest/analyze.html to retrive the
score of the given domain/ip and all security issues
identified. The script parses the html content to retrive
the score, warnings and errors. It depends on the the format
of https://www.ssllabs.com/ssltest/analyze.html
"""
import mechanize
import cookielib
from bs4 import BeautifulSoup
import time
import re
import socket
from struct import *
from datetime import datetime
from json import dumps
import requests
# Browser
br = mechanize.Browser()

# Cookie Jar
cj = cookielib.LWPCookieJar()
br.set_cookiejar(cj)

# Browser options
br.set_handle_equiv(True)
#br.set_handle_gzip(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)

# Follows refresh 0 but not hangs on refresh > 0
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

# Want debugging messages?
#br.set_debug_http(True)
#br.set_debug_redirects(True)
#br.set_debug_responses(True)

# User-Agent (this is cheating, ok?)
br.addheaders = [('User-agent',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:31.0)\
    Gecko/20100101 Firefox/31.0')]


def lookup(ip):
    """
    This function checks whether the given IP address is private
    or public. It returns True for private IP.
    """
    f = unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]
    private = (
        [2130706432, 4278190080],
        # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [3232235520, 4294901760],
        # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [2886729728, 4293918720],
        # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [167772160,  4278190080],
        # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    )
    for net in private:
        if (f & net[1] == net[0]):
            return True
    return False


def try_one_score(domain, ip):
    """
    Try to get the score, warnings and errors of the given domain
    and IP address. If the result is ready, it returns a tuple
    (score, issues). If the result is not ready, it returns "none"
    """
    base_url = "https://www.ssllabs.com/ssltest/analyze.html?d=%s&s=%s"
    test_url = base_url % (domain, ip)
    print test_url


    r = br.open(test_url)
    html = r.read()

    soup = BeautifulSoup(html)
    rating = soup.find_all("div", attrs={"class": re.compile("rating_")})
    # the score is the div with class as rating_r or rating_a
    if len(rating) == 0:
        return "none"
    if len(rating) == 1:
        score = rating[0].text
        score = score.strip()
        issues = get_issues(html)
        return (score, issues)


def get_issues(html):
    """
    This function parse the HTML response and extract the warnings and
    errors. The result is returned as a list.
    """
    soup = BeautifulSoup(html)
    issues = []
    # make sure that the response is valid with checking for score div
    rating = soup.find_all("div", attrs={"class": re.compile("rating_")})
    if len(rating) == 0:
        return []
    # all errors are divs with class=errorBox
    errors = soup.find_all("div", attrs={"class": "errorBox"})
    for error in errors:
        # ignore the client error of Apple browser
        m = re.search('discovered bug in Apple', error.text.strip())
        if m is not None:
            pass
        else:
            # ignore the part following \r\n
            issues.append(error.text.strip().split("\r\n")[0])
    # all warnings are divs with class=warningBox
    warnings = soup.find_all("div", attrs={"class": "warningBox"})
    for warning in warnings:
        # ignore the part following \r\n
        issues.append(warning.text.strip().split("\r\n")[0])
    return issues


def get_score(domain, ip):
    """
    This function get the score for given domain and IP. It keeps
    query the URL until the valid response is ready. If the response
    is not ready, the process sleeps for 25 seconds before
    trying again. If there is still no result after 10 attempts, it
    gives up and returns "none"

    """
    # track the attempt
    attempt = 0
    # Try MAX_ATTEMPTS before giving up
    MAX_ATTEMPTS = 10
    # the process sleep SLEEP_TIME seconds before trying again
    SLEEP_TIME = 25
    score = "none"
    # try once
    score = try_one_score(domain, ip)
    while score == "none":
        attempt += 1
        time.sleep(SLEEP_TIME)
        score = try_one_score(domain, ip)
        if attempt > MAX_ATTEMPTS:
            break
    return score


def get_public_cert_score(domain):
    """
    This function should be used to get the certificate score
    and issues by given public domain. It returns {} for private
    IP and other errors. It returns a dictionary with score and
    other information for successful result.
    """
    result = {}
    try:
        ip = socket.gethostbyname(domain)
    except:
        #in case the domain can not be resloved, return {}
        return result
    #only check for public IP
    if lookup(ip) is False:
        result["domain"] = domain
        result["ip"] = ip
        print get_score(domain, ip)
        (score, issues) = get_score(domain, ip)
        result["score"] = score
        result["issues"] = issues
        result["update_time"] = str(datetime.now())
    else:
        pass
    return result


def get_public_domains(file_name):
    """
    This function returns a list of public domains from a file.
    """
    public_domains = []
    # read domains from the file
    with open(file_name, "r") as f:
        lines = f.readlines()

    for line in lines:
        domain = line.strip()
        # ignore IP addresses
        if re.search('[a-zA-Z]+', domain) is None:
            continue
        try:
            ip = socket.gethostbyname(domain)
            if lookup(ip) is True:
                continue
            public_domains.append(domain)
        except:
            continue
    return public_domains


def pump_one_record(payload):
    """
    This function pumps one record into our control panel.
    """
    url = "http://a-staging.rakr.net/v1/security/certificates"
    resp = requests.post(url, data=payload)
    print resp.status_code


def pump_records(file_name):
    """
    This function reads the content from the file_name, then
    it get the score and security issues for all public domains by
    using function get_public_cert_score.
    """
    the_public_domains = get_public_domains(file_name)
    for domain in the_public_domains:
        print domain
        result = get_public_cert_score(domain)
        if len(result) > 0:
            pump_one_record(dumps(result))
            print dumps(result)

print dumps(get_public_cert_score("rackspace.com"))

#the_file_name = "the_domains.txt"
#pump_records(the_file_name)
