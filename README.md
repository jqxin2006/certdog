certdog
=======

certdog check the security issues of the public certificate using https://www.ssllabs.com/ssltest/analyze.html
The script parses the response from the https://www.ssllabs.com/ssltest/analyze.html to extract the score,
warnings and errors for the given public domain. It does check to make sure that only domain names with
public IP will be checked. 

Warning: This script relies on the service of https://www.ssllabs.com/ssltest/analyze.html. So the score and related 
issues might be accessible from https://www.ssllabs.com. 
The script does take some time to run due to many checks that will run. 


Example:

print get_public_cert_score("rackspace.com")


Output:
{'ip': '162.209.121.65', 'domain': 'cp.rackspace.com', 'score': u'F', 'update_time': '2014-12-10 10:45:57.352219', 'issues': [u'This server is vulnerable to the POODLE attack against TLS servers. Patching required. Grade set to F. MORE\xa0INFO\xa0\xbb', u'Certificate has a weak signature and expires after 2016. Upgrade to SHA2 to avoid browser warnings.', u'This server accepts the RC4 cipher, which is weak. Grade capped to B.', u'The server does not support Forward Secrecy with the reference browsers.']}


