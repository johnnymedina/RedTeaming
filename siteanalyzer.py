import nmap
from Wappalyzer import Wappalyzer, WebPage

hostlist = '10.10.10.0','10.10.10.1'

def scanner(hostlist):
    nm=nmap.PortScanner()
    hostuplist=[]
    for host in hostlist:
        nm.scan(host, arguments='-Pn -p 443')
        portstatus = nm[host]['tcp'][443]['state']
        print(host + " " + portstatus)
        if portstatus == 'open':
            print(host + " has port 443 open" )
            hostuplist.append(host)
    return hostuplist

uplist = scanner(hostlist)
print(uplist)

##print(scanner(hostlist))

def analyze(uplist):
    results=[]
    for host in goodlist:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url('https://' + host)
        data = wappalyzer.analyze_with_versions_and_categories(webpage)
        results.append(data)
    return results

final_results = analyze(uplist)
print(final_results)
