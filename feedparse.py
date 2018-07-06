import feedparser
from BeautifulSoup import BeautifulSoup
import urllib2
import re
import requests, zipfile, StringIO
import multiprocessing
import time 
#TODO Use Tshark to remove non-HTTP containting pcaps, they are useless to this project.
# for now use
#for f in *.pcap; do if [[ $(tshark -r $f -Y http) ]]; then echo "Has HTTP"; else rm $f; echo $f " NO HTTP"; fi; done
d = feedparser.parse('https://www.malware-traffic-analysis.net/blog-entries.rss')

urls = []
for i in d.entries: 
    urls.append(i.link)
    print i

def getLinks(url):
    html_page = urllib2.urlopen(url)
    soup = BeautifulSoup(html_page)
    links = []
    #uri = url.replace('index.html','')
    uri = re.sub('\index\S+','', url) 
    for link in soup.findAll('a', attrs={'href': re.compile("pcap")}):
        links.append(uri + link.get('href')) 
    return links

def unZip(url):
    if getLinks(url) != []:
        print(getLinks(url)[0])
        r = requests.get(getLinks(url)[0], allow_redirects=True)
        filename = zipfile.ZipFile(StringIO.StringIO(r.content))
        filename.extractall('ext_malware_pcap/',pwd='infected')
        #open(filename, 'wb').write(r.content)

if __name__ == '__main__':
    p = multiprocessing.Pool(processes=8)
    #timing it...
    start = time.time()
    for i in urls:
        p.apply_async(unZip, [i])
    p.close()
    p.join()
    print("Complete")
    end = time.time()
    print('total time (s)= ' + str(end-start))
