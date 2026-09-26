"""Collect public directory facts with source URLs and local retryable caches."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib, json, re, time
from datetime import datetime, timezone
from urllib.parse import urljoin
import httpx, html5lib
ROOT=Path(__file__).resolve().parents[2]
CACHE=ROOT/'kb/sources/cache'; CACHE.mkdir(parents=True,exist_ok=True)
OUT=ROOT/'kb/sources'
client=httpx.Client(timeout=45,follow_redirects=True,headers={'User-Agent':'KoreanSiteCatalog/1.0 (public directory research)'})
def get(url):
 p=CACHE/(hashlib.sha256(url.encode()).hexdigest()+'.html')
 if p.exists() and time.time()-p.stat().st_mtime < 7*86400:return p.read_text()
 r=client.get(url);r.raise_for_status();p.write_text(r.text);return r.text

def tree(s):return html5lib.parse(s,namespaceHTMLElements=False)
def text(e):return ' '.join(''.join(e.itertext()).split())
def collect_gov(url):
 root=tree(get(url));out=[]
 for ul in root.iter('ul'):
  if 'gov-web' not in ul.get('class','').split():continue
  for li in ul.findall('li'):
   a=next((a for a in li.iter('a') if 'fncGoSite(' in a.get('onclick','')),None)
   if a is None:continue
   m=re.search(r"fncGoSite\('([^']*)'",a.get('onclick',''))
   if m:out.append({'name':text(a),'url':m[1],'source':url,'kind':'government_directory'})
 return out

def collect_alio(url):
 root=tree(get(url));out=[]
 for tr in root.iter('tr'):
  cells=tr.findall('td')
  if len(cells)!=5:continue
  a=cells[-1].find('a')
  if a is not None and a.get('href','').startswith('http'):
   out.append({'name':text(cells[1]),'url':a.get('href'),'source':url,'kind':'public_institution'})
 return out

def collect_popular(url):
 root=tree(get(url));out=[]
 for tr in root.iter('tr'):
  a=next((a for a in tr.iter('a') if 'website-domain-link' in a.get('class','').split()),None)
  if a is None:continue
  cells=tr.findall('td')
  cat=next((a for a in tr.iter('a') if 'website-category-link' in a.get('class','').split()),None)
  traffic=text(cells[5]).split()[0] if len(cells)>5 else ''
  out.append({'name':text(a),'url':'https://'+text(a),'source':url,'kind':'popular_ranking','category':text(cat) if cat is not None else url.rsplit('/',1)[-1],'rank':text(cells[0]),'traffic_display':traffic})
 return out

def batch(name,urls,fn):
 rows=[];errors=[]
 def one(url):
  try:return fn(url),None
  except Exception as e:return [],{'url':url,'error':type(e).__name__}
 with ThreadPoolExecutor(max_workers=3) as ex:
  for i,(r,e) in enumerate(ex.map(one,urls),1):
   rows.extend(r)
   if e:errors.append(e)
   if i%10==0:print(name,i,len(urls),len(rows),flush=True)
 if errors:
  raise RuntimeError(f'{name}: {len(errors)} failed pages; keeping previous complete snapshot')
 (OUT/(name+'.json')).write_text(json.dumps({'checked':datetime.now(timezone.utc).date().isoformat(),'source_pages':urls,'records':rows,'errors':errors},ensure_ascii=False,indent=2))
 print(name,'finished',len(rows),'errors',len(errors),flush=True)

if __name__=='__main__':
 gov=get('https://www.gov.kr/portal/orgSite')
 pages=max(map(int,re.findall(r'orgSite\?pageIndex=(\d+)',gov)))
 batch('government24',[f'https://www.gov.kr/portal/orgSite?pageIndex={p}' for p in range(1,pages+1)],collect_gov)
 alio=get('https://job.alio.go.kr/orginfo.do')
 # The public list has 10 rows per page and publishes the 342-institution total.
 total=int(re.search(r'모두\s*([\d,]+)개',alio)[1].replace(',',''))
 batch('alio',[f'https://job.alio.go.kr/orginfo.do?pageNo={p}' for p in range(1,(total+9)//10+1)],collect_alio)
 popular=get('https://ahrefstop.com/websites/korea')
 paths=set(re.findall(r'href="(/websites/korea/[^"?#]+)"',popular))
 # Public category selector also carries data-value values; add only observed category paths.
 batch('korea_popular',['https://ahrefstop.com/websites/korea']+['https://ahrefstop.com'+p for p in sorted(paths)],collect_popular)
 nmc=tree(get('https://www.ppm.or.kr/'))
 rows={a.get('data-hospcd'):{'name':a.get('alt'),'url':a.get('data-url'),'source':'https://www.ppm.or.kr/','kind':'public_hospital','source_id':a.get('data-hospcd')} for a in nmc.iter('area') if a.get('data-hospcd')}
 (OUT/'public_hospitals.json').write_text(json.dumps({'checked':datetime.now(timezone.utc).date().isoformat(),'records':list(rows.values())},ensure_ascii=False,indent=2))
 print('hospitals',len(rows),flush=True)
