"""Public Korean traffic rankings, kept distinct from official identity verification."""
from collect_directories import get,batch,tree,OUT
import json,re

def collect(url):
 root=tree(get(url))
 for s in root.iter('script'):
  t=s.text or ''
  marker='window.__PRELOADED_STATE__ = '
  if marker not in t:continue
  state=json.JSONDecoder().raw_decode(t.split(marker,1)[1])[0]
  data=state['data'];rows=data.get('domains',[])
  return [{'name':r['domain_name'],'url':'https://'+r['domain_name'],'kind':'popular_ranking','source':url,'month':state.get('date'),'category':url.rsplit('/',1)[-1],'visits':r.get('total_traffic'),'rank':i} for i,r in enumerate(rows,1)]
 raise ValueError('public ranking table not found')

if __name__=='__main__':
 html=get('https://www.semrush.com/trending-websites/kr/all')
 paths=sorted(set(re.findall(r'href="(/trending-websites/kr/[a-z-]+)"',html)))
 batch('korea_traffic',['https://www.semrush.com'+p for p in paths],collect)
