global relationTable :table[addr] of int = table();
global ipTable :table[addr] of set[string] = table();
event http_reply(c: connection, version: string, code: count, reason: string){
  local useragent: string =to_lower(c$http$user_agent); 
  local ip: addr=c$id$orig_h;
  if(ip in ipTable){
       if(useragent !in ipTable[ip]){
             add ipTable[ip][useragent];
             relationTable[ip] +=1;
       }
  }
  else{
        ipTable[ip] = set(useragent);
        relationTable[ip] = 1;
  }
}
event zeek_done()
{
   for(ip, num in relationTable)
   {
        if(num >= 3)
        {
           print fmt("%s is a proxy", ip);
        }
   }
}
