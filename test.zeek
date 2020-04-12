global ipTable :table[addr] of set[string];
event http_header(c:connection,is_orig:bool,name:string,value:string){
	local ip :addr;
	ip=c$id$orig_h;
	if(c$http?$user_agent){
		local lowerip :string=to_lower(c$http$user_agent);
		if(ip in ipTable){
			add ipTable[ip][lowerip];
		}
		else{
			ipTable[ip]=set(lowerip);
		}
	}
}
event zeek_done(){
	for(i in ipTable){
		if(|ipTable[i]|>=3){
		print cat(i,"is a proxy");
		}
	}
}
