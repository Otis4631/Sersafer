--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.match
local unescape = ngx.unescape_uri


--allow white ip
function white_ip_check()
     if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jiso") then
                    log_record('White_IP',ngx.var_request_uri,rule,"White_IP") --log_record(method,url,data,ruletag)
                    return true
                end
            end
        end
    end
end

--deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"isjo") then
                    log_record('BlackList_IP',ngx.var_request_uri,rule,"BlackList_IP")
                    if config_waf_enable == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

function allow_only_ip_check()
	if config_allow_only_ip_check then
		local client_ip = get_client_ip()
		if client_ip ~= nil then
			for _,ip in pairs(allow_only_ip) do
				if rulematch(client_ip, allow_only_ip, 'isjo') then
					return false
				else ngx.exit(403)
					return true
				end
			end
		end
	end
end

function unusual_HTTP_request_check()
	local req_method = ngx.req.get_method()
	if req_method == "OPTIONS" or req_method == "PUT" or req_method == "DELETE" or req_method == "TRACE" or req_method == "CONNECT" then	
		log_record('unusual_HTTP_request',ngx.var_request_uri,req_method,"unusual_HTTP_request")
		return false
	end
	return false

end

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        -- debug_print("req_url",REQ_URI)
        -- debug_print("rule", URL_WHITE_RULES)
        -- debug_print('match', rulematch(REQ_URI,rule,"jiso"))
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jiso") then
                    log_record('White_URL',ngx.var_request_uri,rule,"White_URL")
                    return true
                end
            end
        end
    end
end

--deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTACK_URI=ngx.var.uri
        local CC_TOKEN = get_client_ip()..ATTACK_URI
        local limit = ngx.shared.limit
        CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req > CCcount then
                log_record('CC_Attack',ngx.var.request_uri,"-","CC_Attack")
                if config_waf_enable == "on" then
                    ngx.exit(403)
                end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

--deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jiso") then
                    log_record('Deny_Cookie',ngx.var.request_uri,rule,'Cookie_injection')
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule')
        i = 0
        local ruletag = "GET_Illegal_Args"
        for _,rule in pairs(ARGS_RULES) do
            i = i + 1
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                	for _, i in pairs(val) do
                		--define the tamper of base64encode.py
                		if base64_check(i) then
                			val[_] = decodeBase64(i)
                		---------------------------------------
                		end
                	end
                    ARGS_DATA = table.concat(val, " ")
                else
                	if base64_check(val) then
                		ARGS_DATA = decodeBase64(val)
                	else
                    	ARGS_DATA = val
                    end
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"isjo") then
                    if i <= 1 or i == 24 then
                        ruletag = "Directory_Traversal_Attack"
                    elseif i == 25 or i >= 4 and i <= 11 or i >= 13 and i <= 14 then
                        ruletag = "SQL_Injection"
                    elseif i == 12 or i == 13 or i == 22 then
                        ruletag = "System_command_Injection"
                    elseif i == 15 or i == 17 then
                        ruletag = 'Vulnerability_Of_Struts2'
                    elseif i == 16 or i == 26 or i == 27 then
                    	ruletag = 'xss Injection'
                    elseif i >= 2 and i <= 4 then
                    	ruletag = 'File_Contains_Attack'
                    end
                    log_record('Deny_URL_Args',ngx.var.request_uri,rule,ruletag)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end
--deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        local ruletag = 'Deny_USER_AGENT'
        local i = 0
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
            	i = i + 1
                if rule ~="" and rulematch(USER_AGENT,rule,"isjo") then
                	if i == 1 then
                		ruletag = "Use_Hack_Tools" 
                	end
                	
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,rule,ruletag)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

function post_data_chack(data)
    local POST_DATA_RULE = get_rule('post.rule')
    for _, rule in pairs(POST_DATA_RULE) do
        if rule ~= '' and data ~= '' and rulematch(unescape(data), rule, "isjo") then
            log_record('Illegal_File_Content_Upload', ngx.var.request_uri, data, 'Illegal_File_Content_Upload')
            if config_waf_enable == "on" then
                waf_output()
                return true
            end
        end
    end
    return false
end

function file_exe_check(ext)
    ext = string.lower(ext)
    if ext then
        for _,rule in pairs(black_file_ext) do
            if rulematch(ext, rule, "isjo") then
                log_record("File_Upload_Attack", ngx.var.request_uri,rule,'Illegal_File_Type_Upload')
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

function steal_resource_check()
    if config_steal_resource_check == 'on' then
        local RESOURCE_URI_RULES = get_rule('resource.rule')
        local REQ_URI = ngx.var.request_uri
        local headers = ngx.req.get_headers()
        local REFERER = headers['Referer']
        if REFERER == nil then
            return false
        end
        for _,rule in pairs(RESOURCE_URI_RULES) do
            if rule ~= "" and rulematch(REQ_URI,rule,'ijso') then
                for _,domain in pairs(allow_request_domain) do
                    if domain ~= '' and rulematch(REFERER,domain,'isjo') then
                        return false
                    end
                end 
                log_record('Steal_resource',ngx.var.request_uri,REFERER,'Steal_resource')
                if config_waf_enable == 'on' then
                    ngx.header.content_type = "text/html"
                    ngx.status = ngx.HTTP_FORBIDDEN
                    -- ngx.say(config_output_html)
                    ngx.exit(ngx.status)
                    return true
                end
            end
        end
    end
end

--deny url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jiso") then
                log_record('Deny_URL',REQ_URI,rule,'Deny_URL')
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

function struts2_exp_check()
	local ruletag = "Deny_of_struts2_EXP"
 	local EXP_RULES = get_rule('exp.rule')
 	if EXP_RULES == nil then
 		return
 	end
    local REQ_URI = ngx.var.request_uri
    local headers = ngx.req.get_headers()
	headers = headers['Content_type']
    if headers == nil then
        return false
    end
    for _, rule in pairs(EXP_RULES) do
    	if rule ~= '' and rulematch(headers, rule, 'isjo') then
    		log_record("Deny_of_EXP", REQ_URI, rule, ruletag)
    		if config_waf_enable == "on" then
    			waf_output()
    			return true
    		end
    	end
    	return false
    end
end
--deny post
function post_attack_check()
    if config_post_check == "on" then
        if ngx.req.get_method() == "POST" then
            local boundary = get_boundary()
            if boundary then
                local len = string.len
                local sock, err = ngx.req.socket()
                if not sock then
                    return
                end
                ngx.req.init_body(128 * 1024)
                sock:settimeout(0)
                local content_length=tonumber(ngx.req.get_headers()['content-length'])
                local chunk_size = 4096
                if content_length < chunk_size then
                    chunk_size = content_length
                end
                local size = 0
                while size < content_length do
                    local data, err, partial = sock:receive(chunk_size)
                    if not data then
                        return
                    end
                    ngx.req.append_body(data)
                    if post_data_chack(data) then
                        return true
                    end
                    size = size + len(data)
                    local file_suffix_name = rulematch(data,[[Content-Disposition: form-data;(.+)filename="(.+)\.(.*)"]],'isjo')
                    if file_suffix_name then
                        file_exe_check(file_suffix_name[3])
                        file_translate = true
                    else
                        if rulematch(data,"Content-Disposition:",'isjo') then
                            file_translate =false
                        end
                        if file_translate == false then
                            if post_data_chack(data) then
                                return true
                            end
                        end
                    end
                    local less = content_length - size
                    if less < chunk_size then
                        chunk_size = less
                    end
                end
                ngx.req.finish_body()
            else
                ngx.req.read_body()
                local args = ngx.req.get_post_args()
                if not args then
                    return
                end
                for key, val in pairs(args) do
                    if type(val) == 'table' then
                        if type(val[1]) == boolean then
                            return
                        end
                        data = talbe.concat(val, ", ")
                    else
                        data = val
                    end
                    if data and type(data) ~= "boolean" and post_data_chack(data) then
                        post_data_chack(key)
                    end
                end
            end
        end 
    end
    return false
end


