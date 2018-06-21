local commands     = require("proxy.commands")
local tokenizer    = require("proxy.tokenizer")

function read_query( packet )
	-- whitelist IP address
	if proxy.connection.client.src.address == "127.0.0.1" then return end
	if proxy.connection.client.src.address == "192.168.1.1" then return end


	-- allowed commands
	local cmd = commands.parse(packet)
	if cmd.type == proxy.COM_SLEEP then return end
	if cmd.type == proxy.COM_QUIT then return end
	if cmd.type == proxy.COM_FIELD_LIST then return end
	if cmd.type == proxy.COM_REFRESH then return end
	if cmd.type == proxy.COM_PING then return end
	if cmd.type == proxy.COM_TIME then return end
	if cmd.type == proxy.COM_STMT_EXECUTE then return end
	if cmd.type == proxy.COM_STMT_SEND_LONG_DATA then return end
	if cmd.type == proxy.COM_STMT_CLOSE then return end
	if cmd.type == proxy.COM_STMT_RESET then return end
	if cmd.type == proxy.COM_STMT_FETCH then return end
	if cmd.type == proxy.COM_SET_OPTION then return end

	if (cmd.type ~= proxy.COM_QUERY) and (cmd.type ~= proxy.COM_STMT_PREPARE) then
		-- disallowed commands
		proxy.response.type = proxy.MYSQLD_PACKET_ERR
		proxy.response.errmsg = "now allowed command"
		-- proxy.response.type = proxy.MYSQLD_PACKET_OK

		return proxy.PROXY_SEND_RESULT
	end

	-- COM_QUERY and COM_STMT_PREPARE, examine SQL
	local tokens = tokenizer.tokenize(cmd.query)
	local stmt = nil
	local has_where = false
	local has_star = false
	for i = 1, #tokens do
		local token = tokens[i]
		-- normalize the query
		if token["token_name"] == "TK_COMMENT" then
		elseif token["token_name"] == "TK_COMMENT_MYSQL" then
		elseif token["token_name"] == "TK_LITERAL" then
			-- commit and rollback at LITERALS
			if stmt == nil then stmt = token end
		elseif token["token_name"] == "TK_STAR" then
			has_star = true
		elseif token["token_name"] == "TK_SQL_WHERE" then
			has_where = true
		else
			-- TK_SQL_* are normal tokens
			if stmt == nil then stmt = token end
		end
	end

	if stmt == nil then return end

	-- allowed construct
	if (stmt.token_name == "TK_SQL_SELECT") and has_where and not has_star then return end
	if (stmt.token_name == "TK_SQL_INSERT")                                then return end
	if (stmt.token_name == "TK_SQL_UPDATE") and has_where                  then return end
	if (stmt.token_name == "TK_SQL_DELETE") and has_where                  then return end

	-- render query a no-op
	proxy.response.type = proxy.MYSQLD_PACKET_OK
	return proxy.PROXY_SEND_RESULT
end
