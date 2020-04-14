-- local nmap = require "nmap"
local stdnse = require "stdnse"

description = "Takes arguments from console"
categories = {"discovery"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

function contains(tbl, value, full_match)
    full_match = full_match or false
    for _, v in pairs(tbl) do
        if (full_match and v == value) or (not full_match and string.find(value, v, 1, true)) then
            return true
        end
    end
    return false
end

function get_keys_list_from_table(tbl)
    local keyset = {}
    for k, _ in pairs(tbl) do table.insert(keyset, k) end
    return keyset
end

--[[
    @param table tbl: table to recurse.
    [@param table filter: table to filter tbl with, containing:
        [boolean: filter[1]: boolean if string must match fully. Default: false],
        filter[2, ..]: strings to filter in (as opposed to filter out).
    If empty, no filtering is done. Default: {}]
    [@param string intentation: string to use as indentation to represent hierarchy in the table. Default: "\t"]
    [prefix_key: boolean whether to prefix value with key. Default: true. Overriden by: one_line]
    [one_line: boolean whether to print all values in one line. If true, overrides prefix_key to false. Default: true]
--]]
function recurse_table_to_json_string(tbl, filter, indentation, prefix_key, one_line, level)
    if not tbl then return "\n*** Table is nil ***\n" end

    filter = filter or {}
    if next(filter) ~= nil and type(filter[1]) ~= "boolean" then
        table.insert(filter, 1, false)
    end

    indentation = indentation or "\t"
    level = level or 0

    if prefix_key == nil then
        prefix_key = true
    elseif one_line then
        prefix_key = false
    end

    local result = ""
    local newline = one_line and "" or "\n"
    for k, v in pairs(tbl) do
        if (type(v) == "table") then
            if next(v) ~= nil or next(v) == nil then -- only recurse if table is not empty
                local deeper = recurse_table_to_json_string(v, filter, indentation, prefix_key,
                                                            one_line, level + 1)
                if deeper ~= "" or next(filter) == nil then -- suppress empty table titles if filtering is used
                    result = result .. string.rep(indentation, level) .. k .. ": " .. newline ..
                                 deeper
                end
            end
        else
            if next(filter) == nil or contains({table.unpack(filter, 2, #filter)}, k, filter[1]) then
                if prefix_key then
                    k = k .. " = "
                else
                    k = ""
                end
                result = result .. string.rep(indentation, level) .. k .. tostring(v) .. newline
            end
        end
    end
    return result
end

-- Shorthand for recurse_table_to_json_string().
function rt(tbl, filter, indentation, prefix_key, level)
    return recurse_table_to_json_string(tbl, filter, indentation, prefix_key, level)
end

function get_arguments()
    local args = {}
    args.output_filename = stdnse.get_script_args({"nscan.filename"})

    local list_interfaces = stdnse.get_script_args({"nscan.list-interfaces"})
    if list_interfaces == 1 then
        args.list_interfaces = true
    else
        args.list_interfaces = false
    end

    args.scan_type = stdnse.get_script_args({"nscan.type"})
    return args
end

function get_network_interface_list(ubus_connection)
    local a = ubus_connection:call("network.device", "status", {})
    -- print(rt(a))

    return get_keys_list_from_table(ubus_connection:call("network.device", "status", {}))
end

function get_interfaces_with_IPs(ubus_connection)
    interfaces_with_IPs = {}
    for _, v in pairs(ubus_connection:call("network.interface", "dump", {}).interface) do
        if v["ipv4-address"] ~= nil and next(v["ipv4-address"]) ~= nil then
            for _, a in pairs(v["ipv4-address"]) do interfaces_with_IPs[v.device] = a end
        end
    end
    return interfaces_with_IPs
end

function add_targets(ip_str, mask)
    local target = require "target"

    success = true
    targets = {}

    local ip = IPv4_str2table(ip_str)
    local ip_min = find_subnet_min_max(ip, mask, 0)
    local ip_max = find_subnet_min_max(ip, mask, 1)
    print(table_to_IPv4_str(ip_min))
    print(table_to_IPv4_str(ip_max))
    print()
    -- for i = 1, 2 ^ (32 - mask), -1 do targets[i] = ip end

    targets[1] = "192.168.1.214"
    -- temporarily enable adding new targets irrespective of script arguments and save old value for restoring later
    local old_ALLOW_NEW_TARGETS = target.ALLOW_NEW_TARGETS
    target.ALLOW_NEW_TARGETS = true

    for _, item in ipairs(targets) do
        local st, err = target.add(item)

        if not st then
            print("\n\nCouldn't add target " .. item .. ": " .. err .. "\n\n")
            success = false
        end
    end

    -- restore ALLOW_NEW_TARGETS state
    target.ALLOW_NEW_TARGETS = old_ALLOW_NEW_TARGETS

    return success
end

prerule = function()
    package.cpath = package.cpath .. ";/usr/lib/lua/?.so"
    local ubus = require "ubus_5_3"
    local conn = ubus.connect()
    if not conn then error("Failed to connect to ubusd") end
    local args = get_arguments()

    local interfaces_with_IPs = get_interfaces_with_IPs(conn)
    if args.list_interfaces then print(rt(interfaces_with_IPs)) end

    -- print(rt(get_network_interface_list(conn)))

    -- print(rt(get_wifi_info(conn)))
    conn:close()

    -- add_targets(interfaces_with_IPs["br-lan"].address, interfaces_with_IPs["br-lan"].mask)

    test()

    return true
end

action = function(host, port) return 0 end

--[[------------------------ IP functions ----------------------------
    3 supported data types for IPs:
        - string, e.g. "192.168.1.1"
        - table with each value representing one bit in the IP address. Indexing starts from the leftmost digit. E.g. {1 1 0 0 0 0 0 0 1 0 1 0 1 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 1}.
        - number representing IP in binary form converted to base 10, e.g. 3232235777
    All conversion functions assume correct argument type. All other functions do conversion automatically.
    All functions assume correct value of each passed argument type.
]]

do -- conversion functions
    local function IPv4_str2table(ip_str)

        local ip_bin = {}
        local octet_index = 0

        ip_str:gsub("%d+", function(octet)
            for i = 8, 1, -1 do
                ip_bin[i + octet_index * 8] = math.floor(octet % 2)
                octet = octet // 2
            end

            octet_index = octet_index + 1
        end)

        return ip_bin
    end

    local function table2IPv4_str(ip_bin)
        local ip = {}
        for o = 0, 3 do
            local octet = 0
            for i = 1, 8 do octet = octet * 2 + ip_bin[i + o * 8] end
            ip[o + 1] = octet
        end

        return ip[1] .. "." .. ip[2] .. "." .. ip[3] .. "." .. ip[4]
    end

    local function IPv4_str2int(ip_str)
        local ip_dec = 0
        local octet_index = 3

        ip_str:gsub("%d+", function(octet)
            ip_dec = ip_dec + octet * 256 ^ octet_index
            octet_index = octet_index - 1
        end)

        return math.floor(ip_dec)
    end

    local function int2IPv4_str(ip_dec)
        local octets = {}
        for i = 1, 4 do
            octets[i] = ip_dec % 256
            ip_dec = (ip_dec - octets[i]) // 256
        end

        return octets[4] .. "." .. octets[3] .. "." .. octets[2] .. "." .. octets[1]
    end

    local n = {
        number = function(ip) return ip end,
        string = function(ip) return IPv4_str2int(ip) end,
        table = function(ip) return IPv4_str2int(table2IPv4_str(ip)) end
    }
    local s = {
        number = function(ip) return int2IPv4_str(ip) end,
        string = function(ip) return ip end,
        table = function(ip) return table2IPv4_str(ip) end
    }
    local t = {
        number = function(ip) return IPv4_str2table(int2IPv4_str(ip)) end,
        string = function(ip) return IPv4_str2table(ip) end,
        table = function(ip) return ip end
    }
    local conv = {
        number = function(ip) return n[type(ip)](ip) end,
        string = function(ip) return s[type(ip)](ip) end,
        table = function(ip) return t[type(ip)](ip) end
    }

    function convert_to(type, ip) return conv[type](ip) end
end

--[[
        Find max or min subnet IP from given IP and mask.
        ip_in_subnet - 
        mask - 
        min_max - 0 if min, 1 if max
    ]]
function find_subnet_min_max(ip_in, mask, min_max)
    local ip_in_subnet = convert_to("table", ip_in)

    local ip = {}
    for i = 1, mask do ip[i] = ip_in_subnet[i] end
    for i = mask + 1, 31 do ip[i] = min_max end
    if mask < 32 then ip[32] = 1 - min_max end
    return ip
end

function IPv4_iter(ip_in, mask)
    local ip = find_subnet_min_max(ip, mask, 0)
    local count = 2 ^ (32 - mask) - 2
    -- local max = find_subnet_min_max(ip, mask, 1)
    return function()
        ip = ip + 1
        count = count - 1
        if count > 0 then return convert_to("string", ip) end
    end
end

function test()
    local ip_str = "22.95.227.62"
    local mask = 28

    -- local ip = convert_to("table", ip_str)
    local ip = convert_to(ip_str)
    local ip2 = convert_to("number", ip_str)
    local a = {ip_str, ip, ip2}
    print()

    -- for ip in IPv4_iter(ip_str) do print(ip) end
end
----------------------------------------------------------------------

--[[
do ----------------------------- Shit --------------------------------

    function get_network_devices_info(ubus_connection, device_name)
        local temp = {}
        if device_name ~= "" and device_name ~= "--list" and device_name ~= "--all" then
            temp.name = device_name
        end

        local device_list = ubus_connection:call("network.device", "status", temp)
        print(rt(device_list))
        if temp.name == nil then return get_keys_list_from_table(device_list) end
        return device_list
    end

    function get_network_interface_data(ubus_connection, device_name)
        return ubus_connection:call("network.interface." .. device_name, "dump", {})
    end

    function get_wifi_info(ubus_connection)
        local wifi_info = ubus_connection:call("network.wireless", "status", {})
        -- print(rt(wifi_info))

        local interfaces_on_networks = {}
        local interfaces = {}

        for _, radio in pairs(wifi_info) do
            for _, interface in pairs(radio.interfaces) do
                table.insert(interfaces, interface.ifname)
                if interface.config.network ~= nil then
                    for _, network in pairs(interface.config.network) do
                        interfaces_on_networks[network] = 1
                        -- print(k, network)
                    end
                end
            end
        end

        -- print(interfaces_on_networks)
        return interfaces_on_networks
    end

    function get_vlans(ubus_connection, device_name)
        local dump = ubus_connection:call("uci", "get", {config = "network"})

        return dump
    end

    local if_data = get_network_interface_data(conn, args.interface)
    print(rt(if_data.interface, {true, "l3_device", "interface", "mask", "address"}))

    local dump = get_vlans(conn)
    print(rt(get_keys_list_from_table(dump.values)))
    print(rt(dump.values))

end
--]]
