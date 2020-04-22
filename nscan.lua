-- local nmap = require "nmap"
local stdnse = require "stdnse"
local json = require "json"

description = "Takes arguments from console"
categories = {"discovery"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local arguments_map = {
    output_filename = stdnse.get_script_args({"nscan.filename"}),
    interface = stdnse.get_script_args({"nscan.interface"}),
    scan_type = stdnse.get_script_args({"nscan.type"})
}

local function get_interfaces_with_IPs(ubus_connection)
    local interfaces_with_IPs = {}
    for _, v in pairs(ubus_connection:call("network.interface", "dump", {}).interface) do
        if v["ipv4-address"] ~= nil and next(v["ipv4-address"]) ~= nil then
            for _, a in pairs(v["ipv4-address"]) do interfaces_with_IPs[v.device] = a end
        end
    end
    return interfaces_with_IPs
end

local function get_manufacturer(mac_str)
    local datafiles = require "datafiles"
    local nmap = require "nmap"

    local catch = function() return "Unknown" end
    local try = nmap.new_try(catch)
    local mac_prefixes = try(datafiles.parse_mac_prefixes())
    local prefix = string.upper(string.sub(mac_str:gsub(':', ''), 1, 6))
    return mac_prefixes[prefix] or "Unknown"
end

local function add_targets(ip, mask)
    local target = require "target"

    local success = true
    local targets = {}

    for ip_s in IPv4_iter(ip, mask) do table.insert(targets, ip_s) end

    print(convert_to("string", Find_subnet_min_max(ip, mask, 0)))
    print(convert_to("string", Find_subnet_min_max(ip, mask, 1)))
    print()

    -- temporarily enable adding new targets irrespective of script arguments and save old value for restoring later
    local old_ALLOW_NEW_TARGETS = target.ALLOW_NEW_TARGETS
    target.ALLOW_NEW_TARGETS = true

    for _, item in pairs(targets) do
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

local file_mode = {read = "r", append = "a", write = "w"}

local function write_json_to(filename, mode, json_str)
    local file = io.open(filename, file_mode.append)
    file:write(json_str)
    file:close()
end

do -- State monitoring
    local state_filepath = "/tmp/nscan.state"
    local state_file

    function Open_state()
        state_file = io.open(state_filepath, file_mode.read)

        -- Check if state file exists
        if state_file then
            -- State file exists, check if locked
            if not state_file:read() then
                -- State file is locked - another instance already running, exit
                state_file:close()
                os.exit(1)
            else
                -- State file is locked - previous instance crashed, clean up
                Close_state()
            end
        end

        -- Lock state file by writing current date and time.
        state_file = io.open(state_filepath, file_mode.write)
        state_file:write(os.date())
    end

    function Close_state()
        -- Close state file if opened
        if state_file then state_file:close() end
        -- Delete state file
        os.remove(state_filepath)
    end

end

prerule = function()
    Open_state()
    package.cpath = package.cpath .. ";/usr/lib/lua/?.so"
    local ubus = require "ubus_5_3"
    local conn = ubus.connect()
    if not conn then error("Failed to connect to ubusd") end

    local interfaces_with_IPs = get_interfaces_with_IPs(conn)

    conn:close()

    if arguments_map.interface == "--list" then
        print(json.generate(interfaces_with_IPs))
    else
        add_targets(interfaces_with_IPs[arguments_map.interface].address,
                    interfaces_with_IPs[arguments_map.interface].mask)
    end

    return false
end

hostrule = function(host) return host.interface == arguments_map.interface end

postrule = function()
    -- Finish writing to file, report state as finished
    Close_state()
end

action = function(host, port)
    local ip_addr = table.concat({string.byte(host.bin_ip, 1, #host.bin_ip)}, ".")
    local mac_addr = string.format('%02X:%02X:%02X:%02X:%02X:%02X',
                                   string.byte(host.mac_addr, 1, #host.mac_addr))

    print(json.generate({IP = ip_addr, MAC = mac_addr, Vendor = get_manufacturer(mac_addr)}))
    print("IP: " .. ip_addr, "MAC: " .. mac_addr, "Vendor: " .. get_manufacturer(mac_addr))
    print("-----------------------------------------------------------------------------")
    -- return "IP: " .. ip_addr .. "\tMAC: " .. mac_addr
    return 0
end

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
        local octets = {}
        for o = 1, 4 do
            local octet = 0
            for i = 1, 8 do octet = octet * 2 + ip_bin[i + (o - 1) * 8] end
            octets[o] = octet
        end

        return table.concat(octets, ".")
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
        for i = 4, 1, -1 do
            octets[i] = ip_dec % 256
            ip_dec = (ip_dec - octets[i]) // 256
        end

        return table.concat(octets, ".")
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
function Find_subnet_min_max(ip_in, mask, min_max)
    local ip_in_subnet = convert_to("table", ip_in)

    local ip = {}
    for i = 1, mask do ip[i] = ip_in_subnet[i] end
    for i = mask + 1, 31 do ip[i] = min_max end
    if mask < 32 then ip[32] = 1 - min_max end
    return ip
end

function IPv4_iter(ip_in, mask)
    local ip = convert_to("number", Find_subnet_min_max(ip_in, mask, 0)) - 1
    local count = 2 ^ (32 - mask) - 1
    -- local max = find_subnet_min_max(ip, mask, 1)
    return function()
        ip = ip + 1
        count = count - 1
        if count > 0 then return convert_to("string", ip) end
    end
end

function Test()
    local mask = 28
    local ip_str = "22.95.227.62"
    local ip = convert_to("table", ip_str)
    local ip2 = convert_to("number", ip_str)

    local a, b, c = {}, {}, {}

    for ip_s in IPv4_iter(ip_str, mask) do table.insert(a, ip_s) end
    for ip_t in IPv4_iter(ip, mask) do table.insert(b, ip_t) end
    for ip_n in IPv4_iter(ip2, mask) do table.insert(c, ip_n) end

    print()
    print(convert_to("string", Find_subnet_min_max(ip_str, mask, 0)))
    for i = 1, #a do print(a[i], b[i], c[i]) end
    print(convert_to("string", Find_subnet_min_max(ip_str, mask, 1)))
    print()
    print(#a)
    print()

end
----------------------------------------------------------------------

--[[
do ----------------------------- Shit --------------------------------

    local function get_keys_list_from_table(tbl)
        local keyset = {}
        for k, _ in pairs(tbl) do table.insert(keyset, k) end
        return keyset
    end

    local function get_network_interface_list(ubus_connection)
        local a = ubus_connection:call("network.device", "status", {})
        -- print(rt(a))

        return get_keys_list_from_table(ubus_connection:call("network.device", "status", {}))
    end

    local function Get_network_devices_info(ubus_connection, device_name)
        local temp = {}
        if device_name ~= "" and device_name ~= "--list" and device_name ~= "--all" then
            temp.name = device_name
        end

        local device_list = ubus_connection:call("network.device", "status", temp)
        print(rt(device_list))
        if temp.name == nil then return get_keys_list_from_table(device_list) end
        return device_list
    end

    local function Get_network_interface_data(ubus_connection, device_name)
        return ubus_connection:call("network.interface." .. device_name, "dump", {})
    end

    local function Get_wifi_info(ubus_connection)
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

    local function Get_vlans(ubus_connection, device_name)
        local dump = ubus_connection:call("uci", "get", {config = "network"})

        return dump
    end

    local if_data = Get_network_interface_data(conn, args.interface)
    print(rt(if_data.interface, {true, "l3_device", "interface", "mask", "address"}))

    local dump = Get_vlans(conn)
    print(rt(get_keys_list_from_table(dump.values)))
    print(rt(dump.values))

end
-- ]]
