local stdnse = require "stdnse"
local json = require "json"

description = "Takes arguments from console"
categories = {"discovery"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local function contains(tbl, value, full_match)
    full_match = full_match or false
    for _, v in pairs(tbl) do
        if (full_match and v == value) or
            (not full_match and string.find(value, v, 1, true)) then
            return true
        end
    end
    return false
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
local function recurse_table_to_json_string(tbl, filter, indentation,
                                            prefix_key, one_line, level)
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
                local deeper = recurse_table_to_json_string(v, filter,
                                                            indentation,
                                                            prefix_key,
                                                            one_line, level + 1)
                if deeper ~= "" or next(filter) == nil then -- suppress empty table titles if filtering is used
                    result = result .. string.rep(indentation, level) .. k ..
                                 ": " .. newline .. deeper
                end
            end
        else
            if next(filter) == nil or
                contains({table.unpack(filter, 2, #filter)}, k, filter[1]) then
                if prefix_key then
                    k = k .. " = "
                else
                    k = ""
                end
                result = result .. string.rep(indentation, level) .. k ..
                             tostring(v) .. newline
            end
        end
    end
    return result
end

-- Shorthand for recurse_table_to_json_string().
local function rt(tbl, filter, indentation, prefix_key, level)
    return recurse_table_to_json_string(tbl, filter, indentation, prefix_key,
                                        level)
end

local args_map = {
    output_filename = stdnse.get_script_args({"nscan.filename"}),
    interface = stdnse.get_script_args({"nscan.interface"}),
    scan_type = stdnse.get_script_args({"nscan.type"}),
    verbose = stdnse.get_script_args({"nscan.v"}) == "true" and true or false,
    wireless = nil,
    first = nil
}

local path = "/tmp/nscan/"
local files = {
    state = path .. "nscan.state",
    interfaces = path .. "nscan_interfaces.json",
    results = args_map.output_filename and path .. args_map.output_filename
}
local file_mode = {append = "a+", read = "r", write = "w+"}

local function write_to(filename, a_string, mode)
    if args_map.verbose then print("Writing to " .. filename) end
    mode = mode or file_mode.write
    local file = io.open(filename, mode)
    file:write(a_string)
    file:close()
end

do -- State monitoring
    local state_file

    local function get_line_from_state(line)
        state_file:seek("set")
        for _ = 1, line - 1 do state_file:read() end
        return state_file:read()
    end

    function Open_state(stage, is_wireless)
        is_wireless = is_wireless or false
        state_file = io.open(files.state, file_mode.read)

        if stage == "startup" then
            -- Check if state file exists
            if state_file then
                -- State file exists, check if either locked or timed out
                local run_datetime = get_line_from_state(1)
                if not run_datetime or os.time() - run_datetime < 60 then
                    -- State file is locked or not timed out - another instance already running, exit
                    state_file:close()
                    os.exit(1)
                else
                    -- State file is not locked - previous instance crashed, clean up
                    Close_state("cleanup")
                end
            end
            -- Lock state file by writing a timestamp.
            state_file = io.open(files.state, file_mode.write)
            state_file:write(os.time() .. "\n" .. tostring(is_wireless))
        elseif stage == "action" then
            -- If third line doesn't exist reopen for writing, create it and set first to true
            if not get_line_from_state(3) then
                state_file:close()
                write_to(files.state, "\n0", file_mode.append)
                state_file = io.open(files.state, file_mode.read)
                args_map.first = true
            else
                args_map.first = false
            end
        end

        args_map.wireless = get_line_from_state(2) == "true"

        -- Add results filename if it's not specified in arguments.
        -- We do this now because earlier we didn't have the time written for reading.
        if not files.results then
            files.results = path ..
                                os.date("!%Y-%m-%d_%H:%M:%S",
                                        get_line_from_state(1)) .. ".json"
        end
    end

    function Close_state(stage)
        -- Close state file if opened
        if state_file then state_file:close() end
        -- Delete state file
        if stage == "cleanup" then os.remove(files.state) end
    end

end

do --[[------------------------ IP functions ----------------------------
    3 supported data types for IPs:
        - string, e.g. "192.168.1.1"
        - table with each value representing one bit in the IP address. Indexing starts from the leftmost digit. E.g. {1 1 0 0 0 0 0 0 1 0 1 0 1 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 1}.
        - number representing IP in binary form converted to base 10, e.g. 3232235777
    All conversion functions assume correct argument type. All other functions do conversion automatically.
    All functions assume correct value of each passed argument type.
]]

    -- conversion functions
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
            for i = 1, 8 do
                octet = octet * 2 + ip_bin[i + (o - 1) * 8]
            end
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
end

--------------------------- ubus functions ---------------------------
local function get_interfaces_with_IPs(ubus_connection)
    local interfaces_with_IPs = {}
    for _, v in pairs(
                    ubus_connection:call("network.interface", "dump", {}).interface) do
        if v["ipv4-address"] ~= nil and next(v["ipv4-address"]) ~= nil then
            for _, addr in pairs(v["ipv4-address"]) do
                addr["interface"] = v.interface
                interfaces_with_IPs[v.l3_device] = addr
            end
        end
    end

    local wireless_APs = {}
    -- ifname might be at radioX.interfaces.X.config.ifname or radioX.interfaces.X.config.wifi_id
    for _, v in pairs(ubus_connection:call("network.wireless", "status", {})) do
        for _, interface in pairs(v.interfaces) do
            if interface.ifname then
                wireless_APs[interface.ifname] = interface.config.network
            elseif interface.config.ifname then
                wireless_APs[interface.config.ifname] = interface.config.network
                -- elseif interface.config.wifi_id then
                --     wireless_APs[interface.config.wifi_id] = interface.config.network
            end
        end
    end
    return {wired = interfaces_with_IPs, wireless = wireless_APs}
end

local function get_interfaces_used_by_wireless(wireless_ap, ubus_connection)
    local interfaces_with_IPs = get_interfaces_with_IPs(ubus_connection)

    local devices = {}

    for _, wireless_interface in
        pairs(interfaces_with_IPs.wireless[wireless_ap]) do
        for dev, v in pairs(interfaces_with_IPs.wired) do
            if v.interface == wireless_interface then
                devices[dev] = interfaces_with_IPs.wired[dev]
            end
        end
    end

    return devices
end

local function get_wireless_on_interface(interface, ubus_connection)
    local interfaces_with_IPs = get_interfaces_with_IPs(ubus_connection)

    local wireless = {}

    for w_name, w_interfaces in pairs(interfaces_with_IPs.wireless) do
        for _, w_interface in pairs(w_interfaces) do
            if w_interface == interfaces_with_IPs.wired[interface].interface then
                wireless[w_name] = w_interfaces
            end
        end
    end

    return wireless
end

local function get_wireless_clients_MACs(wireless_ap, ubus_connection)
    local MACs = {}
    for mac, details in pairs(ubus_connection:call("hostapd." .. wireless_ap,
                                                   "get_clients", {}).clients) do
        if details.authorized or details.preauth then
            table.insert(MACs, mac:upper())
        end
    end
    return MACs
end
----------------------------------------------------------------------
----------------------------- nmap stuff -----------------------------
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
    if args_map.verbose then
        print(
            "From " .. convert_to("string", Find_subnet_min_max(ip, mask, 0)) ..
                " to " .. convert_to("string", Find_subnet_min_max(ip, mask, 1)))
    end

    local target = require "target"

    -- temporarily enable adding new targets irrespective of script arguments and save old value for restoring later
    local old_ALLOW_NEW_TARGETS = target.ALLOW_NEW_TARGETS
    target.ALLOW_NEW_TARGETS = true

    local success = true

    for ip_str in IPv4_iter(ip, mask) do
        local st, err = target.add(ip_str)

        if not st then
            print("\n\nCouldn't add target " .. ip_str .. ": " .. err .. "\n\n")
            success = false
        end
    end

    -- restore ALLOW_NEW_TARGETS state
    target.ALLOW_NEW_TARGETS = old_ALLOW_NEW_TARGETS

    return success
end

prerule = function()
    if args_map.verbose then print("\nprerule") end
    package.cpath = package.cpath .. ";/usr/lib/lua/?.so"
    local ubus = require "ubus_5_3"
    local conn = ubus.connect()
    if not conn then error("Failed to connect to ubusd") end

    local interfaces_with_IPs = get_interfaces_with_IPs(conn)
    Open_state("startup", interfaces_with_IPs.wireless[args_map.interface] and
                   true or false)

    if args_map.verbose then
        print("Scanning " .. (args_map.wireless and "wireless" or "ethernet"))
    end
    if args_map.interface == "--list" then
        if args_map.verbose then
            print(json.generate(interfaces_with_IPs))
        end
        write_to(files.interfaces, json.generate(interfaces_with_IPs) .. "\n")
    else
        if args_map.wireless then
            for _, device in pairs(get_interfaces_used_by_wireless(
                                       args_map.interface, conn)) do
                add_targets(device.address, device.mask)
            end
        else
            add_targets(interfaces_with_IPs.wired[args_map.interface].address,
                        interfaces_with_IPs.wired[args_map.interface].mask)
        end

        write_to(files.results, "[")
    end

    conn:close()
    Close_state("startup")
    return false
end

hostrule = function(host)
    if args_map.verbose then print("\nhostrule") end
    Open_state("filter")
    local mac_addr = host.mac_addr and
                         string.format('%02X:%02X:%02X:%02X:%02X:%02X',
                                       string.byte(host.mac_addr, 1,
                                                   #host.mac_addr)) or ""

    package.cpath = package.cpath .. ";/usr/lib/lua/?.so"
    local ubus = require "ubus_5_3"
    local conn = ubus.connect()
    if not conn then error("Failed to connect to ubusd") end

    local dev_on_wireless = false
    local ret = false

    if args_map.wireless then
        for _, mac in pairs(get_wireless_clients_MACs(args_map.interface, conn)) do
            if args_map.verbose then
                print(mac, mac_addr, mac == mac_addr)
            end
            if mac == mac_addr then dev_on_wireless = true end
        end
        ret = dev_on_wireless and
                  get_interfaces_used_by_wireless(args_map.interface, conn)[host.interface]
    else
        for wireless, _ in pairs(get_wireless_on_interface(args_map.interface,
                                                           conn)) do
            if args_map.verbose then print(wireless) end
            for _, mac in pairs(get_wireless_clients_MACs(wireless, conn)) do
                if args_map.verbose then
                    print(mac, mac_addr, mac == mac_addr)
                end
                if mac == mac_addr then dev_on_wireless = true end
            end
        end
        ret = not dev_on_wireless and host.interface == args_map.interface
    end

    conn:close()
    Close_state("host")
    return ret
end

portrule = function()
    if args_map.verbose then print("\nportrule") end
    return false
end

-- Finish writing to file, delete state file
postrule = function()
    if args_map.verbose then print("\npostrule") end
    Open_state("cleanup")
    if args_map.interface ~= "--list" then
        write_to(files.results, "]\n", file_mode.append)
    end
    Close_state("cleanup")
end

action = function(host, port)
    if port then
        return 0
    else
        if args_map.verbose then print(rt(host.os)) end
        if args_map.verbose then print("\naction") end
        Open_state("action")
        local mac_addr = string.format('%02X:%02X:%02X:%02X:%02X:%02X',
                                       string.byte(host.mac_addr, 1,
                                                   #host.mac_addr)):upper()

        if args_map.verbose and host.os then print(host.os.name) end
        local res = json.generate({
            IP = table.concat({string.byte(host.bin_ip, 1, #host.bin_ip)}, "."),
            MAC = mac_addr,
            vend = get_manufacturer(mac_addr),
            intf = args_map.interface,
            OS = args_map.scan_type == "full" and host.os and host.os.name or ""
        })

        write_to(files.results, (args_map.first and "" or "\n,") .. res,
                 file_mode.append)

        Close_state("action")
        return 0
    end
end
