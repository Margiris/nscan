-- local nmap = require "nmap"
local stdnse = require "stdnse"
local target = require "target"

description = "Takes arguments from console"
categories = {"discovery"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

function contains(tbl, value, full_match)
    full_match = full_match or false
    for _, v in pairs(tbl) do
        if (full_match and v == value) or
            (not full_match and string.find(value, v, 1, true)) then
            return true
        end
    end
    return false
end

function get_table_keys_list(tbl)
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
    [prefix_key: boolean whether to prefix value with key. Default: true]
--]]
function recurse_table_to_json_string(tbl, filter, indentation, prefix_key,
                                      level)
    if not tbl then return "\n*** Table is nil ***\n" end

    filter = filter or {}
    if next(filter) ~= nil and type(filter[1]) ~= "boolean" then
        table.insert(filter, 1, false)
    end

    indentation = indentation or "\t"
    level = level or 0

    if not prefix_key then prefix_key = true end

    local result = ""
    for k, v in pairs(tbl) do
        if (type(v) == "table") then
            if next(v) ~= nil then -- only recurse if table is not empty
                local deeper = recurse_table_to_json_string(v, filter,
                                                            indentation,
                                                            prefix_key,
                                                            level + 1)
                if deeper ~= "" or next(filter) == nil then -- suppress empty table titles if filtering is used
                    result = result .. string.rep(indentation, level) .. k ..
                                 ":\n" .. deeper
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
                             tostring(v) .. "\n"
            end
        end
    end
    return result
end

-- Shorthand for recurse_table_to_json_string().
function rt(tbl, filter, indentation, prefix_key, level)
    return recurse_table_to_json_string(tbl, filter, indentation, prefix_key,
                                        level)
end

function get_arguments()
    local args = {}
    args.output_filename = stdnse.get_script_args({"nscan.filename"})
    args.interface = stdnse.get_script_args({"nscan.interface"})
    args.scan_type = stdnse.get_script_args({"nscan.type"})
    return args
end

function get_network_devices_info(ubus_connection, device_name)
    local temp = {}
    if device_name ~= "" and device_name ~= "--list" and device_name ~= "--all" then
        temp.name = device_name
    end

    local device_list = ubus_connection:call("network.device", "status", temp)
    if temp.name == nil then return get_table_keys_list(device_list) end
    return device_list
end

function get_network_interface_data(ubus_connection, device_name)
    return ubus_connection:call("network.interface." .. device_name, "dump", {})
end

function get_wifi_info(ubus_connection)
    local wifi_info = ubus_connection:call("network.wireless", "status", {})

    local network_name = rt(wifi_info, {false, "network"}, "")

    print(network_name)
    local network_name = recurse_table_to_json_string(wifi_info,
                                                      {false, "network"}, "")

    print(network_name)
    return wifi_info
end

function get_vlans(ubus_connection, device_name)
    local dump = ubus_connection:call("uci", "get", {config = "network"})

    return dump
end

function add_targets()
    success = true
    targets = {}
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
    --[[
    local device_info = get_network_devices_info(conn, args.interface)
    print(rt(device_info, {}, "", true))
    --]]
    --[[
    -- local if_data = get_network_interface_data(conn, args.interface)
    -- print(rt(if_data.interface, {true, "l3_device", "interface", "mask", "address"}))
    --]]
    --[[
    local dump = get_vlans(conn)
    print(rt(get_table_keys_list(dump.values)))
    print(rt(dump.values))
    --]]
    print(rt(get_wifi_info(conn)))

    conn:close()

    -- add_targets()

    return true
end

action = function(host, port) return 0 end
