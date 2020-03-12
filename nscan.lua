-- local nmap = require "nmap"
local stdnse = require"stdnse"
local target = require"target"

description = "Takes arguments from console"
categories = {"discovery"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

function contains(tbl, value)
    for _, v in pairs(tbl) do
        if v == value then
            return true
        end
    end
    return false
end

function get_table_keys_list(tbl)
    local keyset = {}
    for k, _ in pairs(tbl) do
        table.insert(keyset, k)
    end
    return keyset
end

function recurse_table_to_json_string(tbl, filter, indentation, prefix_key)
    if not tbl then
        return "\n*** Table is nil ***\n"
    end

    filter = filter or {}
    indentation = indentation or ""
    prefix_key = not (not prefix_key or false)
    local result = ""
    for k, v in pairs(tbl) do
        if (type(v) == "table") then
            if next(v) ~= nil then -- only recurse if table is not empty
                local deeper = recurse_table_to_json_string(v, filter, "\t" .. indentation, prefix_key)
                if deeper ~= "" or next(filter) == nil then -- suppress empty table titles if filtering is used
                    result = result .. indentation .. k .. ":\n" .. deeper
                end
            end
        else
            if next(filter) == nil or contains(filter, k) then
                if prefix_key then
                    result = result .. indentation .. k .. " = "
                end
                result = result .. tostring(v) .. "\n"
            end
        end
    end
    return result
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
    if temp.name == nil then
        return get_table_keys_list(device_list)
    end
    return device_list
end

function get_network_interface_data(ubus_connection, device_name)
    return ubus_connection:call("network.interface." .. device_name, "dump", { })
end

function get_vlans(ubus_connection, device_name)
    local dump = ubus_connection:call("uci", "get", { config="network", section="@switch_vlan[0]"})

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
    if not conn then
        error("Failed to connect to ubusd")
    end

    local args = get_arguments()

    -- local device_info = get_network_devices_info(conn, args.interface)
    -- print(recurse_table_to_json_string(device_info, {}, "", true))

    -- local if_data = get_network_interface_data(conn, args.interface)
    -- print(recurse_table_to_json_string(if_data.interface, {"l3_device", "interface", "mask", "address"}))

    local dump = get_vlans(conn)
    print(recurse_table_to_json_string(dump))

    conn:close()

    -- add_targets()

    return true
end

action = function(host, port) return 0 end