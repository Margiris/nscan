local nmap = require "nmap"
local stdnse = require "stdnse"
local target = require "target"

description = "Takes arguments from console"

categories = {"discovery"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

function get_arguments ()
    args = {}
    args.output_filename = stdnse.get_script_args({"nscan.filename"})
    args.interface = stdnse.get_script_args({"nscan.interface"})
    args.scan_type = stdnse.get_script_args({"nscan.type"})
    return args
end

function print_table_recursively (tbl, prefix)
    prefix = prefix or ""
    for k, v in pairs(tbl) do
        if (type(v) == "table") then
            print(prefix .. k .. ":")
            print_table_recursively(v, prefix .. "\t")
        else
            print(prefix .. k .. " = " .. tostring(v))
        end
    end
end

prerule = function()
    package.cpath = package.cpath .. ";/usr/lib/lua/?.so"
    local ubus = require "ubus_5_3"
 
    local conn = ubus.connect()
    if not conn then
        error("Failed to connect to ubusd")
    end

    args = get_arguments()

    if args.interface == "--list" then
        local interface_data = conn:call("network.device", "status", {})
        for k, _ in pairs(interface_data) do
            print(k)
        end
    else
        -- Call a procedure
        local interface_data = conn:call("network.device", "status", { name = args.interface })
        print(args.interface .. ":")
        print_table_recursively(interface_data, "\t")
        print("\nMAC address of interface " .. args.interface .. " is " .. tostring(interface_data["macaddr"]).. "\n")
    end

    
    -- Close connection
    conn:close()
    
    targets = {}
    targets[1] = "192.168.1.214"
    
    -- temporarily enable adding new targets irrespective of script arguments and save old value for restoring later
    local old_ALLOW_NEW_TARGETS = target.ALLOW_NEW_TARGETS
    target.ALLOW_NEW_TARGETS = true
    for _, item in ipairs(targets) do
        local st, err = target.add(item)
        if not st then
            print("\n\nCouldn't add target " .. item .. ": " .. err .."\n\n")
        end
    end
    -- restore ALLOW_NEW_TARGETS state
    target.ALLOW_NEW_TARGETS = old_ALLOW_NEW_TARGETS

	return true
end

action = function(host, port)
    return 0
end
