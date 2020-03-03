local nmap = require "nmap"
local stdnse = require "stdnse"
local target = require "target"

package.path = package.path .. ";/usr/lib/lua/?.so"
local ubus = require "ubus"

description = "Takes arguments from console"

categories = {"discovery"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

function build_results(argument_list)
    local new_table = {}

    for _, arg in argument_list do
        local item = {}
        item.name = ""
        item.value = arg

    end
end

prerule = function()
	return true
end

action = function(host, port)
    result = {}
    result.output_filename = stdnse.get_script_args({"nscan.filename"})
    result.interface = stdnse.get_script_args({"nscan.interface"})
    result.scan_type = stdnse.get_script_args({"nscan.type"})

    targets = {}
    targets[1] = "192.168.1.214"
    
    -- temporarily enable adding new targets irrespective of script arguments and save old value for restoring later
    local old_ALLOW_NEW_TARGETS = target.ALLOW_NEW_TARGETS
    target.ALLOW_NEW_TARGETS = true
    -- for _, item in ipairs(targets) do
    --     local st, err = target.add(item)
    --     if not st then
    --         print("\n\nCouldn't add target " .. item .. ": " .. err .."\n\n")
    --     end
    -- end
    -- restore ALLOW_NEW_TARGETS state
    target.ALLOW_NEW_TARGETS = old_ALLOW_NEW_TARGETS
    
    return result
end
