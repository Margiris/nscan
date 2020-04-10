---------------------------- IP functions ----------------------------
function convert_IPv4_str_to_table(ip_str)
    print(ip_str)

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

function convert_IPv4_str_to_decimal(ip_str)
    print(ip_str)

    local ip_dec
    local octet_index = 0
    -- local st = {}

    ip_str:gsub("%d+", function(octet)
        -- local a = ""
        for i = 8, 1, -1 do
            ip_bin[i + octet_index * 8] = math.floor(octet % 2)
            octet = octet // 2
            -- a = a .. ip_bin[i + octet_index * 8]
        end

        octet_index = octet_index + 1
        -- st[octet_index] = string.reverse(a)
    end)

    -- print(st[1] .. "." .. st[2] .. "." .. st[3] .. "." .. st[4])
    return ip_bin
end

function table_to_IPv4_str(ip_bin)
    local ip = {}
    for o = 0, 3 do
        local octet = 0
        for i = 1, 8 do octet = octet * 2 + ip_bin[i + o * 8] end
        ip[o + 1] = octet
    end

    return ip[1] .. "." .. ip[2] .. "." .. ip[3] .. "." .. ip[4]
end

--[[
    Find max or min subnet IP from given IP and mask.
    ip_in_subnet - 
    mask - 
    min_max - 0 if min, 1 if max
]]
function find_subnet_min_max(ip_in_subnet, mask, min_max)
    local ip = {}
    for i = 1, mask do ip[i] = ip_in_subnet[i] end
    for i = mask + 1, 31 do ip[i] = min_max end
    if mask < 32 then ip[32] = 1 - min_max end
    return ip
end

function IPv4_iter(ip, mask)
    local start = find_subnet_min_max(ip, mask, 0)
    local count = 2 ^ (32 - mask) - 2
    -- local max = find_subnet_min_max(ip, mask, 1)
    return function()
        count = count - 1
        if count > 0 then return min end
    end
end

function test()
    local ip_str = "192.168.1.48"
    local mask = 22

    local ip = convert_IPv4_str_to_table(ip_str)
    local ip_min = find_subnet_min_max(ip, mask, 0)
    local ip_max = find_subnet_min_max(ip, mask, 1)
    print(table_to_IPv4_str(ip_min))
    print(table_to_IPv4_str(ip_max))
    print()
    print(#ip_min)
end
----------------------------------------------------------------------
