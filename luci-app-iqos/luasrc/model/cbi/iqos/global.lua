-- Copyright 2026 ilxp <lixp@live.com>
-- Licensed to the public under the Apache License 2.0.

local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()
local net = require "luci.model.network".init()
local qos = require "luci.model.iqos"
local http = require "luci.http"
local json = require "luci.jsonc"

local m, s, o
local upload_classes = {}
local download_classes = {}
local iqos = "iqos"

-- 从 UCI 中加载已有的上传/下载类别
uci:foreach(iqos, "upload_class", function(s)
    local class_alias = s.name
    if class_alias then
        upload_classes[#upload_classes + 1] = {name = s[".name"], alias = class_alias}
    end
end)

uci:foreach(iqos, "download_class", function(s)
    local class_alias = s.name
    if class_alias then
        download_classes[#download_classes + 1] = {name = s[".name"], alias = class_alias}
    end
end)

m = Map("iqos", translate("iQoS"),
    translate("iQoS provides more refined bandwidth control, supporting 4 algorithms including HTP+CAKE,HFSC+CAKE,HTP+FQ_CODEL,CAKE-MQ. It also supports active congestion control, dynamic classification, ACK speed limit, and TCP/UDP optimization. Ensure low latency for gaming and VoIP while efficiently managing high traffic.") ..
    '<br/>' ..
    translate("Author : ") .. '<a href="https://github.com/ilxp/iqos-openwrt" target="_blank">ilxp </a>' .. 
    translate("Donate : ") .. '<a href="https://afdian.com/a/ioprx/plan" target="_blank">认可iQoS我将做的更好！</a>')
	
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true

-- QoS 启用/禁用开关
o = s:option(Flag, "enabled", translate("Enable QoS"), translate("Enable or disable the QoS service"))
o.default = "0"
o.rmempty = false
o.enabled = "1"
o.disabled = "0"

-- 网络接口设置
o = s:option(Value, "wan_interface", translate("Network Interface"), translate("Select the network interface"))
local interfaces = sys.exec("ls -l /sys/class/net/ | grep virtual 2>/dev/null |awk '{print $9}' 2>/dev/null")
for interface in string.gmatch(interfaces, "%S+") do
   o:value(interface)
end
local wan = qos.get_wan()
if wan then o.default = wan:ifname() end
o.rmempty = false

-- QoS算法选择
o = s:option(ListValue, "algorithm", translate("QoS Algorithm"), 
    translate("HFSC: Guarantees low latency, ideal for gaming/voip.HTB: Flexible bandwidth control, good for multi-service management.CAKE: Modern and plug-and-play, simple to use."))
o:value("htb_cake", "HTB+CAKE")
o:value("htb_fqcodel", "HTB+FQ_CODEL")
o:value("hfsc_cake", "HFSC+CAKE")
o:value("cake", "CAKE-MQ")
o.default = "htb_cake"

-- 自定义规则选择
local ruleset_dir = "/etc/iqos/rulesets"
local ruleset_opts = { ["default.ru"] = "Default" }
if nixio.fs.access(ruleset_dir) then
    for f in nixio.fs.dir(ruleset_dir) do
        if f:match("%.ru$") then
            ruleset_opts[f] = f
        end
    end
end

local ruleset = s:option(ListValue, "ruleset", translate("Custom Rule"))
ruleset.default = "default.ru"
for k, v in pairs(ruleset_opts) do
    ruleset:value(k, v)
end
ruleset.description = translate("Select a custom rule file to override built-in rules.")

-- 链路类型
o = s:option(ListValue, "linklayer", translate("Linklayer Type"), translate("Select linkelayer type"))
o:value("ethernet", translate("Ethernet"))
o:value("atm", "ATM")
o:value("adsl", "ADSL")
o.default = "atm"

-- 链路开销
o = s:option(Value, "overhead", translate("Linklayer Overhead"), translate("Set linklayer overhead"))
o.datatype = "uinteger"
o.default="32"

-- ACK 限速开关
o = s:option(Flag, "enable_ack_limit", translate("Enable ACK Limit"),
             translate("Limit ACK packets to prevent bufferbloat. Recommended for asymmetric links."))
o.default = "0"
o.rmempty = false

-- TCP 升级开关
o = s:option(Flag, "enable_tcp_upgrade", translate("Enable TCP Upgrade"),
             translate("Prioritize slow TCP connections (e.g., web browsing) to improve responsiveness."))
o.default = "0"
o.rmempty = false

-- UDP 限速开关
o = s:option(Flag, "enable_udp_limit", translate("Enable UDP Limit"),
             translate("Rate limit UDP packets to prevent abuse. Packets exceeding the limit will be dropped or marked as bulk."))
o.default = "0"
o.rmempty = false

-- 动态分类总开关
o = s:option(Flag, "enable_dclassify", translate("Enable Dynamic Classification"),
             translate("Automatically detect bulk clients and high-throughput services, and adjust their priority accordingly."))
o.default = "0"
o.rmempty = false

-- 调整百分比开关
o = s:option(Flag, "auto_adjust_percentages", translate("Auto Adjust Percentages"),
             translate("Automatically adjust class percentages and min/max bandwidth based on total bandwidth and linklayer type with priorities ranging from 1 to 4,Only supports 4 class."))
o.default = "1"
o.rmempty = false

-- 获取当前规则集文件路径
local function get_current_ruleset_file()
    local ruleset = uci:get(iqos, "global", "ruleset") or "default.ru"
    if not ruleset:match("%.ru$") then ruleset = ruleset .. ".ru" end
    return "/etc/iqos/rulesets/" .. ruleset
end

-- 从规则集文件中解析指定类型的类别
local function parse_classes_from_file(filepath, class_type)
    local classes = {}
    local f = io.open(filepath, "r")
    if not f then return classes end
    local in_class = false
    local class_name = nil
    for line in f:lines() do
        local match = line:match("^%s*config%s+" .. class_type .. "%s+'([^']+)'")
        if match then
            class_name = match
            in_class = true
        elseif in_class and line:match("^%s*option%s+name%s+'([^']+)'") then
            local name = line:match("^%s*option%s+name%s+'([^']+)'")
            if name then
                table.insert(classes, { name = class_name, alias = name })
            end
            in_class = false
        end
    end
    f:close()
    return classes
end

-- 获取上传类别列表（如果 UCI 中已存在则使用，否则从规则集文件解析）
if #upload_classes == 0 then
    local ruleset_file = get_current_ruleset_file()
    local parsed = parse_classes_from_file(ruleset_file, "upload_class")
    for _, v in ipairs(parsed) do
        upload_classes[#upload_classes+1] = v
    end
end

-- 获取下载类别列表
if #download_classes == 0 then
    local ruleset_file = get_current_ruleset_file()
    local parsed = parse_classes_from_file(ruleset_file, "download_class")
    for _, v in ipairs(parsed) do
        download_classes[#download_classes+1] = v
    end
end

-- ========== 上传带宽配置 ==========
s = m:section(NamedSection, "upload", "upload", translate("Upload Settings"))
s.anonymous = true

o = s:option(ListValue, "default_class", translate("Default Service Class"),
    translate("Specifies how packets that do not match any rule should be classified."))
for _, class in ipairs(upload_classes) do
    o:value(class.name, class.alias)
end

o = s:option(Value, "total_bandwidth", translate("Total Upload Bandwidth"),
    translate("Enter the total upload bandwidth in kbit/s (kilobits per second). It is recommended to set this to about 90% of your actual upload speed. "
    .. "Enter 0 or leave blank to disable upload QoS. Example: 50000 for 50 Mbit/s."))
o.datatype = "uinteger"
o.placeholder = "45000"
o.rmempty = true

-- ========== 下载带宽配置 ==========
s = m:section(NamedSection, "download", "download", translate("Download Settings"))
s.anonymous = true

o = s:option(ListValue, "default_class", translate("Default Service Class"),
    translate("Specifies how packets that do not match any rule should be classified."))
for _, class in ipairs(download_classes) do
    o:value(class.name, class.alias)
end

o = s:option(Value, "total_bandwidth", translate("Total Download Bandwidth"),
    translate("Enter the total download bandwidth in kbit/s (kilobits per second). It is recommended to set this to about 90% of your actual download speed. "
    .. "Enter 0 or leave blank to disable download QoS. Example: 100000 for 100 Mbit/s."))
o.datatype = "uinteger"
o.placeholder = "180000"
o.rmempty = true

-- 配置IFB设备
local function get_ifb_devices()
    local devices = {}
    local handle = io.popen("ls /sys/class/net/ 2>/dev/null | grep '^ifb'")
    if handle then
        for line in handle:lines() do
            devices[#devices+1] = line
        end
        handle:close()
    end
    return devices
end

local ifb_devices_list = get_ifb_devices()

o = s:option(Value, "ifb_device", translate("IFB Device"),
    translate("Select or enter the IFB (Intermediate Functional Block) device used for ingress shaping. Typically ifb0."))

for _, ifb in ipairs(ifb_devices_list) do
    o:value(ifb)
end

local current_ifb = uci:get(iqos, "download", "ifb_device")
if current_ifb and current_ifb ~= "" then
    o.default = current_ifb
else
    if #ifb_devices_list > 0 then
        o.default = ifb_devices_list[1]
    else
        o.default = "ifb0"
    end
end
o.placeholder = "ifb0"

-- ================== 保存后处理（使用标准 on_commit 回调） ==================
function m.on_commit(self)
    sys.call("logger -t iqos '配置已提交，正在处理服务启停'")
    
    -- 1. 同步增强功能开关到各自的配置节（确保服务启动时能读取到最新值）
    local ack_enabled = uci:get(iqos, "global", "enable_ack_limit") or "0"
    local tcp_enabled = uci:get(iqos, "global", "enable_tcp_upgrade") or "0"
    local udp_enabled = uci:get(iqos, "global", "enable_udp_limit") or "0"
    local dynamic_enabled = uci:get(iqos, "global", "enable_dclassify") or "0"

    if not uci:get(iqos, "ack_limit") then
        uci:set(iqos, "ack_limit", "ack_limit")
    end
    uci:set(iqos, "ack_limit", "enabled", ack_enabled)

    if not uci:get(iqos, "tcp_upgrade") then
        uci:set(iqos, "tcp_upgrade", "tcp_upgrade")
    end
    uci:set(iqos, "tcp_upgrade", "enabled", tcp_enabled)

    if not uci:get(iqos, "udp_limit") then
        uci:set(iqos, "udp_limit", "udp_limit")
    end
    uci:set(iqos, "udp_limit", "enabled", udp_enabled)

    uci:set(iqos, "global", "enable_dclassify", dynamic_enabled)
    uci:commit(iqos)   -- 提交同步的更改

    -- 2. 如果是“保存&应用”操作，则重启服务；仅保存时不重启
    if http.formvalue("cbi.apply") then
        local enabled = uci:get(iqos, "global", "enabled") or "0"
        if enabled == "1" then
            sys.call("/etc/init.d/iqos restart >/dev/null 2>&1")
            sys.call("logger -t iqos 'QoS 服务已重启'")
        else
            sys.call("/etc/init.d/iqos stop >/dev/null 2>&1")
            sys.call("logger -t iqos 'QoS 服务已停止'")
        end
    else
        sys.call("logger -t iqos '配置已保存，服务未重启（仅保存）'")
    end
    
    return true
end

return m