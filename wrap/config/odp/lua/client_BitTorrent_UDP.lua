--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: BitTorrent
version: 6
description: A peer-to-peer file sharing protocol used for transferring large amounts of data.
bundle_description: $VAR1 = {
          'BitTorrent' => 'A peer-to-peer file sharing protocol used for transferring large amounts of data.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "BitTorrent UDP",
    proto =  DC.ipproto.udp,
    client = {
        init =  'client_init',
        clean = 'client_clean',
        validate =  'client_validate',
        minimum_matches = 1
    }
}

gName = DetectorPackageInfo.name
gSfAppIdBT = 61
appTypeId = 7
appProductId = 229
appServiceId = 38

gPatterns = {
    -- this one stands by itself
    btt_d1 = {'\100\049\058\097\100\050\058\105\100\050\048\058', 0, gSfAppIdBT},

    -- the following two patterns can be a part of client packets
    btt_p =  {'\000\000\195\080', 12, gSfAppIdBT},
    btt_54 = {'\000\000\000\005\004\000\000', 20, gSfAppIdBT},

    -- this is present in packets starting with btt_41
    btt_15 = {'\000\000\000\000\000\016\000\000', 8, gSfAppIdBT}, 
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.btt_d1},
    {DC.ipproto.udp, gPatterns.btt_p},
    {DC.ipproto.udp, gPatterns.btt_54},
    {DC.ipproto.udp, gPatterns.btt_15},
}

gAppRegistry = {
    --AppIdValue          Extracts Info
    ---------------------------------------
    {gSfAppIdBT,              0}
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdBT);
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.success
end

function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.einvalid
end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init(detectorInstance)

    gDetector = detectorInstance

    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
    gDetector:client_init()

    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if (gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,v[2][1])
        end
    end

    for i,v in ipairs(gAppRegistry) do
        pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end

    if (gDetector.registerClientDetectorCallback) then
        gDetector:registerClientDetectorCallback(gSfAppIdBT, "client_callback");
    end

    return gDetector
end

--[[Validator function registered in DetectorInit()
--]]
function client_validate()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf('%s: packetCount %d, dir %d, size %d\n', gName, context.packetCount, dir, size);

    if (gDetector.isMidStreamSession) then
        local isMidStream = gDetector:isMidStreamSession()
        if (isMidStream == 1) then
            return clientFail(context)
        end
    end

    local isHttp = context.detectorFlow:getFlowFlag(DC.flowFlags.httpSession)

    if ((not isHttp) or (isHttp == 0)) then
        if (dir == 0 and size > 19) then
            if (gDetector.addHostPortAppDynamic) then
                src_ip_str = DC.intToIPv4(context.srcIp, 1)
                dst_ip_str = DC.intToIPv4(context.dstIp, 1)

                DC.printf('%s: Adding hostPortCache entry %s:%d %d - %d 1\n', gName, dst_ip_str, dstPort, DC.ipproto.tcp, gSfAppIdBT)
                gDetector:addHostPortAppDynamic(1, gSfAppIdBT, dst_ip_str, dstPort, DC.ipproto.tcp);
            end
            return clientSuccess(context)
        end
    end

    return clientFail(context)
end

function client_callback()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf('%s: packetCount %d, dir %d, size %d\n', gName, context.packetCount, dir, size);

    if (gDetector.isMidStreamSession) then
        local isMidStream = gDetector:isMidStreamSession()
        if (isMidStream == 1) then
            return DC.clientStatus.einvalid
        end
    end

    local isHttp = context.detectorFlow:getFlowFlag(DC.flowFlags.httpSession)

    if ((not isHttp) or (isHttp == 0)) then
        if (dir == 0) then
            if (gDetector.addHostPortAppDynamic) then
                src_ip_str = DC.intToIPv4(context.srcIp, 1)
                dst_ip_str = DC.intToIPv4(context.dstIp, 1)

                DC.printf('%s: Adding hostPortCache entry %s:%d %d - %d 1\n', gName, dst_ip_str, dstPort, DC.ipproto.tcp, gSfAppIdBT)
                gDetector:addHostPortAppDynamic(1, gSfAppIdBT, dst_ip_str, dstPort, DC.ipproto.tcp);
            end
            return clientSuccess(context)
        end
    end

    return DC.clientStatus.einvalid
end

function client_clean()
end
