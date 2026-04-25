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
detection_name: ZenVPN
version: 3
description: VPN/anonymizer app.
--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name = "ZenVPN",
    proto = DC.ipproto.tcp,
    client = {
        init = 'client_init',
        clean = 'client_clean',
        validate = 'client_validate',
        minimum_matches = 1
    }
}

gName = DetectorPackageInfo.name
gAppIdZenVPN = 4150

gPatterns = {

    common1 = {'\000\000\000\001', 31, gAppIdZenVPN},
    common2 = {'\000\000\000\002', 31, gAppIdZenVPN},
    common3 = {'\000\000\000\003', 31, gAppIdZenVPN},

    client1 = {'\000\042\056', 0, gAppIdZenVPN},
    client2 = {'\000\050\040', 0, gAppIdZenVPN},
    client3 = {'\001\035\032', 0, gAppIdZenVPN},

}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.common1},
    {DC.ipproto.tcp, gPatterns.common2},
    {DC.ipproto.tcp, gPatterns.common3},
}

gDNSHostPatternList = {
    { 1, gAppIdZenVPN, "zenvpn.net" },
}

gAppRegistry = {
    --AppIdValue          Extracts Info
    ---------------------------------------
    {gAppIdZenVPN,              0}
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gAppIdZenVPN);
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

    appTypeId = 26
    appProductId = 525
    appServiceId = 0

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

    if gDetector.addDNSHostPattern then
        for i,v in ipairs(gDNSHostPatternList) do
            gDetector:addDNSHostPattern(v[1],v[2],v[3]);
        end
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
    local rft = FT.getFlowTracker(flowKey)

    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {client_seen=0})
    end

    DC.printf('%s: packetCount %d, dir %d, size %d\n', gName, context.packetCount, dir, size);

    if (dir == 1 or size == 0) then
        return clientInProcess(context)
    end

    if (dir == 0) then

        if (rft.client_seen == 0 and
            DC.checkPattern(gDetector, gPatterns.common1) and
            DC.checkPattern(gDetector, gPatterns.client1)) then

            rft.client_seen = 1
            return clientInProcess(context)
        end

        if (rft.client_seen == 1 and
            DC.checkPattern(gDetector, gPatterns.common2) and
            DC.checkPattern(gDetector, gPatterns.client2)) then

            rft.client_seen = 2
            return clientInProcess(context)
        end

        if (rft.client_seen == 2 and
            DC.checkPattern(gDetector, gPatterns.common3) and
            DC.checkPattern(gDetector, gPatterns.client3)) then

            return clientSuccess(context)
        end

    end

    return clientFail(context)

end


function client_clean()
end
