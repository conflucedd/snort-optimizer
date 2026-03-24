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
detection_name: Omron FINS
version: 2
description: Factory Interface Network Service, a suite of protocols used by Omron programmable logic controllers.
bundle_description: $VAR1 = {
          'Omron FINS' => 'Factory Interface Network Service, a suite of protocols used by Omron programmable logic controllers.'
        };

--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "Omron FINS",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20207
gServiceName = 'Omron FINS'
gSfAppIdFINS = 4590

gPatterns = {
    -- TCP packets have a very clear invariant pattern
    fins_header = {"FINS", 0, gSfAppIdFINS},
    -- For UDP, FINS has a twelve-byte header but there are not many invariants we can use.
    -- The first byte is the "ICF" byte, and all but the first, second, and eighth bits are
    -- reserved. Because the second byte is also reserved, there are only a handful of valid
    -- values for the first two bytes. In order to avoid false positives we should not use these
    -- as fast patterns, but only for validation if the port has been hit.
    udp_1 = {'\000\000', 0, gSfAppIdFINS},
    udp_2 = {'\001\000', 0, gSfAppIdFINS},
    udp_3 = {'\064\000', 0, gSfAppIdFINS},
    udp_4 = {'\065\000', 0, gSfAppIdFINS},
    udp_5 = {'\128\000', 0, gSfAppIdFINS},
    udp_6 = {'\129\000', 0, gSfAppIdFINS},
    udp_7 = {'\192\000', 0, gSfAppIdFINS},
    udp_8 = {'\193\000', 0, gSfAppIdFINS},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.fins_header},
}

gPorts = {
    {DC.ipproto.tcp, 9600},
    {DC.ipproto.udp, 9600},
}

gAppRegistry = {
    {gSfAppIdFINS, 0}
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if not flowFlag or flowFlag == 0 then
        gDetector:inProcessService()
    end

    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if not flowFlag or flowFlag == 0 then
        gDetector:addService(gServiceId, "Omron", "", gSfAppIdFINS)
    end

    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if not flowFlag or flowFlag == 0 then
        gDetector:failService()
    end

    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()
    for i,v in ipairs(gFastPatterns) do
        if gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0 then
            DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2][1])
        end
    end

    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    for i,v in ipairs(gAppRegistry) do
        pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()\n',gServiceName)
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()
    return gDetector
end

local function isWrongPort(proto, srcPort)
    for i,v in ipairs(gPorts) do
        if proto == v[1] and srcPort == v[2] then
            return false
        end
    end
    return true
end

function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
        context.packetCount, dir, size)

    if size < 12 or dir == 0 then
        return serviceInProcess(context)
    end

    -- The getL4Protocol API has been around for a long time but let's do some defensive coding
    -- in case anyone is running a very old version of the lua API.
    if gDetector.getL4Protocol then
        proto = gDetector:getL4Protocol()
        if isWrongPort(proto, srcPort) then
            return serviceFail(context)
        end
    -- In the rare case that getL4Protocol is not supported, manually setting the proto to 17
    -- is safe, since TCP frames should all have the fins_header pattern we check for below.
    else
        proto = 17
    end

    -- double-check pattern for TCP (shouldn't appear on UDP, but this is not worth
    -- checking the protocol for).
    if DC.checkPattern(gDetector, gPatterns.fins_header) then
        return serviceSuccess(context)
    end

    -- for UDP, we already know the port is okay, but let's double-check these patterns.
    if proto == 17 and
        (DC.checkPattern(gDetector, gPatterns.udp_1) or
         DC.checkPattern(gDetector, gPatterns.udp_2) or
         DC.checkPattern(gDetector, gPatterns.udp_3) or
         DC.checkPattern(gDetector, gPatterns.udp_4) or
         DC.checkPattern(gDetector, gPatterns.udp_5) or
         DC.checkPattern(gDetector, gPatterns.udp_6) or
         DC.checkPattern(gDetector, gPatterns.udp_7) or
         DC.checkPattern(gDetector, gPatterns.udp_8)) then
            return serviceSuccess(context)
    end

    return serviceFail(context)

end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
