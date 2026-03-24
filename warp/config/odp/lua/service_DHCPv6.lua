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
detection_name: DHCPv6
version: 2
description: Dynamic Host Configuration Protocol for IPv6.
bundle_description: $VAR1 = {
          'DHCPv6' => 'Dynamic Host Configuration Protocol for IPv6.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name = "DHCPv6",
    proto = DC.ipproto.udp,
    server = {
        init = 'DetectorInit',
        validate = 'DetectorValidator',
    }
}

gServiceId = 20004
gServiceName = "DHCPv6"
gDetector = nil
gSfAppIdDHCPv6 = 116

--port based detection
gPorts = {
    {DC.ipproto.udp, 546},
    {DC.ipproto.udp, 547},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdDHCPv6,	         0}
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:inProcessService()
    end

    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:addService(gServiceId, "", "", gSfAppIdDHCPv6)
    end

    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:failService()
    end

    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()

    --register port based detection
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    for i,v in ipairs(gAppRegistry) do
	pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end
end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function DetectorInit(detectorInstance)

    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', gServiceName);

    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')

    registerPortsPatterns()

    return gDetector
end

--[[Validator function registered in DetectorInit()
--]]
function DetectorValidator()
    local context = {}

    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()

    local dir =  context.packetDir
    local size = context.packetDataLen
    local flowKey = context.flowKey
    local srcPort = context.srcPort
    local dstPort = context.dstPort

    DC.printf ('%s:DetectorValidator(): packetCount %d\n', gServiceName, context.packetCount);

    if (size == 0) then
        return serviceInProcess(context)
    end

    if (srcPort == 547 or dstPort == 547) then
        return serviceSuccess(context)
    elseif (srcPort == 546 or dstPort == 546) then
        return serviceSuccess(context)
    else
        return serviceFail(context)
    end
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

