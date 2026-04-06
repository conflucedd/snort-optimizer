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
detection_name: DNP3
version: 6
description: Process automation protocol, commonly used to control equipment used by utilities such as electricity and water.
bundle_description: $VAR1 = {
          'DNP3' => 'Process automation protocol, commonly used to control equipment used by utilities such as electricity and water.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

gServiceId = 20066
gServiceName = 'DNP3'

DetectorPackageInfo = {
    name =  "DNP3",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdDnp3 = 616

gPatterns = {       
    pattern       = {'\005\100',                  0, gSfAppIdDnp3},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.pattern},
}

gPorts = {
    {DC.ipproto.tcp, 20000},
}

gAppRegistry = {
	{gSfAppIdDnp3,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdDnp3)
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

    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    for i,v in ipairs(gFastPatterns) do
        gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3])
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end

function DetectorInit( detectorInstance)

    DC.printf('%s: DetectorInit()\n',gServiceName)

    gDetector = detectorInstance
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
end

local function getOverhead(size)
    data_len = size - 10
    num_chunks = math.floor(data_len / 18)
    remaining_bytes = data_len % 18
    overhead = 5
    if num_chunks > 0 then
        overhead = overhead + num_chunks * 2
    end
    if remaining_bytes > 0 then
        overhead = overhead + 2
    end
    DC.printf('size %d, data_len %d, num_chunks %d, remaining_bytes %d, overhead %d\n', size, data_len, num_chunks, remaining_bytes, overhead)
    return overhead
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

    if (size < 10) then
        return serviceInProcess(context)
    end

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d size %d\n', gServiceName, context.packetCount, dir, size)

    if (DC.checkPattern(gDetector, gPatterns.pattern)) then
        DC.printf ('%s: checking server packet pattern\n',gServiceName)
        matched, body_size_raw = gDetector:getPcreGroups("..(.)", 0)
        body_size = DC.binaryStringToNumber(body_size_raw, 1)
        overhead = getOverhead(size) 
        DC.printf (' body_size %d, overhead %d, size %d\n', body_size, overhead, size)
        if (size - overhead == body_size) then
            return serviceSuccess(context)
        end
    end

    return serviceFail(context)
end

function DetectorFini()
end
