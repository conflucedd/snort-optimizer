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
version: 4
description: Process automation protocol, commonly used to control equipment used by utilities such as electricity and water.
bundle_description: $VAR1 = {
          'DNP3' => 'Process automation protocol, commonly used to control equipment used by utilities such as electricity and water.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "DNP3",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

gSfAppIdDnp3 = 616

gPatterns = {
    pattern       = {'\005\100',    0, gSfAppIdDnp3},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.pattern},
}

gAppRegistry = {
	{gSfAppIdDnp3,		         0}
}

flowTrackerTable = {}

function clientInProcess(context)
    DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdDnp3);
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.success
end
function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.einvalid
end

function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name)
    gDetector:client_init()

    appTypeId = 20
    appProductId = 67
    appServiceId = 20066
    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    for i,v in ipairs(gFastPatterns) do
        gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3])
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

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

function client_validate()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetSize = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local size = context.packetSize
    local dir = context.packetDir

    DC.printf ('packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

    if (size < 10) then
        return clientInProcess(context)
    end

    if (DC.checkPattern(gDetector, gPatterns.pattern)) then
        DC.printf ('client DNP3: checking server packet pattern\n')
        matched, body_size_raw = gDetector:getPcreGroups("..(.)", 0)
        body_size = DC.binaryStringToNumber(body_size_raw, 1)
        overhead = getOverhead(size)
        DC.printf (' body_size %d, overhead %d, size %d\n', body_size, overhead, size)
        if (size - overhead == body_size) then
            return clientSuccess(context)
        end
    end

    return clientFail(context)

end

function client_clean()
end

