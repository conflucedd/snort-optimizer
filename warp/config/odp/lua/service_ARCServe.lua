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
detection_name: ARCServe
version: 7
description: Distributed network backup system.
bundle_description: $VAR1 = {
          'DCE/RPC' => 'Distributed Computing Environment / Remote Procedure Calls is the remote procedure call system for the Distributed Computing Environment.',
          'ARCServe' => 'Distributed network backup system.',
          'Epmap' => 'DCE endpoint resolution. Registered with IANA on port 135 TCP/UDP.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceName = 'ARCServe'
gDetector = nil

DetectorPackageInfo = {
    name =  "ARCServe",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdArcserve = 552
gSfAppIdDceRpc = 603
gSfAppIdEpmap = 3085

gServiceIdArcserve = 20069
gServiceIdDceRpc = 5

gPatterns = {
    bind_ack = {'\005\000\012\003\016\000\000\000', 0, gSfAppIdDceRpc},
    bind_ack2 = {'\005\000\012\023\016\000\000\000', 0, gSfAppIdDceRpc},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.bind_ack},
    {DC.ipproto.tcp, gPatterns.bind_ack2},
}

gPorts = {
    {DC.ipproto.tcp, 135},
    {DC.ipproto.tcp, 139},
    {DC.ipproto.tcp, 445},
    {DC.ipproto.tcp, 6502},
    {DC.ipproto.tcp, 6503},
    {DC.ipproto.tcp, 6504},
    {DC.ipproto.tcp, 41523}, 
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
    {gSfAppIdDceRpc,                 1},
	{gSfAppIdArcserve,		         1},
    {gSfAppIdEpmap,                  1},
}

function serviceInProcess(context)

    if ((not context.serviceDetected) or (context.serviceDetected == 0)) then
        gDetector:inProcessService()
    end

    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)

    if ((not context.serviceDetected) or (context.serviceDetected == 0)) then
        gDetector:addService(context.service_id, context.vendor, "", context.appid)
    end

    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.success
end

function serviceFail(context)

    if ((not context.serviceDetected) or (context.serviceDetected == 0)) then
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
        DC.printf('%s: registering port %d\n',gServiceName,v[2])
    end

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2][1])
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function DetectorInit( detectorInstance)

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
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.packetCount = gDetector:getPktCount()
    context.serviceDetected = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey
    local continue = context.detectorFlow:getFlowFlag(DC.flowFlags.continue)

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', 
                gServiceName, context.packetCount, dir, size);

    if (context.serviceDetected == DC.flowFlags.serviceDetected and continue == DC.flowFlags.continue) then
        return DC.serviceStatus.success
    end

    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    if (dir == 1)
    then
        if (context.srcPort == 41523) then
            context.appid = gSfAppIdArcserve
            context.service_id = gServiceIdArcserve
            context.vendor = "Computer Associates"
            return serviceSuccess(context)
        elseif ((size >= 10) and
            ((gDetector:memcmp(gPatterns.bind_ack[1], #gPatterns.bind_ack[1], gPatterns.bind_ack[2]) == 0) or
             (gDetector:memcmp(gPatterns.bind_ack2[1], #gPatterns.bind_ack2[1], gPatterns.bind_ack2[2]) == 0)))
        then
            matched, len_raw = gDetector:getPcreGroups('(..)', 8)
            if (matched) then
                len = DC.reverseBinaryStringToNumber(len_raw, 2)
                DC.printf('%s: size %d, len %d\n', gServiceName, size, len)
                if (len == size) then
                    if (context.srcPort == 135 or context.srcPort == 139 or context.srcPort == 445) then
                        context.appid = gSfAppIdEpmap
                        context.service_id = gServiceIdDceRpc
                        context.vendor = "Microsoft"
                        context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    elseif (context.srcPort == 6502 or context.srcPort == 6503 or context.srcPort == 6504) then
                        context.appid = gSfAppIdArcserve
                        context.service_id = gServiceIdArcserve
                        context.vendor = "Computer Associates"
                    else
                        context.appid = gSfAppIdDceRpc
                        context.service_id = gServiceIdDceRpc
                        context.vendor = ""
                    end 
                    return serviceSuccess(context)
                end
            end
        end
    end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

