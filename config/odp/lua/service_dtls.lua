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
detection_name: DTLS
version: 8
description: Datagram Transport Layer Security, essentially TLS over UDP.
bundle_description: $VAR1 = {
          'DTLS' => 'Datagram Transport Layer Security, essentially TLS over UDP.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local HT = hostServiceTrackerModule

DetectorPackageInfo = {
    name =  "DTLS",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
        fini = 'DetectorFini',
    }
}

gServiceId = 20201
gServiceName = 'DTLS'
gSfAppIdDTLS = 4162

gPatterns = {
    handshake_0_9 = {'\022\001\000', 0, gSfAppIdDTLS},
    handshake_1_0 = {'\022\254\255', 0, gSfAppIdDTLS},
    handshake_1_2 = {'\022\254\253', 0, gSfAppIdDTLS},
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.handshake_0_9},
    {DC.ipproto.udp, gPatterns.handshake_1_0},
    {DC.ipproto.udp, gPatterns.handshake_1_2},
}

gAppRegistry = {
	{gSfAppIdDTLS, 0}
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
        gDetector:addService(gServiceId, "", context.version, gSfAppIdDTLS)
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

function DetectorInit( detectorInstance)

    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()\n',gServiceName)

    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
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
    context.flowKey = context.detectorFlow:getFlowKey()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size);

    if (size > 13) then
        matched, len_raw = gDetector:getPcreGroups("...........(..)", 0)
        if (matched) then
            len = DC.binaryStringToNumber(len_raw, 2)
            DC.printf ('%s:DetectorValidator(): len is %d size is %d\n', gServiceName, len, size)
            if (size - 13 == len) then
                if (DC.checkPattern(gDetector, gPatterns.handshake_1_2)) then
                    context.version = "1.2"
                elseif (DC.checkPattern(gDetector, gPatterns.handshake_1_0)) then
                    context.version = "1.0"
                elseif (DC.checkPattern(gDetector, gPatterns.handshake_0_9)) then
                    context.version = "0.9"
                else
                    DC.printf('%s:DetectorValidator(): \n',gServiceName)
                    return serviceFail(context)
                end

                return serviceSuccess(context)
            end
        end
    end

    return serviceFail(context)

end

function DetectorFini()
end
