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
detection_name: HIKE Media
version: 2
description: Voice and Video calls between HIKE users.
bundle_description: $VAR1 = {
          'HIKE Media' => 'Voice and Video calls between HIKE users.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "HIKE Media",
    proto =  DC.ipproto.udp,
    client = {
        init =  'client_init',
        clean = 'client_clean',
        validate =  'client_validate',
        minimum_matches = 1
    }
}

gSfAppIdHIKEMDIA = 4133

gPatterns = {
	audioPattern = { '\003\008\000\032', 0 , gSfAppIdHIKEMDIA },
	videoPattern1 = { '\220\000\002\001', 0 , gSfAppIdHIKEMDIA },
	videoPattern2 = { '\161\000\000\000\036\000', 0 , gSfAppIdHIKEMDIA },
	videoPattern3 = { '\019\001\001\000\068\000', 0 , gSfAppIdHIKEMDIA },
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.audioPattern},
    {DC.ipproto.udp, gPatterns.videoPattern1},
    {DC.ipproto.udp, gPatterns.videoPattern2},
    {DC.ipproto.udp, gPatterns.videoPattern3},
}

gAppRegistry = {
    {gSfAppIdHIKEMDIA, 0},
}

flowTrackerTable = {}

function clientInProcess(context)
    DC.printf('%s: InProcess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, appid: %d\n', DetectorPackageInfo.name,  appProductId)
    gDetector:client_addApp(appServiceId , appTypeId, appProductId , "", gSfAppIdHIKEMDIA )
    flowTrackerTable[context.flowKey] = nil
    return DC.clientStatus.success
end

function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    flowTrackerTable[context.flowKey] = nil
    return DC.clientStatus.einvalid
end


--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
    gDetector:client_init()
    appTypeId = 16
    appProductId = 519
    appServiceId=0

    DC.printf ('%s:DetectorInit(): appTypeId %d, product %d\n', DetectorPackageInfo.name, appTypeId, appProductId )

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,v[2][1])
        end
    end

        for i,v in ipairs(gAppRegistry) do
                pcall(function () gDetector:registerAppId(v[1],v[2]) end)
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
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('%s: packetCount %d, dir %d, size %d\n', DetectorPackageInfo.name, context.packetCount, dir, size)

    if ( dir == 0 ) then
        if ( dstPort == 9998 ) then
            if (gDetector:memcmp(gPatterns.audioPattern[1], #gPatterns.audioPattern[1], gPatterns.audioPattern[2]) == 0) then
                return clientSuccess(context)
            end
        elseif ( dstPort == 8000 ) then
            if (gDetector:memcmp(gPatterns.videoPattern1[1], #gPatterns.videoPattern1[1], gPatterns.videoPattern1[2]) == 0 or
                gDetector:memcmp(gPatterns.videoPattern2[1], #gPatterns.videoPattern2[1], gPatterns.videoPattern2[2]) == 0) then
                return clientSuccess(context)
            end
        elseif ( dstPort > 4000 and dstPort < 4010) then
            if (gDetector:memcmp(gPatterns.videoPattern3[1], #gPatterns.videoPattern3[1], gPatterns.videoPattern3[2]) == 0) then
                return clientSuccess(context)
            end
        end
    end

    return clientFail(context)
end

function client_clean()
end

