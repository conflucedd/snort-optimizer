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
detection_name: QUIC
version: 6
description: Quick UDP Internet Connections, an experimental, mutliplexing transport layer protocol.
bundle_description: $VAR1 = {
          'QUIC' => 'Quick UDP Internet Connections, an experimental, mutliplexing transport layer protocol.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "QUIC",
    proto =  DC.ipproto.udp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

gSfAppIdQUIC = 4023

gPatterns = {
    flags_9 = { '\009', 0, gSfAppIdQUIC},
    flags_13 = { '\013', 0, gSfAppIdQUIC},
    flags_25 = { '\025', 0, gSfAppIdQUIC},
    flags_29 = { '\029', 0, gSfAppIdQUIC},
    flags_41 = { '\041', 0, gSfAppIdQUIC},
    flags_45 = { '\045', 0, gSfAppIdQUIC},
    flags_57 = { '\057', 0, gSfAppIdQUIC},
    flags_61 = { '\061', 0, gSfAppIdQUIC},
    
    verQV50 = { 'Q050', 1, gSfAppIdQUIC},
    verQV46 = { 'Q046', 1, gSfAppIdQUIC},
    ver = { "Q0", 9, gSfAppIdQUIC},
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.ver},
    {DC.ipproto.udp, gPatterns.verQV46 },
    {DC.ipproto.udp, gPatterns.verQV50 },
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdQUIC,		         0}
}

--contains detector specific data related to a flow 
flowTrackerTable = {}

function clientInProcess(context)

    DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, context.ver, gSfAppIdQUIC);
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
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name)
    gDetector:client_init()
    appTypeId = 23
    appProductId = 4023
    appServiceId = 20203
    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

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
    context.packetSize = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local size = context.packetSize
    local dir = context.packetDir

    DC.printf ('QUIC packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

    -- check for a version, and one of a set of flags.
    -- these must be present at the start of a QUIC connection
    -- note that after a connection is negotiated,
    -- it becomes much harder to identify a QUIC session
    -- so we are not expecting to be very good at midstream detection
    if (size >= 12 and
        ((DC.checkPattern(gDetector, gPatterns.verQV46) or
        DC.checkPattern(gDetector, gPatterns.verQV50)) or  
        (DC.checkPattern(gDetector, gPatterns.ver) and
        (DC.checkPattern(gDetector, gPatterns.flags_9) or 
         DC.checkPattern(gDetector, gPatterns.flags_13) or
         DC.checkPattern(gDetector, gPatterns.flags_25) or
         DC.checkPattern(gDetector, gPatterns.flags_29) or
         DC.checkPattern(gDetector, gPatterns.flags_41) or
         DC.checkPattern(gDetector, gPatterns.flags_45) or
         DC.checkPattern(gDetector, gPatterns.flags_57) or
         DC.checkPattern(gDetector, gPatterns.flags_61))))
        )
    then
        DC.printf(' patterns check out for QUIC\n')
        matched, ver = gDetector:getPcreGroups('Q0(..)', 9)
        matched1, ver = gDetector:getPcreGroups('Q0(..)', 1)
        if (matched or matched1) then
            DC.printf(' ver is %s\n',ver)
            context.ver = ver
            return clientSuccess(context)
        end
    end

    return clientFail(context)

end

function client_clean()
end
