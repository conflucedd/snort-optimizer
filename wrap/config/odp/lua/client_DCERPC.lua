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
detection_name: DCE/RPC
version: 9
description: Distributed Computing Environment / Remote Procedure Calls is the remote procedure call system for the Distributed Computing Environment.
bundle_description: $VAR1 = {
          'Epmap' => 'DCE endpoint resolution. Registered with IANA on port 135 TCP/UDP.',
          'ARCServe' => 'Distributed network backup system.',
          'DCE/RPC' => 'Distributed Computing Environment / Remote Procedure Calls is the remote procedure call system for the Distributed Computing Environment.',
          'MAPI' => 'The protocol that Microsoft Outlook uses to communicate with Microsoft Exchange.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "DCERPC",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

gSfAppIdDceRpc = 603
gSfAppIdMapi = 277
gSfAppIdEpmap = 3085
gSfAppIdArcserve = 552

gClientIdArcserve = 70
gClientIdMapi = 89
gClientIdEpmap = 514
gClientIdDceRpc = 515

gServiceIdArcserve = 20069
gServiceIdDceRpc = 5

gPatterns = {
    bind = {'\005\000\011\003\016\000\000\000', 0, gSfAppIdDceRpc},
    mapi_bind = {'\005\000\011\023\016\000\000\000', 0, gSfAppIdDceRpc},
    uuid_mapi =  {'\000\219\241\164\071\202\103\016\179\031\000\221\001\006\098\218', 32, gSfAppIdDceRpc},
    uuid_epmap = {'\008\131\175\225\031\093\201\017\145\164\008\000\043\020\160\250', 32, gSfAppIdDceRpc},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.bind},
    {DC.ipproto.tcp, gPatterns.mapi_bind},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdDceRpc,		         0}
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
    gDetector:client_addApp(context.serviceid, 23, context.clientid, "", context.appid);
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

    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, 23, gClientIdDceRpc, gServiceIdDceRpc)

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

    DC.printf ('client DCERPC packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

    if (dir == 0 and size > 10) then
        matched, size_raw = gDetector:getPcreGroups("(..)", 8)
        size_packet = DC.reverseBinaryStringToNumber(size_raw, 2)    
        DC.printf ("client DCERPC size is %d size_packet is %d\n", size, size_packet)
        if (size_packet == size) then

            if ((context.dstPort == 6502) or
                (context.dstPort == 6503) or
                (context.dstPort == 6504))
            then
                DC.printf("client DCERPC detected ARCServe\n")
                context.clientid = gClientIdArcserve
                context.serviceid = gServiceIdArcserve
                context.appid = gSfAppIdArcserve
                return clientSuccess(context)
            elseif (gDetector:memcmp(gPatterns.uuid_mapi[1], #gPatterns.uuid_mapi[1], gPatterns.uuid_mapi[2]) == 0)
            then
                DC.printf("client DCERPC detected MAPI\n")
                context.clientid = gClientIdMapi
                context.serviceid = gServiceIdDceRpc
                context.appid = gSfAppIdMapi
                return clientSuccess(context)
            elseif (context.dstPort == 135 or (gDetector:memcmp(gPatterns.uuid_epmap[1], #gPatterns.uuid_epmap[1], gPatterns.uuid_epmap[2]) == 0))
            then
                DC.printf("client DCERPC detected EPMAP\n")
                context.clientid = gClientIdEpmap
                context.serviceid = gServiceIdDceRpc
                context.appid = gSfAppIdEpmap
                context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                return clientSuccess(context)
            else
                DC.printf("client DCERPC must be DCERPC\n")
                context.clientid = gClientIdDceRpc
                context.serviceid = gServiceIdDceRpc
                context.appid = gSfAppIdDceRpc
                return clientSuccess(context)
            end
        end
    end

    return clientFail(context)

end

function client_clean()
end
