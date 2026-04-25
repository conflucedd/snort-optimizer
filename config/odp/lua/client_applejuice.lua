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
detection_name: Applejuice
version: 2
description: Peer-to-peer file sharing.
bundle_description: $VAR1 = {
          'Applejuice' => 'Peer-to-peer file sharing.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "Applejuice",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        validate =  'client_validate',
        clean = 'client_clean',
    }
}

gDetector = nil

gSfAppIdApplejuice = 29
--patterns used in DetectorInit()
gPatterns = {
    --patternName        Pattern         offset
    -------------------------------------------
    clientReq = {'ajprot\013\010', 0, gSfAppIdApplejuice},
}

--fast pattern registerd with core engine
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.clientReq},
}

--port is not a well known one. each installation can be different.

gAppRegistry = {
        --AppIdValue          Extracts Info
        ---------------------------------------
        {gSfAppIdApplejuice,                     0}
}

flowTrackerTable = {}

function clientInProcess(context)

        DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
        return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, "", "", gSfAppIdApplejuice);
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
function client_init( detectorInstance)

    gDetector = detectorInstance
    DC.printf ('%s:client_init()\n', DetectorPackageInfo.name);
    gDetector:client_init()
    appTypeId = 15
    appServiceId = 20038
    DC.printf ('%s:client_validate(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, "", appServiceId)

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

    local dir =  context.packetDir
    local size = context.packetDataLen
    local flowKey = context.flowKey

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', DetectorPackageInfo.name, context.packetCount, dir, size);

    if (size == 0 or dir == 1) then
        return clientInProcess(context)
    end

    --client packet is received
    if ((dir == 0) and (size > 7)) then
        matched = gDetector:getPcreGroups(gPatterns.clientReq[1], 0);
        if matched then
            return clientSuccess(context)
        end
    end
    --fails since the detector get syn packet also.
    return clientFail(context)
end

function client_clean()
end
