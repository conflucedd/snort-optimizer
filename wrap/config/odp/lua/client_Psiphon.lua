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
detection_name: Psiphon
version: 3
description: Web proxy/anonymizer.
bundle_description: $VAR1 = {
          'Psiphon' => 'Web proxy/anonymizer.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name = "Psiphon",
    proto = DC.ipproto.tcp,
    client = {
        init = 'client_init',
        clean = 'client_clean',
        validate = 'client_validate',
        minimum_matches = 1
    }
}

gName = DetectorPackageInfo.name
gSfAppIdPsiphon = 4075
appTypeId = 26
appProductId = 536
appServiceId = 0

gPatterns = {
    -- This is added just so that we can register the detector with the
    -- callback functionality that we are actually interested in
    btt_d1 = {'psiphon3.com', 0, gSfAppIdPsiphon},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.btt_d1},
}

gAppRegistry = {
    --AppIdValue          Extracts Info
    ---------------------------------------
    {gSfAppIdPsiphon,              0}
}

flowTrackerTable = {}

function clientInProcess(context)
    DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdPsiphon);
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
function client_init(detectorInstance)

    gDetector = detectorInstance

    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
    gDetector:client_init()

    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if (gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,v[2][1])
        end
    end

    for i,v in ipairs(gAppRegistry) do
        pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end

    if (gDetector.registerClientDetectorCallback) then
        gDetector:registerClientDetectorCallback(gSfAppIdPsiphon, "client_callback");
    end

    return gDetector
end

--[[Validator function registered in DetectorInit()
--]]
function client_validate()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.flowKey = context.detectorFlow:getFlowKey()
    return clientFail(context)
end

function client_callback()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey
    local srvPort = dstPort
    local isHttpTunnel = false

    DC.printf('%s: packetCount %d, dir %d, size %d\n', gName, context.packetCount, dir, size);

    if (gDetector.isMidStreamSession) then
        local isMidStream = gDetector:isMidStreamSession()
        if (isMidStream == 1) then
            return DC.clientStatus.einvalid
        end
    end

    if (gDetector.isHttpTunnel) then
        isHttpTunnel = gDetector:isHttpTunnel()
    end

    if (isHttpTunnel) then
        local ip = gDetector:getHttpTunneledIp()
        dst_ip_str = DC.intToIPv4(ip, 1)
        srvPort = gDetector:getHttpTunneledPort()
    elseif (dir == 0) then
        dst_ip_str = DC.intToIPv4(context.dstIp, 1)
    else
        dst_ip_str = DC.intToIPv4(context.srcIp, 1)
        srvPort = srcPort
    end

    if (gDetector.addHostPortAppDynamic) then
        DC.printf('%s: Adding hostPortCache entry %s:%d %d - %d 1\n', gName, dst_ip_str, srvPort, DC.ipproto.tcp, gSfAppIdPsiphon)
        gDetector:addHostPortAppDynamic(1, gSfAppIdPsiphon, dst_ip_str, srvPort, DC.ipproto.tcp);

        DC.printf('%s: Adding hostPortCache entry %s:%d %d - %d 1\n', gName, dst_ip_str, srvPort, DC.ipproto.udp, gSfAppIdPsiphon)
        gDetector:addHostPortAppDynamic(1, gSfAppIdPsiphon, dst_ip_str, srvPort, DC.ipproto.udp);
    end

    return clientSuccess(context)
end

function client_clean()
end
