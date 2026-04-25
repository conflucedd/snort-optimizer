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
detection_name: UltraView CCS
version: 3
description: Web application tool to configure software parameters for any supported video equipment.
bundle_description: $VAR1 = {
          'UltraView CCS' => 'Web application tool to configure software parameters for any supported video equipment.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "UltraView CCS",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20206
gServiceName = 'UltraView CCS'
gSfAppIdUltraview = 4582

gPatterns = {
    getRPC = {"getRPCVersion", 0, gSfAppIdUltraview},
    OKRPC = {"OK RPCVersion", 0, gSfAppIdUltraview},
    addUDPClient = {"addUDPClient", 0, gSfAppIdUltraview},
    getBufferDurationMs= {"getBufferDurationMs", 0, gSfAppIdUltraview},
    rpc_dbQuery= {"rpc_dbQuery", 0, gSfAppIdUltraview},
    getServices= {"getServices", 0, gSfAppIdUltraview},
    services_reply= {"SERVICES", 0, gSfAppIdUltraview},
    ping={"PING", 0, gSfAppIdUltraview},
    pong={"PONG", 0, gSfAppIdUltraview},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.getRPC},
    {DC.ipproto.tcp, gPatterns.OKRPC},
}

gAppRegistry = {
    {gSfAppIdUltraview, 0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdUltraview)
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

    local rft = FT.getFlowTracker(flowKey)
    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {mid_session=0})
    end

    if (dir == 1) then
        if (DC.checkPattern(gDetector, gPatterns.OKRPC) and rft.mid_session == 0) then
            rft.mid_session = 1
            return serviceInProcess(context)
        elseif DC.checkPattern(gDetector, gPatterns.services_reply) and rft.mid_session == 2 then
            return serviceSuccess(context)
        elseif DC.checkPattern(gDetector, gPatterns.pong) and rft.mid_session == 2 then
            return serviceSuccess(context)
        end
    end

    if (dir == 0 and size > 5 and  rft.mid_session == 1) then
        if (DC.checkPattern(gDetector, gPatterns.addUDPClient) or
            DC.checkPattern(gDetector, gPatterns.getBufferDurationMs) or
            DC.checkPattern(gDetector, gPatterns.rpc_dbQuery)) then

            if (gDetector.createFutureFlow) then
                matched, ip, port = gDetector:getPcreGroups("ip=\"(.*)\".*port=([0-9]*)")
                if (matched) then
                    src_ip_str = DC.intToIPv4 (context.dstIp, 1)
                    if (gDetector:createFutureFlow(src_ip_str, 0, ip, port, DC.ipproto.udp, gSfAppIdUltraview , gSfAppIdUltraview, gSfAppIdUltraview, gSfAppIdUltraview)) then
                        DC.printf ('%s:DetectorValidator(): creating future flow %s:%d - %s:%d\n', gServiceName, src_ip_str, 0, ip, port)
                    end
                end
            end
            return serviceSuccess(context)
        elseif DC.checkPattern(gDetector, gPatterns.getServices) then
            rft.mid_session = 2
            return serviceInProcess(context)
        elseif DC.checkPattern(gDetector, gPatterns.ping) then
            rft.mid_session = 2
            return serviceInProcess(context)
        end
    end
    return serviceFail(context)

end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
