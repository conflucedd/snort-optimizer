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
detection_name: SOCKS
version: 7
description: An Internet protocol that facilitates the routing of network packets between clientserver applications via a proxy server.
bundle_description: $VAR1 = {
          'SOCKS' => 'An Internet protocol that facilitates the routing of network packets between clientserver applications via a proxy server.'
        };

--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "SOCKS",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
        fini = 'DetectorFini',
    }
}

gServiceId = 20019
gServiceName = 'SOCKS'
gSfAppIdSOCKS = 839

gPatterns = {
    socks_ack =  {'\005\000', 0, gSfAppIdSOCKS},   
    socks_cont = {'\005\000\000\001\072\048\064\124\000\000', 0, gSfAppIdSOCKS},
    socks4_ack = {'\000\090\000\000\000\000\000\000', 0, gSfAppIdSOCKS},
    socks5_ack1 = {'\005\001', 0, gSfAppIdSOCKS},
    socks5_ack2 = {'\005\002', 0, gSfAppIdSOCKS},
    socks5_ack3 = {'\005\003', 0, gSfAppIdSOCKS},
    socks5_ack5 = {'\005\005', 0, gSfAppIdSOCKS},
    socks5_ack6 = {'\005\006', 0, gSfAppIdSOCKS},
    socks5_ack7 = {'\005\007', 0, gSfAppIdSOCKS},
    socks5_ack8 = {'\005\008', 0, gSfAppIdSOCKS},
    socks5_ack9 = {'\005\009', 0, gSfAppIdSOCKS},
    socks5_meth = {'\001\000', 0, gSfAppIdSOCKS},
    socks5_cont1 = {'\005\000\000\001', 0, gSfAppIdSOCKS},
    socks5_cont3 = {'\005\000\000\003', 0, gSfAppIdSOCKS},
    socks5_cont4 = {'\005\000\000\004', 0, gSfAppIdSOCKS},
}

gFastPatterns = {   
    {DC.ipproto.tcp, gPatterns.socks_ack},
    {DC.ipproto.tcp, gPatterns.socks4_ack},
    {DC.ipproto.tcp, gPatterns.socks5_ack1},
    {DC.ipproto.tcp, gPatterns.socks5_ack2},
    {DC.ipproto.tcp, gPatterns.socks5_ack3},
    {DC.ipproto.tcp, gPatterns.socks5_ack5},
    {DC.ipproto.tcp, gPatterns.socks5_ack6},
    {DC.ipproto.tcp, gPatterns.socks5_ack7},
    {DC.ipproto.tcp, gPatterns.socks5_ack8},
    {DC.ipproto.tcp, gPatterns.socks5_ack9},
}

gAppRegistry = {
	{gSfAppIdSOCKS, 0}
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
        gDetector:addService(gServiceId, "", context.ver, gSfAppIdSOCKS)
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

    -- if we ever get any SOCKS4 traffic, we can modify this to reflect
    -- actual version
    context.ver = 5

    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    if (dir == 1 and
        size == 8 and
        DC.checkPattern(gDetector, gPatterns.socks4_ack))
    then
        DC.printf ('%s:DetectorValidator(): socks4 found\n',gServiceName)
        context.ver = 4
        return serviceSuccess(context)
    end

    if (dir == 1 and
        (((size == 2 or size == 6) and DC.checkPattern(gDetector, gPatterns.socks_ack)) or
        (size == 2 and (DC.checkPattern(gDetector, gPatterns.socks5_ack1) or DC.checkPattern(gDetector, gPatterns.socks5_ack2) or
        DC.checkPattern(gDetector, gPatterns.socks5_ack3) or DC.checkPattern(gDetector, gPatterns.socks5_ack5) or
        DC.checkPattern(gDetector, gPatterns.socks5_ack6) or DC.checkPattern(gDetector, gPatterns.socks5_ack7) or
        DC.checkPattern(gDetector, gPatterns.socks5_ack8) or DC.checkPattern(gDetector, gPatterns.socks5_ack9)))))
    then 
        DC.printf ('%s:DetectorValidator(): this looks like the first packet\n',  gServiceName)
        local rft = FT.getFlowTracker(flowKey)
        if (not rft) then
            rft = FT.addFlowTracker(flowKey, {p=1})
            return serviceInProcess(context)
        end
    end

    if (dir == 1 and
        size == 10 and
        DC.checkPattern(gDetector, gPatterns.socks_cont))
    then
        DC.printf ('%s:DetectorValidator(): this looks like the 2nd packet\n',  gServiceName)
        local rft = FT.getFlowTracker(flowKey)
        if (rft and rft.p == 1) then
            return serviceSuccess(context)
        end
    end

    if (dir == 1 and size == 2 and
        DC.checkPattern(gDetector, gPatterns.socks5_meth))
    then
        DC.printf ('%s:DetectorValidator(): this looks like the 2nd packet\n',  gServiceName)
        local rft = FT.getFlowTracker(flowKey)
        if (rft and rft.p == 1) then
		rft = FT.addFlowTracker(flowKey, {p=2})
            return serviceInProcess(context)
        end
    end

    if (dir == 1 and size >= 7 and
         (DC.checkPattern(gDetector, gPatterns.socks5_cont1) or
         DC.checkPattern(gDetector, gPatterns.socks5_cont3) or
         DC.checkPattern(gDetector, gPatterns.socks5_cont4)))
    then
        DC.printf ('%s:DetectorValidator(): this looks like the 2nd or 3rd packet\n',  gServiceName)
        local rft = FT.getFlowTracker(flowKey)
        if (rft and (rft.p ==1 or rft.p == 2)) then
            return serviceSuccess(context)
        end
    end

    return serviceFail(context) 

end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
