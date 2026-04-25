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
detection_name: TFTP
version: 2
description: Trivial File Transfer Protocol is a lightweight file transfer protocol.
bundle_description: $VAR1 = {
          'Thin Manager TFTP' => 'A TFTP like protocol used to push firmware to Thin clients.',
          'TFTP' => 'Trivial File Transfer Protocol is a lightweight file transfer protocol.'
        };

--]]

require "DetectorCommon"

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "TFTP(odp)",
    proto = DC.ipproto.udp,
    server = {
        init = 'DetectorInit',
        validate = 'DetectorValidator',
        clean = 'DetectorFini',
    }
}

gServiceName = DetectorPackageInfo.name

gSfServiceIdTFTP = 35
gSfAppIdTFTP = 862

gSfServiceIdThin = 20204
gSfAppIdThin = 4543
gSfVendorThin = "Rockwell Automation"

xferRequest = "[ -~]+\000(netascii|octet|mail)\000"

gPatterns = {
    rrq = {'\000\001', 0, gSfAppIdTFTP},
    wrq = {'\000\002', 0, gSfAppIdTFTP},
}

gPorts = {
    {DC.ipproto.udp, 69},
    {DC.ipproto.udp, 4900},
}

gAppRegistry = {
    {gSfAppIdTFTP, 0},
    {gSfAppIdThin, 0}
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:service_inProcessService()
    end

    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:service_addService(context.serviceId, context.vendor, "", context.appId)
    end

    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:service_failService()
    end

    DC.printf('%s: Failed, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()
    for i,v in ipairs(gPorts) do
        gDetector:service_addPort(v[1], v[2])
    end

    for i,v in ipairs(gAppRegistry) do
        pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end
end

function DetectorInit( detectorInstance)
    gDetector = detectorInstance

    DC.printf('%s: DetectorInit()\n',gServiceName)

    gDetector:service_init(gServiceName, 'DetectorValidator', 'DetectorFini')

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

    if (size == 0 or dir == 1) then
        return serviceInProcess(context)
    end

    if (DC.checkPattern(gDetector, gPatterns.rrq) or
        DC.checkPattern(gDetector, gPatterns.wrq)) then

        matched = gDetector:getPcreGroups(xferRequest, 0)
        if (matched and gDetector.createFutureFlow) then
            src_ip_str = DC.intToIPv4(context.srcIp, 1)
            dst_ip_str = DC.intToIPv4(context.dstIp, 1)

            if(dstPort == 69) then
                context.serviceId = gSfServiceIdTFTP
                context.appId = gSfAppIdTFTP
                context.vendor = ""
            else
                context.serviceId = gSfServiceIdThin
                context.appId = gSfAppIdThin
                context.vendor = gSfVendorThin
            end

            DC.printf('%s:DetectorValidator(): Creating future flow %s:%d - %s:%d %d\n', gServiceName, dst_ip_str, 0, src_ip_str, srcPort, DC.ipproto.udp)

            gDetector:createFutureFlow(dst_ip_str, 0,
                                       src_ip_str, srcPort, DC.ipproto.udp,
                                       context.appId, 0, 0, context.appId)

            context.detectorFlow:setFlowFlag(DC.flowFlags.continue)

            return serviceSuccess(context)
        end
    end

    -- fail if there is no rrq or wrq pattern, or if the regexp fails
    return serviceFail(context)

end

function DetectorFini()
end
