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
detection_name: CIP
version: 2
description: Common Industrial Protocol.
bundle_description: $VAR1 = {
          'ENIP' => 'Ethernet/IP, an industrial control protocol.',
          'CIP' => 'Common Industrial Protocol.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "CIP",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

enip_port_udp = 2222

gServiceName = 'CIP'

gServiceIdEnip = 20501
gServiceIdCip = 20502

gSfAppIdEnip = 5001
gSfAppIdCip = 5002

gPorts = {
    {DC.ipproto.udp, enip_port_udp}
}

gAppRegistry = {
    {gSfAppIdEnip, 0},
	{gSfAppIdCip, 0},
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:inProcessService()
    end
    DC.log(gDetector,'%s: Inprocess, packetCount: %d', gServiceName, context.packetCount)
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:addService(context.serviceId, "", "", context.appId)
    end
    DC.log(gDetector,'%s: Detected, packetCount: %d', gServiceName, context.packetCount)
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:failService()
    end
    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.log(gDetector,'%s: Failed, packetCount: %d', gServiceName, context.packetCount)
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end
	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end
end

function DetectorInit( detectorInstance)
    gDetector = detectorInstance
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
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort

    if dstPort ~= enip_port_udp and srcPort ~= enip_port_udp or size < 2 then
        return serviceFail(context)
    end

    DC.log(gDetector,'%s:DetectorValidator(): packetCount %d, dir %d size %d', gServiceName, context.packetCount, dir, size)

    matched, item_count_raw = gDetector:getPcreGroups("(..)", 0)
    item_count = DC.reverseBinaryStringToNumber(item_count_raw, 2)
    cur_index = 2

    while item_count > 0 and cur_index < size do
        DC.log(gDetector,'checking an enip item at index %d', cur_index) 
        matched, type_id_raw, item_len_raw = gDetector:getPcreGroups("(..)(..)", cur_index)
        type_id = DC.reverseBinaryStringToNumber(type_id_raw, 2)
        if type_id == 177 then
            DC.log(gDetector,'found a connected data item - CIP detected')
            context.serviceId = gServiceIdCip
            context.appId = gSfAppIdCip
            return serviceSuccess(context)
        end
        DC.log(gDetector,'not a connected data item')
        item_len = DC.reverseBinaryStringToNumber(item_len_raw, 2)
        cur_index = cur_index + 4 + item_len
        item_count = item_count - 1
    end

    context.serviceId = gServiceIdEnip
    context.appId = gSfAppIdEnip
    return serviceSuccess(context)
end

function DetectorFini()
end
