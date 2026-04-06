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
          'CIP' => 'Common Industrial Protocol.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "CIP",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

-- technically, 44818 is for ENIP
cip_port_tcp = 44818
gServiceName = 'CIP'
gServiceIdCip = 20502
gSfAppIdCip = 5002
ENIP_header_len = 24

gPatterns = {
    enip_unknown = { '\001\000', 0, gSfAppIdCip },
    enip_list_services = { '\004\000', 0, gSfAppIdCip },
    enip_list_interfaces = { '\100\000', 0, gSfAppIdCip },
    enip_register_session = { '\101\000', 0, gSfAppIdCip },    
    cip_send_rr_data = { '\111\000', 0, gSfAppIdCip },
    cip_interface_handle = { '\000\000\000\000', 25, gSfAppIdCip }, 
}

gPorts = {
    {DC.ipproto.tcp, cip_port_tcp},
}

gAppRegistry = {
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
    if not flowFlag or flowFlag == 0 or context.reset_service then
        gDetector:addService(gServiceIdCip, "", "", gSfAppIdCip)
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

local function checkEnipHeaderLen(size)
    matched, header_len_raw = gDetector:getPcreGroups("..(..)", 0)
    header_len = DC.reverseBinaryStringToNumber(header_len_raw, 2) 
    DC.log(gDetector,'found ENIP header len %d', header_len)
    if size - ENIP_header_len == header_len then
        return 1
    else
        return nil
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
    local srcPort = gDetector:getPktSrcPort()
    local dstPort = gDetector:getPktDstPort()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir

    if dstPort ~= cip_port_tcp and srcPort ~= cip_port_tcp then
        return serviceFail(context)
    end

    if size < ENIP_header_len then
        return serviceInProcess(context)
    end

    DC.log(gDetector,'%s:DetectorValidator(): packetCount %d, dir %d size %d', gServiceName, context.packetCount, dir, size)

    if checkEnipHeaderLen(size) then
        if DC.checkPattern(gDetector, gPatterns.enip_unknown) or                                           
            DC.checkPattern(gDetector, gPatterns.enip_list_services) or                                      
            DC.checkPattern(gDetector, gPatterns.enip_list_interfaces) or                                    
            DC.checkPattern(gDetector, gPatterns.enip_register_session) then
            return serviceInProcess(context)
        elseif DC.checkPattern(gDetector, gPatterns.cip_send_rr_data) then
            return serviceSuccess(context)
        end
    end

    return serviceFail(context)

end

function DetectorFini()
end
