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
detection_name: Tanium
version: 3
description: Endpoint security and systems management software.
bundle_description: $VAR1 = {
          'Tanium' => 'Endpoint security and systems management software.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Tanium",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20197
gServiceName = 'Tanium'
gServiceVendor = 'Tanium'
gSfAppId = 4076

--patterns used in DetectorInit()
gPatterns = {       
    pattern1          = {'\000\000\000\001', 2, gSfAppId},
}

gPorts = {
    {DC.ipproto.tcp, 17472}
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppId,		         0}
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
        gDetector:addService(gServiceId, gServiceVendor, "", gSfAppId)
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

    --register port based detection
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end
    
	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end


--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function DetectorInit( detectorInstance)

    DC.printf (gServiceName .. ': DetectorInit()')

    gDetector = detectorInstance
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
end


function DetectorValidator()
    local context = {}
    context.packetDir = gDetector:getPacketDir()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.detectorFlow = gDetector:getFlow()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local dir = context.packetDir
    local size = context.packetDataLen
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local headBanner=gPatterns.pattern1[1]
    --local headBanner='ZBXD\x01'

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, 
               context.packetCount, dir, size);
    if (size == 0 or dir == DC.flowDirection.fromInitiator) then
        return serviceInProcess(context)
    end

    if (size >= 6 and (gDetector:memcmp(gPatterns.pattern1[1], #gPatterns.pattern1[1], gPatterns.pattern1[2]) == 0)) then
        DC.printf('got tanium initial pattern\n')
        matched, len_raw = gDetector:getPcreGroups('(..)', 0)
        if (matched) then
            len = DC.binaryStringToNumber(len_raw, 2)
            DC.printf('tanium len is %d size is %d\n', len, size)
            if (size - 2 == len) then
                return serviceSuccess(context)
            end
        end 
    end

    return serviceFail(context)
end

function DetectorFini()
end
