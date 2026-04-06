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
detection_name: MDNS
version: 6
description: Multicast DNS.
bundle_description: $VAR1 = {
          'MDNS' => 'Multicast DNS.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "MDNS",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20146
gServiceName = 'MDNS'
gSfAppId = 1755

--patterns used in DetectorInit()
gPatterns = {       
    pattern2          = {'\000\000\132\000\000\000', 0, gSfAppId},
    pattern3          = {'\000\000\004\000\000\000', 0, gSfAppId},
    pattern4          = {'\000\000\008\000\000\000', 0, gSfAppId},
}

--fast pattern registerd with core engine - needed when not using CSD tables
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.udp, gPatterns.pattern2},
    {DC.ipproto.udp, gPatterns.pattern3},
    {DC.ipproto.udp, gPatterns.pattern4},
}

gPorts = {
    {DC.ipproto.udp, 5353}
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
        gDetector:addService(gServiceId, "", "", gSfAppId)
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
    
    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
	    DC.printf('%s: Failed to register the pattern', gServiceName )
        else
	    DC.printf('%s: Successful in registering the pattern', gServiceName )
        end
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
    local headBanner2=gPatterns.pattern2[1]
    local headBanner3=gPatterns.pattern3[1]
    local headBanner4=gPatterns.pattern4[1]

    DC.printf ('%s: DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, 
               context.packetCount, dir, size)
    	DC.printf ('The Port is: dstport\n')
    if ( dstPort == 5353 or srcPort == 5353 ) then
    --	DC.printf ('%s:Matched with Port\n', gServiceName);
	    if (size >= 6 and (gDetector:memcmp(headBanner2, #headBanner2, 0) == 0)) then 
		    DC.printf('%s: Matched with Pattern 2\n', gServiceName )
	        return serviceSuccess(context)
	    elseif (size >= 6 and (gDetector:memcmp(headBanner3, #headBanner3, 0) == 0)) then 
		    DC.printf('%s: Matched with Pattern 3\n', gServiceName )
	        return serviceSuccess(context)
	    elseif (size >= 6 and (gDetector:memcmp(headBanner4, #headBanner4, 0) == 0)) then 
		    DC.printf('%s: Matched with Pattern 4\n', gServiceName )
	        return serviceSuccess(context)
	    end
    end

    return serviceFail(context)
end

function DetectorFini()
end
