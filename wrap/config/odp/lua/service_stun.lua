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
detection_name: STUN
version: 5
description: Session Traversal Utilities for NAT is used in NAT traversal for applications with real-time voice, video, messaging, and other interactive communications.
bundle_description: $VAR1 = {
          'STUN' => 'Session Traversal Utilities for NAT is used in NAT traversal for applications with real-time voice, video, messaging, and other interactive communications.'
        };

--]]

require "DetectorCommon"


--require('debugger')
--local DC = require("DetectorCommon")
local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "stun",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20037
gServiceName = 'STUN'
gDetector = nil
gSfAppIdStun = 853

--patterns used in DetectorInit()
gPatterns = {
    --patternName        Pattern         offset
    -------------------------------------------
    msg_cookie       = {"\033\018\164\066", 4, gSfAppIdStun},

    bindReq          = {"\000\001\000",    0, gSfAppIdStun},
    sharedSecretReq  = {"\000\002\000",    0, gSfAppIdStun},
    allocateReq      = {"\000\003\000",    0, gSfAppIdStun},
    refreshReq       = {"\000\004\000",    0, gSfAppIdStun},

    bindSuccess      = {"\001\001\000",    0, gSfAppIdStun},
    sharedSecSuccess = {"\001\002\000",    0, gSfAppIdStun},
    allocateSuccess  = {"\001\003\000",    0, gSfAppIdStun},
    refreshSuccess   = {"\001\004\000",    0, gSfAppIdStun},

    BindErrError     = {"\001\017\000",    0, gSfAppIdStun},
    sharedSecError   = {"\001\018\000",    0, gSfAppIdStun},
    allocateError    = {"\001\019\000",    0, gSfAppIdStun},
    refreshError     = {"\001\020\000",    0, gSfAppIdStun},
}

--fast pattern registerd with core engine 
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.msg_cookie},
    {DC.ipproto.udp, gPatterns.msg_cookie},
}

--port based detection - needed when not using CSD tables
gPorts = {
    {DC.ipproto.udp, 3478},
    {DC.ipproto.tcp, 3478},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdStun,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdStun)
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
            DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2][1])
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function DetectorInit(detectorInstance)

    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', gServiceName);

    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')

    registerPortsPatterns()

    return gDetector
end

--[[Validator function registered in DetectorInit()
--]]
function DetectorValidator()
    local context = {}

    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()

    local dir =  context.packetDir
    local size = context.packetDataLen
    local flowKey = context.flowKey
    local srcPort = context.srcPort
    local dstPort = context.dstPort

    DC.printf ('%s:DetectorValidator(): packetCount %d\n', gServiceName, context.packetCount);

    if (size == 0) then
        return serviceInProcess(context)
    end

    if (gDetector:memcmp(gPatterns.msg_cookie[1], #gPatterns.msg_cookie[1],
            gPatterns.msg_cookie[2]) == 0) then
        DC.printf('%s:DetectorValidator():msg_cookie detected\n', gServiceName)
        matched, len_raw = gDetector:getPcreGroups("..(..)", 0)
        if (matched) then
            len = DC.binaryStringToNumber(len_raw, 2)
            DC.printf ('%s:DetectorValidator(): len is %d size is %d\n', gServiceName, len, size)
            if (size - 20 == len) then
                return serviceSuccess(context)
            end
        end   
    end
 
    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
