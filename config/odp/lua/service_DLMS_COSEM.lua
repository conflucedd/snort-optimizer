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
detection_name: DLMS-COSEM
version: 7
description: DLMS (Device Language Message Specification) / COSEM (CompanionSpecification for Energy Metering) specifies an interface model and communication protocols for data exchange with metering equipment.
bundle_description: $VAR1 = {
          'DLMS-COSEM Get Response' => 'A DLMS-COSEM service to send a response to a previously received GET indication primitive.',
          'DLMS-COSEM Set Response' => 'A DLMS-COSEM service to send a response to a previously received SET indication primitive.',
          'DLMS-COSEM' => 'DLMS (Device Language Message Specification) / COSEM (CompanionSpecification for Energy Metering) specifies an interface model and communication protocols for data exchange with metering equipment.',
          'DLMS-COSEM Get Request' => 'A DLMS-COSEM service request to get the value(s) of one or all attributes.',
          'DLMS-COSEM Initiate Request High-Level Authentication' => 'A DLMS-COSEM service request for User-Information exchange with High-Level Authentication.',
          'DLMS-COSEM Initiate Response' => 'A DLMS-COSEM service response for User-Information exchange.',
          'DLMS-COSEM Initiate Request No Authentication' => 'A DLMS-COSEM service request for User-Information exchange with No Authentication.',
          'DLMS-COSEM Initiate Request Low-Level Authentication' => 'A DLMS-COSEM service request for User-Information exchange with Low-Level Authentication.',
          'DLMS-COSEM Set Request' => 'A DLMS-COSEM service request to set the value of one or more attributes.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "DLMS-COSEM",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceIdDLMSCOSEM = 20212
gServiceName = 'DLMS-COSEM'

gSfAppIdDLMSCOSEM = 5300
gSfAppIdDLMSCOSEMGETRES = 5301
gSfAppIdDLMSCOSEMSETRES = 5302
gSfAppIdDLMSCOSEMGETREQ = 5303
gSfAppIdDLMSCOSEMSETREQ = 5304
gSfAppIdDLMSCOSEMINITRES = 5305
gSfAppIdDLMSCOSEMINITREQNOAUT = 5306
gSfAppIdDLMSCOSEMINITREQLWAUT = 5307
gSfAppIdDLMSCOSEMINITREQHGAUT = 5308

gPorts = {
    {DC.ipproto.tcp, 4059},
    {DC.ipproto.udp, 4059},
    {DC.ipproto.tcp, 4060},
    {DC.ipproto.udp, 4060},
    {DC.ipproto.tcp, 4061},
    {DC.ipproto.udp, 4061},
    {DC.ipproto.tcp, 4063},
    {DC.ipproto.udp, 4063},
    {DC.ipproto.tcp, 5025},
    {DC.ipproto.udp, 5025},
    {DC.ipproto.tcp, 40000},
    {DC.ipproto.udp, 40000},
}

gAppRegistry = {
    {gSfAppIdDLMSCOSEM, 0},
    {gSfAppIdDLMSCOSEMGETRES, 0},
    {gSfAppIdDLMSCOSEMSETRES, 0},
    {gSfAppIdDLMSCOSEMGETREQ, 0},
    {gSfAppIdDLMSCOSEMSETREQ, 0},
    {gSfAppIdDLMSCOSEMINITRES, 0},
    {gSfAppIdDLMSCOSEMINITREQNOAUT, 0},
    {gSfAppIdDLMSCOSEMINITREQLWAUT, 0},
    {gSfAppIdDLMSCOSEMINITREQHGAUT, 0},
}


TIDPatterns = {
    {"\196", gSfAppIdDLMSCOSEMGETRES}, -- GETRES 0xC4
    {"\197", gSfAppIdDLMSCOSEMSETRES}, -- SETRES 0xC5
    {"\192", gSfAppIdDLMSCOSEMGETREQ}, -- GETREQ 0xC0
    {"\193", gSfAppIdDLMSCOSEMSETREQ}, -- SETREQ 0xC1
    {"\97", gSfAppIdDLMSCOSEMINITRES}, -- INITRES 0x61
    {"\96", gSfAppIdDLMSCOSEMINITREQNOAUT}, -- INITREQ 0x60
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:inProcessService()
    end
    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
    --    DC.printf('%s: adding service\n', gServiceName)
        gDetector:addService(gServiceIdDLMSCOSEM, "DLMS-COSEM", "", gSfAppIdDLMSCOSEM)
    end
    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:failService()
    end
    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', gServiceName, context.packetCount)
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

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
--    DC.printf('%s: DetectorInit()\n',gServiceName)
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()
    return gDetector
end

local function checkHdlcStart(index)
    start_ptn = "\126" -- 0x7E
    if gDetector:memcmp(start_ptn, #start_ptn, index) == 0 then
        return 1
    else
        return nil
    end
end

local function checkWrappedDlmsCosem(index,size)
       matched, apdu_size_raw = gDetector:getPcreGroups("(..)", index+6)
       if (matched) then
           apdu_size = DC.binaryStringToNumber(apdu_size_raw,2)
--         DC.printf (' apdu_size %d, size %d\n', apdu_size, size)
           if (size - 8 == apdu_size) then
                return 1
           else
                return nil
           end
       end
end

local function getDlmsCosemApduIndex(index,size)
	apdu_index = 0
	if checkWrappedDlmsCosem(index,size) then
		apdu_index = 8
	elseif checkHdlcStart(index) then
		apdu_index = 11
	end
	return apdu_index
end

local function checkTID(index)
    for i = 1, #TIDPatterns do
        if gDetector:memcmp(TIDPatterns[i][1], #TIDPatterns[i][1], index) == 0 then
            return TIDPatterns[i][2]
        end
    end
    return nil
end

local function authentication_level(index,size)
    if (gDetector:memcmp("\190\016\004\014", 4, index+13) == 0) then
        return 0 	-- No Authentication functional Unit ; Lowest Level Security
    end
    if size >= index+25 then
        matched, auth_mechanism_id_byte = gDetector:getPcreGroups("(.)", index+25) 
        if (matched) then
            auth_mechanism_id = DC.binaryStringToNumber(auth_mechanism_id_byte, 1)
            if auth_mechanism_id >= 2 then
                return 2				 -- High Level Security
            else
                return auth_mechanism_id -- 0 : Lowest Level, 1 : Low Level Security
            end
        end
    end
    return 0
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


    if size == 0 then
        return serviceInProcess(context)
    end

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size)

    found = 0
    report_payload_id = 0

	if size >= 9 then
		-- there can be more than one ASDU per packet, but for now we will assume there is one
		start_index = 0
        apdu_index = getDlmsCosemApduIndex(start_index, size)
        if (apdu_index > 0) then
            -- This is either a HDLC based or TCP-UDP/IP Wrapped communication profile
            if found == 0 and size >= apdu_index + 1 then
                tid = checkTID(apdu_index)
                if tid == gSfAppIdDLMSCOSEMINITREQNOAUT and size >= apdu_index+16 then
                    tid = tid + authentication_level(apdu_index,size)
                end

                if tid then
                    found = 1
                    report_payload_id = tid
                end
            end

            if found == 1 then
                --DC.printf('%s:Adding payload %d\n',gServiceName, report_payload_id)
                gDetector:service_analyzePayload(report_payload_id)
            end

            -- if we are on dlms-cosem ports and we saw the start pattern, its dlms-cosem
            -- so set the continue flag (to keep looking for messages) and declare success.
            context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
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
