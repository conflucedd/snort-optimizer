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
detection_name: SCCP
version: 7
description: Skinny Call Control Protocol, a VoIP call setup protocol.
bundle_description: $VAR1 = {
          'RTP' => 'Real-Time Transport Protocol is primarily used to deliver real-time audio and video.',
          'SCCP' => 'Skinny Call Control Protocol, a VoIP call setup protocol.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "SCCP",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

skinny_port = 2000

gServiceId = 20196
gServiceName = 'SCCP'
gSfAppIdSCCP = 2940
gSfAppIdRTP = 813

gPatterns = {
    enhanced_alarm = {'\090\001\000\000', 8, gSfAppIdSCCP},
    startmedia_trn = {'\138\000\000\000', 8, gSfAppIdSCCP},
}

gPorts = {
    {DC.ipproto.tcp, skinny_port},
}

gAppRegistry = {
    {gSfAppIdSCCP, 0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdSCCP)
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

local function numToReverseBytes(tint)
    local t = {}
    for i = 0, 3 do
        sint = bit.band(bit.rshift(tint, (i * 8)), 0xFF)
        t[i+1] = string.char(sint)
    end
    return table.concat(t)
end

-- SCCP can have more than one PDU per packet
local function skinny_header_length_doesnt_match(size)
    first_target_size_bytes = numToReverseBytes(size - 8)
    if gDetector:memcmp(first_target_size_bytes, #first_target_size_bytes, 0) == 0 then
        DC.printf("%s: found a valid length field matching size %d at index 0\n", gServiceName, size - 8)
        return nil
    else
        -- look from the end for multi PDU
        remaining_size = size
        while remaining_size > 0 do
            candidate_pdu_size = 4
            while candidate_pdu_size + 8 <= remaining_size do
                candidate_len_field_index = remaining_size - candidate_pdu_size - 8
                DC.printf("%s: remaining_size: %d, candidate_pdu_size %d, checking index %d\n", gServiceName, remaining_size, candidate_pdu_size, candidate_len_field_index)
                candidate_pdu_size_bytes = numToReverseBytes(candidate_pdu_size)
                if gDetector:memcmp(candidate_pdu_size_bytes, #candidate_pdu_size_bytes, candidate_len_field_index) == 0 then
                    DC.printf("found a valid PDU length field\n")
                    if candidate_pdu_size + 8 == remaining_size then
                        return nil
                    else
                        break
                    end
                end
                candidate_pdu_size = candidate_pdu_size + 4
            end
            remaining_size = remaining_size - candidate_pdu_size - 8
            if remaining_size <= 0 then
                DC.printf("%s: No valid length fields found\n", gServiceName)
                return 1
            end
        end
    end
    return 1
end

function DetectorInit(detectorInstance)
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

    DC.printf('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
        context.packetCount, dir, size)

    -- get out ASAP if port is not 2000 because we have patterns that
    -- could cause lots of false positives in brute-force mode
    if dir == 0 and dstPort ~= skinny_port or dir == 1 and srcPort ~= skinny_port then
        return serviceFail(context)
    end

    -- SCCP header portion is 12 bytes
    if size < 12 then
        return serviceInProcess(context)
    end

    local rft = FT.getFlowTracker(flowKey)
    if not rft then
        rft = FT.addFlowTracker(flowKey, {pkts = 0, enhanced_alarm_flow = 0})
    end

    -- Enhanced Alarm is a potentially long, segmented packet that we cannot test by comparing
    -- the header length field with the packet length. But we can expect it to be the first
    -- client packet in a call.
    if dir == 0 and rft.pkts == 0 and DC.checkPattern(gDetector, gPatterns.enhanced_alarm) then
        DC.printf('%s:DetectorValidator(): client sent EnhancedAlarm message\n', gServiceName)
        rft.pkts = rft.pkts + 1
        rft.enhanced_alarm_flow = 1
        return serviceInProcess(context)
    end

    -- If length header value doesn't match data size then this traffic is not skinny. 
    -- We make an exception for the extra long EnhancedAlarm message.
    if skinny_header_length_doesnt_match(size) then
        if rft.enhanced_alarm_flow == 1 then                                                    
            DC.printf('%s:DetectorValidator(): another segment of EnhancedAlarm message\n',         
                gServiceName)                                                                       
            return serviceInProcess(context)     
        else
            DC.printf('%s:DetectorValidator(): bad length header, not skinny\n', gServiceName)
            return serviceFail(context)
        end
    end

    DC.printf('%s:DetectorValidator(): packet %d looks good\n', gServiceName, rft.pkts)
    rft.pkts = rft.pkts + 1
    -- if we get here on and EnhancedAlarm packet, we know we have seen the whole thing
    if rft.enhanced_alarm_flow == 1 then                                                    
        DC.printf('%s:DetectorValidator(): end of Enhanced Alarm\n', gServiceName)          
        rft.enhanced_alarm_flow = 0                                                         
    elseif size >= 28 and DC.checkPattern(gDetector, gPatterns.startmedia_trn) then
        DC.printf('%s:DetectorValidator(): StartMediaTransfer found\n', gServiceName)
        matched, dst_ip_raw, dst_port_raw = gDetector:getPcreGroups("(....)(....)", 20)
        if matched and gDetector.createFutureFlow then
            dst_ip_int = DC.reverseBinaryStringToNumber(dst_ip_raw, 4)
            dst_port = DC.reverseBinaryStringToNumber(dst_port_raw, 4)
            -- the PACKET dst IP is going to be the client here, and the src addr of the new flow
            src_ip_str = DC.intToIPv4 (context.dstIp, 1)
            dst_ip_str = DC.intToIPv4 (dst_ip_int, 1)
            DC.printf('%s:DetectorValidator(): creating future flow %s:%d - %s:%d\n',
                gServiceName, src_ip_str, 0, dst_ip_str, dst_port)
            gDetector:createFutureFlow(src_ip_str, 0, dst_ip_str, dst_port, 17, gSfAppIdRTP,
                gSfAppIdRTP, gSfAppIdSCCP, gSfAppIdSCCP)
            gDetector:createFutureFlow(dst_ip_str, dst_port, src_ip_str, 0, 17, gSfAppIdRTP,
                gSfAppIdRTP, gSfAppIdSCCP, gSfAppIdSCCP)
            -- Continue monitoring the session after the call is setup
        end
    end

    -- If we have made it here, we at least know this packet is TCP port 2000, and the first 
    -- four bytes of data, which is at least 12 bytes long, is a valid length field.
    -- This is good enough to validate Skinny/SCCP. 
    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
    return serviceSuccess(context)

end

function DetectorFini()
end
