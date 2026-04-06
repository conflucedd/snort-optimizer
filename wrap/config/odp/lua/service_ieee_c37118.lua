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
detection_name: IEEE C37.118 Synchrophasor
version: 7
description: IEEE C37.118 Synchrophasor Data Transfer Protocol is an IEEE standard which defines a method for exchange of synchronized phasor measurement data between power system equipment.
bundle_description: $VAR1 = {
          'IEEE C37.118 Configuration Frame 3' => 'An IEEE C37.118 Protocol Synchrophasor Configuration Frame 3 Packet.',
          'IEEE C37.118 Command Extended Frame' => 'An IEEE C37.118 Protocol Synchrophasor Command Extended Frame Packet.',
          'IEEE C37.118 Command DT On Frame' => 'An IEEE C37.118 Protocol Synchrophasor Command Data Transmission On Frame Packet.',
          'IEEE C37.118 Configuration Frame 1' => 'An IEEE C37.118 Protocol Synchrophasor Configuration Frame 1 Packet.',
          'IEEE C37.118 Command Send Configuration 2 Frame' => 'An IEEE C37.118 Protocol Synchrophasor Command Send Configuration 2 Frame Packet.',
          'IEEE C37.118 Command Send Configuration 1 Frame' => 'An IEEE C37.118 Protocol Synchrophasor Command Send Configuration 1 Frame Packet.',
          'IEEE C37.118 Configuration Frame 2' => 'An IEEE C37.118 Protocol Synchrophasor Configuration Frame 2 Packet.',
          'IEEE C37.118 Header Frame' => 'An IEEE C37.118 Protocol Synchrophasor Header Frame Packet.',
          'IEEE C37.118 Command Send Configuration 3 Frame' => 'An IEEE C37.118 Protocol Synchrophasor Command Send Configuration 3 Frame Packet.',
          'IEEE C37.118 Command DT Off Frame' => 'An IEEE C37.118 Protocol Synchrophasor Command Data Transmission Off Frame Packet.',
          'IEEE C37.118 Data Frame' => 'An IEEE C37.118 Protocol Synchrophasor Data Frame Packet.',
          'IEEE C37.118 Command Send Header Frame' => 'An IEEE C37.118 Protocol Synchrophasor Command Send Header Frame Packet.',
          'IEEE C37.118 Synchrophasor' => 'IEEE C37.118 Synchrophasor Data Transfer Protocol is an IEEE standard which defines a method for exchange of synchronized phasor measurement data between power system equipment.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "IEEE C37.118 Synchrophasor",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceIdIEEC37118 = 20213
gServiceName = 'IEEE C37.118 Synchrophasor'

gSfAppIdIEEC37118 = 5320
gSfAppIDIEEC37118HDRFRAME = 5321
gSfAppIDIEEC37118DATAFRAME = 5322
gSfAppIDIEEC37118CFG1FRAME = 5323
gSfAppIDIEEC37118CFG2FRAME = 5324
gSfAppIDIEEC37118CFG3FRAME = 5325
gSfAppIDIEEC37118CMDEXTD = 5326
gSfAppIDIEEC37118CMDDTON = 5327
gSfAppIDIEEC37118CMDSNDHDR = 5328
gSfAppIDIEEC37118CMDDTOFF = 5329
gSfAppIDIEEC37118CMDSNDCFG2 = 5330
gSfAppIDIEEC37118CMDSNDCFG3 = 5331
gSfAppIDIEEC37118CMDSNDCFG1 = 5332

gPorts = {
    {DC.ipproto.tcp, 4712},
    {DC.ipproto.udp, 4713},
}

gAppRegistry = {
    {gSfAppIdIEEC37118, 0},
    {gSfAppIDIEEC37118HDRFRAME, 0},
    {gSfAppIDIEEC37118DATAFRAME, 0},
    {gSfAppIDIEEC37118CFG1FRAME, 0},
    {gSfAppIDIEEC37118CFG2FRAME, 0},
    {gSfAppIDIEEC37118CFG3FRAME, 0},
    {gSfAppIDIEEC37118CMDEXTD, 0},
    {gSfAppIDIEEC37118CMDDTON, 0},
    {gSfAppIDIEEC37118CMDSNDHDR, 0},
    {gSfAppIDIEEC37118CMDDTOFF, 0},
    {gSfAppIDIEEC37118CMDSNDCFG2, 0},
    {gSfAppIDIEEC37118CMDSNDCFG3, 0},
    {gSfAppIDIEEC37118CMDSNDCFG1, 0},
}

TIDPatterns = {
    {"\017", gSfAppIDIEEC37118HDRFRAME}, -- HDR_FRAME Ver 1 0x11
    {"\018", gSfAppIDIEEC37118HDRFRAME}, -- HDR_FRAME Ver 2 0x12
    {"\001", gSfAppIDIEEC37118DATAFRAME}, -- DATA_FRAME Ver 1 0x01
    {"\002", gSfAppIDIEEC37118DATAFRAME}, -- DATA_FRAME Ver 2 0x02
    {"\033", gSfAppIDIEEC37118CFG1FRAME}, -- CFG_FRAME_1 Ver 1 0x21
    {"\034", gSfAppIDIEEC37118CFG1FRAME}, -- CFG_FRAME_1 Ver 2 0x22
    {"\049", gSfAppIDIEEC37118CFG2FRAME}, -- CFG_FRAME_2 Ver 1 0x31
    {"\050", gSfAppIDIEEC37118CFG2FRAME}, -- CFG_FRAME_2 Ver 2 0x32
    {"\081", gSfAppIDIEEC37118CFG3FRAME}, -- CFG_FRAME_3 Ver 1 0x51
    {"\082", gSfAppIDIEEC37118CFG3FRAME}, -- CFG_FRAME_3 Ver 2 0x52
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
        DC.printf('%s: adding service\n', gServiceName)
        gDetector:addService(gServiceIdIEEC37118, "IEEE C37.118 Synchrophasor", "", gSfAppIdIEEC37118)
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
    DC.printf('%s: DetectorInit()\n',gServiceName)
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()
    return gDetector
end

local function checkStart(index)
    start_ptn = "\170" -- 0xAA
    if gDetector:memcmp(start_ptn, #start_ptn, index) == 0 then
        return 1
    else
        return nil
    end
end

local function checkCommand(index)
    cmd_frame_ptn = "\065" -- 0x41
    if gDetector:memcmp(cmd_frame_ptn, #cmd_frame_ptn, index) == 0 then
        return 1
    end
    cmd_frame_ptn = "\066" -- 0x42
    if gDetector:memcmp(cmd_frame_ptn, #cmd_frame_ptn, index) == 0 then
        return 1
    end
    return nil
end

local function checkTID(index)
    for i = 1, #TIDPatterns do
        if gDetector:memcmp(TIDPatterns[i][1], #TIDPatterns[i][1], index) == 0 then
            return TIDPatterns[i][2]
        end
    end
    return nil
end

local function command_frame_subtype(index,size)
    if size >= index+2 then
        matched, cmd_frame_subtype_byte = gDetector:getPcreGroups("(..)", index) 
        if (matched) then
            cmd_frame_subtype_id = DC.binaryStringToNumber(cmd_frame_subtype_byte, 1)
            return cmd_frame_subtype_id -- 1 to 6 and 8 values are used command sub types
        end
    end
    return 0
end
function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.packetCount = gDetector:getPktCount()
    local size = gDetector:getPacketSize()
    local dir = gDetector:getPacketDir()

    if size == 0 then
        return serviceInProcess(context)
    end

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size)

    report_payload_id = 0

    if (size < 14 or not checkStart(0)) then
        return serviceFail(context)
    end
    DC.printf("IEEEC37.118 packet with valid proper header length\n")
    tid_index = 1
    tid = checkTID(tid_index)
    DC.printf("IEEEC37.118 packet found tid %d \n", tid)
    if ((size >= tid_index + 16) and checkCommand(tid_index)) then
        cmd_frame_subtype = command_frame_subtype(tid_index+14,size)
        DC.printf("IEEEC37.118 packet found cmd_frame_subtype  %d \n", cmd_frame_subtype)
        if (cmd_frame_subtype < 1 or cmd_frame_subtype > 8 or cmd_frame_subtype == 7) then
            return serviceFail(context)
        end
        if cmd_frame_subtype == 1 then
            tid = gSfAppIDIEEC37118CMDDTOFF
        elseif cmd_frame_subtype == 2 then
            tid = gSfAppIDIEEC37118CMDDTON
        elseif cmd_frame_subtype == 3 then
            tid = gSfAppIDIEEC37118CMDSNDHDR
        elseif cmd_frame_subtype == 4 then
            tid = gSfAppIDIEEC37118CMDSNDCFG1
        elseif cmd_frame_subtype == 5 then
            tid = gSfAppIDIEEC37118CMDSNDCFG2
        elseif cmd_frame_subtype == 6 then
            tid = gSfAppIDIEEC37118CMDSNDCFG3
        elseif cmd_frame_subtype == 8 then
            tid = gSfAppIDIEEC37118CMDEXTD
        end
        DC.printf("IEEEC37.118 packet found new tid %d \n", tid)
    end

    if tid then
        report_payload_id = tid
        DC.printf('%s: IEEE C37.118 Adding payload %d\n',gServiceName, report_payload_id)
        gDetector:service_analyzePayload(report_payload_id)
        -- if we are on port 4712 or 4713 and we saw the start pattern, we know its ieee c37.118
        -- so set the continue flag (to keep looking for messages) and declare success.
        context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
        return serviceSuccess(context)
    end
    return serviceFail(context)
end


--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
