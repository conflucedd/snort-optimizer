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
detection_name: CAMP
version: 7
description: Common ASCII Message Protocol (CAMP).
bundle_description: $VAR1 = {
          'CAMP Device Specific (with side effect) Command' => 'A CAMP Device Specific Command, containing at least one task having side effects.',
          'CAMP Memory Exchange Command' => 'A CAMP Memory Exchange Command.',
          'CAMP Memory Exchange Response' => 'A CAMP Memory Exchange Response.',
          'CAMP Device Specific (unknown) Command' => 'A CAMP Device Specific Command, containing at least one task that could not be identified.',
          'CAMP Write Data Command' => 'A CAMP Write Data Command.',
          'CAMP Device Specific (read only) Command' => 'A CAMP Device Specific Command, containing only tasks having no side effects.',
          'CAMP Protocol Error Message' => 'A CAMP Protocol Error Message.',
          'CAMP Read Data Command' => 'A CAMP Read Data Command.',
          'CAMP Device Specific (with side effect) Response' => 'A CAMP Device Specific Response, containing at least one task having side effects.',
          'CAMP Write Data Response' => 'A CAMP Write Data Response.',
          'CAMP Read Data Response' => 'A CAMP Read Data Response.',
          'CAMP' => 'Common ASCII Message Protocol (CAMP).',
          'CAMP Device Specific (unknown) Response' => 'A CAMP Device Specific Response, containing at least one task that could not be identified.',
          'CAMP Device Specific (read only) Response' => 'A CAMP Device Specific Response, containing only tasks having no side effects.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "CAMP",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceIdCAMP = 20215
gServiceName = 'CAMP'

gSfAppIdCamp = 5336
gSfAppIdCampReadDataCmd = 5337
gSfAppIdCampReadDataResp = 5338
gSfAppIdCampWriteDataCmd = 5339
gSfAppIdCampWriteDataResp = 5340
gSfAppIdCampMemExchCmd = 5341
gSfAppIdCampMemExchResp = 5342
gSfAppIdCampDevSpecReadOnlyCmd = 5343
gSfAppIdCampDevSpecReadOnlyResp = 5344
gSfAppIdCampDevSpecWithSideEffectCmd = 5345
gSfAppIdCampDevSpecWithSideEffectResp = 5346
gSfAppIdCampDevSpecUnknownCmd = 5347
gSfAppIdCampDevSpecUnknownResp = 5348
gSfAppIdCampProtoErrMsg = 5349


gPatterns = {
    --patternName    pattern        offset   appId
    -------------------------------------------------------------
    pattern0       = {'[04',    0,  gSfAppIdCampReadDataCmd},
    pattern1       = {'[05',    0,  gSfAppIdCampReadDataResp},
    pattern2       = {'[06',    0,  gSfAppIdCampWriteDataCmd},
    pattern3       = {'[07',    0,  gSfAppIdCampWriteDataResp},
    pattern4       = {'[08',    0,  gSfAppIdCampMemExchCmd},
    pattern5       = {'[09',    0,  gSfAppIdCampMemExchResp},
    pattern6       = {'[02',    0,  gSfAppIdCampDevSpecUnknownCmd},
    pattern7       = {'[03',    0,  gSfAppIdCampDevSpecUnknownResp},
    pattern8       = {'[FF',    0,  gSfAppIdCampProtoErrMsg},
}

gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.pattern0},
    {DC.ipproto.tcp, gPatterns.pattern1},
    {DC.ipproto.tcp, gPatterns.pattern2},
    {DC.ipproto.tcp, gPatterns.pattern3},
    {DC.ipproto.tcp, gPatterns.pattern4},
    {DC.ipproto.tcp, gPatterns.pattern5},
    {DC.ipproto.tcp, gPatterns.pattern6},
    {DC.ipproto.tcp, gPatterns.pattern7},
    {DC.ipproto.tcp, gPatterns.pattern8},
}

gPorts = {
    {DC.ipproto.tcp, 1505},
}

gAppRegistry = {
    {gSfAppIdCamp, 0},
    {gSfAppIdCampReadDataCmd, 0},
    {gSfAppIdCampReadDataResp, 0},
    {gSfAppIdCampWriteDataCmd, 0},
    {gSfAppIdCampWriteDataResp, 0},
    {gSfAppIdCampMemExchCmd, 0},
    {gSfAppIdCampMemExchResp, 0},
    {gSfAppIdCampDevSpecReadOnlyCmd, 0},
    {gSfAppIdCampDevSpecReadOnlyResp, 0},
    {gSfAppIdCampDevSpecWithSideEffectCmd, 0},
    {gSfAppIdCampDevSpecWithSideEffectResp, 0},
    {gSfAppIdCampDevSpecUnknownCmd, 0},
    {gSfAppIdCampDevSpecUnknownResp, 0},
    {gSfAppIdCampProtoErrMsg, 0},
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
        gDetector:addService(gServiceIdCAMP, "", "", gSfAppIdCamp)
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

    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf('%s: Failed to register the pattern', gServiceName )
        else
            DC.printf('%s: Successful in registering the pattern', gServiceName )
        end
    end
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()', gServiceName)
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()
    return gDetector
end


TASK_READ_ONLY = 1
TASK_WITH_SIDE_EFFECT = 2

TASK_CODE_TO_TYPE = {
    ["01"]=TASK_READ_ONLY,        -- Read Word Memory Random
    ["02"]=TASK_WITH_SIDE_EFFECT, -- Write Word Memory Area Random"
    ["30"]=TASK_READ_ONLY,        -- Read Operational Status
    ["32"]=TASK_WITH_SIDE_EFFECT, -- Program to Run Mode
    ["33"]=TASK_WITH_SIDE_EFFECT, -- Go to Program Mode
    ["34"]=TASK_WITH_SIDE_EFFECT, -- Execute Power-up
    ["35"]=TASK_WITH_SIDE_EFFECT, -- Execute Complete (Warm) Start
    ["36"]=TASK_READ_ONLY,        -- Execute Partial (Hot) Start
    ["50"]=TASK_WITH_SIDE_EFFECT, -- Read User Word Area Block
    ["51"]=TASK_WITH_SIDE_EFFECT, -- Write User Word Area Starting at Address
    ["58"]=TASK_WITH_SIDE_EFFECT, -- Set Controller Time of Day Clock
    ["59"]=TASK_WITH_SIDE_EFFECT, -- Write Discrete I/O Status or Force via Data Element Type
    ["5A"]=TASK_WITH_SIDE_EFFECT, -- Write Block
    ["6B"]=TASK_READ_ONLY,        -- Read Discrete I/O Status or Force via Data Element Type
    ["71"]=TASK_READ_ONLY,        -- Read Controller Time of Day Clock
    ["7D"]=TASK_READ_ONLY,        -- Read SF/Loop Processor Mode
    ["7E"]=TASK_READ_ONLY,        -- Read Random
    ["7F"]=TASK_READ_ONLY,        -- Read Block
    ["88"]=TASK_WITH_SIDE_EFFECT, -- Select Number of SF Module Task Codes Per Scan
    ["89"]=TASK_READ_ONLY,        -- Read Number of SF Module Task Codes Per Scan
    ["8D"]=TASK_WITH_SIDE_EFFECT, -- Subcommand
    ["93"]=TASK_WITH_SIDE_EFFECT, -- Assign/Deassign Port
    ["94"]=TASK_WITH_SIDE_EFFECT, -- Configure Port
    ["99"]=TASK_WITH_SIDE_EFFECT, -- Write VME Memory Area Block/Random
    ["9A"]=TASK_READ_ONLY,        -- Read VME Memory Area Block/Random
}


local function isCmdType(type)
    -- this assumes appid codes are always in the command, response order, and allows saving a hashtable search
    if (type - gSfAppIdCamp) % 2 == 1 then
        return true
    end
    return false
end


-- parse tasks to deduce exact appid, or return nil if parsing failed or found an unknown task type
local function getDevSpecSubType(type, index, size)
    local sub_type = nil

    local offset = index + 15
    local end_offset = size - 6  -- bcc + closing ']'

    while (offset + 4) < end_offset do
        local matched, nitp_char_count_raw = gDetector:getPcreGroups('([0-9A-F]{2})', offset)
        if matched == 0 then
            return nil
        end

        local nitp_char_count = tonumber(nitp_char_count_raw, 16)

        -- char_count max is 80 (72 for body, 2 for delimiters, 2 for char count, 4 for error checking code)
        -- char_count min is 8 (2 for delimiters, 2 for char count, 4 for error checking code)
        if nitp_char_count == nil or nitp_char_count < 8  or nitp_char_count > 80 then
            return nil
        end

        local matched, task_code = gDetector:getPcreGroups('([0-9A-F]{2})', offset + 2)
        if matched == 0 then
            return nil
        end

        local task_type = TASK_CODE_TO_TYPE[task_code]
        if task_type == nil then
            sub_type = gSfAppIdCampDevSpecUnknownCmd
            break
        elseif (task_type == TASK_READ_ONLY) and (sub_type == nil) then
            -- type is read only if this task and the previous ones also were read only
            sub_type = gSfAppIdCampDevSpecReadOnlyCmd
        elseif task_type == TASK_WITH_SIDE_EFFECT then
            sub_type = gSfAppIdCampDevSpecWithSideEffectCmd
        end

        -- NITP starting and ending delimiters counted but not added, so removing 2 bytes
        offset = offset + nitp_char_count - 2
    end

    if (sub_type ~= nil) and not isCmdType(type) then
        sub_type = sub_type + 1   -- type is a response
    end

    return sub_type
end


local function checkMessageType(size)
    msg_type = nil

    for patternName in pairs(gPatterns) do
        if gDetector:memcmp(gPatterns[patternName][1], #gPatterns[patternName][1], 0) == 0 then
            msg_type = gPatterns[patternName][3]
            break
        end
    end

    if (msg_type == gSfAppIdCampDevSpecUnknownCmd) or (msg_type == gSfAppIdCampDevSpecUnknownResp) then
        sub_type = getDevSpecSubType(msg_type, 0, size)
        if sub_type ~= nil then
            msg_type = sub_type
        end
    end

    return msg_type
end


function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    local size = gDetector:getPacketSize()

    if size <= 10 then
        return serviceInProcess(context)
    end

    if gDetector:memcmp(':', 1, 0) == 0 then
        -- NITP
        return serviceInProcess(context)
    end
    if (gDetector:memcmp('[00', 3, 0) == 0) or (gDetector:memcmp('[01', 3, 0) == 0) then
        -- standard deviation seen in some pcaps
        return serviceInProcess(context)
    end

    local payload_id = checkMessageType(size)

    if payload_id then
        gDetector:service_analyzePayload(payload_id)
        context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
        return serviceSuccess(context)
    end

    return serviceFail(context)
end


function DetectorFini()
end
