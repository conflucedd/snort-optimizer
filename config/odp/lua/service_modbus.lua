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
detection_name: Modbus
version: 5
description: Serial communications protocol, used to network computer-controlled industrial machinery.
bundle_description: $VAR1 = {
          'Modbus Read Coils' => 'The Read Coils command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Write Multiple Coils' => 'The Write Multiple Coils command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Read Discrete Inputs' => 'The Read Discrete Inputs command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Write Single Coil' => 'The Write Single Coil command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Write Single Register' => 'The Write Single Register command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Read Holding Registers' => 'The Read Holding Registers command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Write Multiple Registers' => 'The Write Multiple Registers command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Mask Write Register' => 'The Mask Write Register command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus' => 'Serial communications protocol, used to network computer-controlled industrial machinery.',
          'Modbus Read FIFO Queue' => 'The Read FIFO Queue command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Encapsulated Interface Transport' => 'The Modbus Encapsulated Interface Transport command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Write File Record' => 'The Write File Record command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Read Input Registers' => 'The Read Input Registers command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Read/Write Multiple Registers' => 'The Read/Write Multiple Registers command is a function code in the Modbus Serial Communication Protocol.',
          'Modbus Read File Record' => 'The Read File Record command is a function code in the Modbus Serial Communication Protocol.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

gSfAppIdModbus = 737
gServiceId = 20067
gServiceName = 'Modbus'

DetectorPackageInfo = {
    name =  "Modbus",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

modbus_read_coils = 5079                        -- function code 0x01
modbus_read_discrete_inputs = 5080              -- function code 0x02
modbus_read_holding_registers = 5081            -- function code 0x03
modbus_read_input_registers = 5082              -- function code 0x04
modbus_write_single_coil = 5083                 -- function code 0x05
modbus_write_single_register = 5084             -- function code 0x06
modbus_write_multiple_coils = 5085              -- function code 0x0F
modbus_write_multiple_registers = 5086          -- function code 0x10
modbus_read_file_record = 5087                  -- function code 0x14
modbus_write_file_record = 5088                 -- function code 0x15
modbus_mask_write_register = 5089               -- function code 0x16
modbus_read_write_multiple_registers = 5090     -- function code 0x17
modbus_read_fifo_queue = 5091                   -- function code 0x18
modbus_encapsulated_interface_transport = 5092  -- function code 0x2B

gPorts = {
    {DC.ipproto.tcp, 502},
}

gPatterns = {
    modbus = { '\000\000', 2, gSfAppIdModbus}
}

gAppRegistry = {
    --AppIdValue          Extracts Info
    ---------------------------------------
    {gSfAppIdModbus,                    0},
    {modbus_read_coils,                 0},
    {modbus_read_discrete_inputs,       0},
    {modbus_read_holding_registers,     0},
    {modbus_read_input_registers,       0},
    {modbus_write_single_coil,          0},
    {modbus_write_single_register,      0},
    {modbus_write_multiple_coils,       0},
    {modbus_write_multiple_registers,   0},
    {modbus_read_file_record,           0},
    {modbus_write_file_record,          0},
    {modbus_mask_write_register,        0},
    {modbus_read_write_multiple_registers, 0},
    {modbus_read_fifo_queue,            0},
    {modbus_encapsulated_interface_transport, 0}
}

function serviceInProcess(context)

    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:inProcessService()
    end

    DC.printf('%s: Inprocess, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount);
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if context.payload_id then
        gDetector:service_analyzePayload(context.payload_id)
    end

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:addService(context.service_id, "", "", context.appId)
    end

    DC.printf('%s: Detected, packetCount: %d\n', context.appId, context.packetCount);
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:failService()
    end

    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount);
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

    DC.printf('%s: DetectorInit()\n',DetectorPackageInfo.name)

    gDetector = detectorInstance
    gDetector:init(DetectorPackageInfo.name, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
end


--[[Validator function registered in DetectorInit()

    (1+dir) and (2-dir) logic takes care of symmetric request response case. Once connection is established,
    client (server) can send request and server (client) should send a response.
--]]
function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir

    if (size == 0 or dir == 1) then
        return serviceInProcess(context)
    end

    -- if service hasn't been detected, verify service port is 502
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if ((not flowFlag) or (flowFlag == 0)) then
        local service_port = gDetector:getPktDstPort()
        if (service_port ~= 502) then
            return serviceFail(context)
        end
    end


    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d size %d\n', gServiceName, context.packetCount, dir, size)

    if (size > 7) then
        -- Check bytes 3 & 4 are 00 00
        if DC.checkPattern(gDetector, gPatterns.modbus) then
            -- Check Length stated in Modbus message is the same as actual length of packet
            DC.printf ('%s: checking server packet pattern\n',gServiceName)
            matched, body_size_raw = gDetector:getPcreGroups("....(..)", 0)
            if (matched) then
                body_size = DC.binaryStringToNumber(body_size_raw, 2)
                DC.printf (' body_size %d, size %d\n', body_size, size)
                if (size - 6 == body_size) then
                    -- We know its Modbus; lets look for the function code
                    context.service_id = gServiceId
                    context.appId = gSfAppIdModbus

                    fc_byte_raw = gDetector:getPcreGroups("(.)", 7)
                    fc_byte = DC.binaryStringToNumber(fc_byte_raw, 1)

                    if fc_byte == 1 then
                        context.payload_id = modbus_read_coils
                    elseif fc_byte == 2 then
                        context.payload_id = modbus_read_discrete_inputs
                    elseif fc_byte == 3 then
                        context.payload_id = modbus_read_holding_registers
                    elseif fc_byte == 4 then
                        context.payload_id = modbus_read_input_registers
                    elseif fc_byte == 5 then
                        context.payload_id = modbus_write_single_coil
                    elseif fc_byte == 6 then
                        context.payload_id = modbus_write_single_register
                    elseif fc_byte == 15 then
                        context.payload_id = modbus_write_multiple_coils
                    elseif fc_byte == 16 then
                        context.payload_id = modbus_write_multiple_registers
                    elseif fc_byte == 20 then
                        context.payload_id = modbus_read_file_record
                    elseif fc_byte == 21 then
                        context.payload_id = modbus_write_file_record
                    elseif fc_byte == 22 then
                        context.payload_id = modbus_mask_write_register
                    elseif fc_byte == 23 then
                        context.payload_id = modbus_read_write_multiple_registers
                    elseif fc_byte == 24 then
                        context.payload_id = modbus_read_fifo_queue
                    elseif fc_byte == 43 then
                        context.payload_id = modbus_encapsulated_interface_transport
                    end

                    -- Since we know its Modbus functions codes are likely to change
                    -- Set the continue flag to keep looking for function codes and declare success
                    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    return serviceSuccess(context)
                end
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
