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
detection_name: Wireguard
version: 2
description: WireGuard is a free and open-source software application and communication protocol that implements virtual private network techniques to create secure point-to-point connections in routed or bridged configurations.
bundle_description: $VAR1 = {
          'Wireguard' => 'WireGuard is a free and open-source software application and communication protocol that implements virtual private network techniques to create secure point-to-point connections in routed or bridged configurations.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule


DetectorPackageInfo = {
    name =  "Wireguard",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdWireguard = 4663
gServiceIdWireguard = 20216
gServiceName = 'Wireguard'

gPatterns = {
    wg_handshake_resp = { '\002\216\093\174', 0, gSfAppIdWireguard},
    wg_reserved = { '\216\093\174', 1, gSfAppIdWireguard},
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.wg_handshake_resp},
}

gAppRegistry = {
    {gSfAppIdWireguard, 0},
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
        gDetector:addService(gServiceIdWireguard, "", "", gSfAppIdWireguard)
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
    for i,v in ipairs(gFastPatterns) do
        if gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0 then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name, v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,
                v[2][1])
        end
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

local function wireguard_sender_reciever_id_match(rft,size,dir)
    -- bytes 4-7 are the ID of the packet source. If we don't have a value for that side,
    -- save it, if we do have a value for that side, match it
        matched, msg_type_raw, id = gDetector:getPcreGroups("(.)...(....)", 0)
        msg_type = DC.binaryStringToNumber(msg_type_raw, 1)

        -- msg_type 1 should be the first packet, from the peer. If don't have an init id yet,
        -- save it. (Or else fail the session).
        if msg_type == 1 and rft.init == 0 then
            DC.printf ('%s: msg_type %d, handshake init\n', gServiceName, msg_type)
            rft.init = id
            return 1

        -- msg_type 2 should be second packet, from server. If we don't have a resp id yet, save it.
        -- Also, if we have an init id, extract the next four bytes, and those should match - service success!
        -- We should fail service if we have init id and it doesn't match, or if we receive this packet and
        -- we already have resp id.
        elseif msg_type == 2 and rft.resp == 0 and size >= 12 then
            DC.printf ('%s: msg_type %d, handshake resp\n', gServiceName, msg_type)

            matched, id2 = gDetector:getPcreGroups("(....)", 8)
            
            if rft.init == 0 then
                DC.printf ('%s: have not seen init id yet\n', gServiceName)
                rft.resp = id
                rft.init = id2
                return 2
            elseif rft.init == id2 then
                DC.printf ('%s: init id matches previous\n', gServiceName)
                return 3
            end

        -- msg type 4 carry the id of the OTHER side, and we should have both sides' ids; if they match,
        -- declare service success, or in any other case, fail out
        elseif msg_type == 4 and rft.init ~= 0 and rft.resp ~= 0 then
            if (dir == DC.flowDirection.fromInitiator and id == rft.resp) or
               (dir == DC.flowDirection.fromResponder and id == rft.init)  then
                DC.printf ('%s: transport data packet receiver id matches', gServiceName)
                return 3
            end
        end
    return 0
end

function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    local size = gDetector:getPacketSize()
    local dir = gDetector:getPacketDir()
    local flowKey = context.detectorFlow:getFlowKey()
    local rft = FT.getFlowTracker(flowKey)

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size)

    if size >= 8 and DC.checkPattern(gDetector, gPatterns.wg_reserved) then

        if not rft then
            rft = FT.addFlowTracker(flowKey, {init = 0, resp = 0})
        end
        rt_val =  wireguard_sender_reciever_id_match(rft,size, dir)

        if rt_val == 1 then
            DC.printf ('%s: msg_type %d, handshake init\n', gServiceName, msg_type)
            return serviceInProcess(context)
        elseif rt_val == 2 then
            return serviceInProcess(context)
        elseif rt_val == 3 then
            return serviceSuccess(context)
        end
    end
    DC.printf ('%s: Failed %d', gServiceName, id)
    return serviceFail(context)
end

function DetectorFini()
end
