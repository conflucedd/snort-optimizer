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
detection_name: TeamViewer
version: 1
description: Remote desktop control and file transfer software.
bundle_description: $VAR1 = {
          'TeamViewer' => 'Remote desktop control and file transfer software.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "TeamViewer",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

teamviewer_port = 5938

gServiceId = 20214
gServiceName = 'TeamViewer'
gSfAppIdTeamViewer = 958

gPatterns = {
    cmd_v1 = {'\023\036', 0, gSfAppIdTeamViewer},
    cmd_v2 = {'\017\048', 0, gSfAppIdTeamViewer},
}

gPorts = {
    {DC.ipproto.tcp, teamviewer_port},
}

gAppRegistry = {
    {gSfAppIdTeamViewer, 0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdTeamViewer)
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

local function v1_header_lengths_match(index, size)
    DC.printf('%s:DetectorValidator(): v1 header index %d size %d\n', gServiceName, index, size)
    if index >= 0 and index + 5 <= size and 
        gDetector:memcmp(gPatterns.cmd_v1[1], #gPatterns.cmd_v1[1], index) == 0 then
        matched, len_raw = gDetector:getPcreGroups("...(..)", index)
        len = DC.reverseBinaryStringToNumber(len_raw, 2)
        endex = index + 5 + len
        DC.printf('%s:DetectorValidator(): len is %d, endex is %d\n', gServiceName, len, endex)
        if endex == size then
            return 1
        else
            return v1_header_lengths_match(endex, size)
        end
    end
    return nil
end

-- One of the reasons to use two separate functions for v1 and v2 headers is that the v2 header
-- seems to have a "header offset" field. But we are not sure if this is actually used, because 
-- all of our v2 examples have actual header length 24 and offset 24. So for now we will assume
-- a fixed header length of 24, but we may need to address this later.
local function v2_header_lengths_match(index, size)
    DC.printf('%s:DetectorValidator(): v2 header index %d size %d\n', gServiceName, index, size)
    if index >= 0 and index + 24 <= size and 
        gDetector:memcmp(gPatterns.cmd_v2[1], #gPatterns.cmd_v2[1], index) == 0 then
        matched, len_raw = gDetector:getPcreGroups("....(....)", index)                                  
        len = DC.reverseBinaryStringToNumber(len_raw, 4)                                         
        endex = index + 24 + len                                                                     
        DC.printf('%s:DetectorValidator(): len is %d, endex is %d\n', gServiceName, len, endex)     
        if endex == size then                                                                       
            return 1                                                                                
        else                                                                                        
            return v2_header_lengths_match(endex, size)                                             
        end
    end
    return nil
end    

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()\n',gServiceName)

    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    if gDetector.addSSLCertPattern then                                                             
        gDetector:addSSLCertPattern(0, 958, 'teamviewer.com')                                            
    end    

    if gDetector.addSSLCnamePattern then                                                            
        gDetector:addSSLCnamePattern(0, 958, 'teamviewer.com')                                           
    end 

    if gDetector.addAppUrl then                                                                     
        gDetector:addAppUrl(0, 0, 0, 1637, 9, "teamviewer.com", "/", "http:", "", 958);                
    end     

    if gDetector.portOnlyService then                                                               
        gDetector:portOnlyService(958, 5938, 17)                                            
    end     

    return gDetector
end

function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    local size = gDetector:getPacketSize() 
    local dir = gDetector:getPacketDir()
    local srcPort = gDetector:getPktSrcPort()
    local dstPort = gDetector:getPktDstPort()

    DC.printf('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
        context.packetCount, dir, size)

    -- confirm port is 5938
    if dir == 0 and dstPort ~= teamviewer_port or dir == 1 and srcPort ~= teamviewer_port then
        return serviceFail(context)
    end

    -- We have examples of multiple headers in one packet for both v1 and v2 packets; but there is
    -- no reason to assume that v1 and v2 headers can be mixed in the same packet. So for now we
    -- will assume that we should parse the entire packet based on the first header type.
    DC.printf('%s:DetectorValidator(): checking hdr type\n', gServiceName)                                                                                
    if size >= 2 then                                                        
        if DC.checkPattern(gDetector, gPatterns.cmd_v1) then                                        
            if v1_header_lengths_match(0, size) then
                return serviceSuccess(context)                                                                             
            end
        elseif DC.checkPattern(gDetector, gPatterns.cmd_v2) then                                    
            if v2_header_lengths_match(0, size) then                      
                return serviceSuccess(context)
            end
        end                                                                                         
    else
        return serviceInProcess(context)
    end           

    return serviceFail(context)
end

function DetectorFini()
end
