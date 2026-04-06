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
detection_name: Zoom
version: 3
description: Remote conferencing via cloud computing.
bundle_description: $VAR1 = {
          'Zoom' => 'Remote conferencing via cloud computing.',
          'Zoom Download' => 'Downloading a file from Zoom.',
          'Zoom Meeting' => 'Participating in a meeting on Zoom.',
          'Zoom Upload' => 'Uploading a file on Zoom.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Zoom",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

gSfAppIdZoom= 4513

gPatterns = {
    tcpPattern1 = {'\001\000\108\000\002', 0 , gSfAppIdZoom},
    tcpPattern2 = {'\001\000\106\000\002', 0 , gSfAppIdZoom},
    tcpPattern3 = {'\001\000\131\000\002', 0 , gSfAppIdZoom},
}

gZoomPatterns = {
    {DC.ipproto.tcp, gPatterns.tcpPattern1},
    {DC.ipproto.tcp, gPatterns.tcpPattern2},
    {DC.ipproto.tcp, gPatterns.tcpPattern3},
}

gAppRegistry = {
    {gSfAppIdZoom, 0}
}

gUrlPatternList = {                                                                                 
                                                                                                    
    -- Zoom Upload
    { 0, 0, 0, 1942, 21, "file.zoom.us", "/zoomfile/upload", "http:", "", 4627 },    

    -- Zoom Download
    { 0, 0, 0, 1943, 21, "file.zoom.us", "/zoomfile/download", "http:", "", 4628 },

    -- Zoom Meeting
    { 0, 0, 0, 1944, 21, "zoom.us", "/sendUserBehavior", "http:", "", 4629 },    
    { 0, 0, 0, 1944, 21, "zoom.us", "/conf", "http:", "", 4629 },                                                                                            
}                                                                                                   
                                                                                                    
gSSLHostPatternList = {                                                                             
    { 1, 4513, 'zoom.us' },                                               
    { 1, 4513, 'zoomus.zendesk.com' },
}  

function clientInProcess(context)
    DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, '', gSfAppIdZoom)
    return DC.clientStatus.success
end

function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.einvalid
end

function client_clean()
end

function client_init(detectorInstance)
    gDetector = detectorInstance

    DC.printf('Zoom Application\n')
    gDetector:addSSLCertPattern( 1, 4513, 'zoom.us' )
    gDetector:addSSLCertPattern( 1, 4513, 'zoomus.zendesk.com' )

    DC.printf('%s:client_init()\n', DetectorPackageInfo.name)
    gDetector:client_init()
    appTypeId = 11
    appProductId = 530
    appServiceId = 20202
    DC.printf('%s:client_validate(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    -- register SSL and URL patterns
    if gDetector.addAppUrl then                                                                      
        for i,v in ipairs(gUrlPatternList) do                                                       
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);                
        end                                                                                         
    end                                                                                             
    if gDetector.addSSLCertPattern then                                                             
        for i,v in ipairs(gSSLHostPatternList) do                                                   
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);                                            
        end                                                                                         
    end  

    --register pattern based detection
    for i,v in ipairs(gZoomPatterns) do
        if (gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,v[2][1])
        end
    end

    for i,v in ipairs(gAppRegistry) do
        pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end

    return gDetector
end

function client_validate()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.protocol = gDetector:getProtocolType()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf('Zoom packetCount %d dir %d, size %d\n', context.packetCount, dir, size)
    -- Port should match along with matching criteria
    if dstPort == 8801 then
        DC.printf("Zoom matched it\n")

        -- Just Validation for data size
        if (size == 0) then
            return clientInProcess(context)
        end

        return clientSuccess(context)
    end

    return clientInProcess(context)

end


function DetectorFini()
end
