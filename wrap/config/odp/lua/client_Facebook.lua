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
detection_name: Facebook
version: 8
description: Facebook is a social networking service.
bundle_description: $VAR1 = {
          'Instagram' => 'Mobile phone photo sharing.',
          'Facebook' => 'Facebook is a social networking service.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Facebook",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gSfAppIdFacebook = 629
gSfAppIdInstagram = 1233

-- Instagram is now a part of Facebook. Both use same patterns.
gPatterns = {
    facebook_cli = {'\049\081\084\086', 0, gSfAppIdFacebook},
}

gFastPatterns = {
	{DC.ipproto.tcp, gPatterns.facebook_cli},
}

gAppRegistry = {
	{gSfAppIdFacebook, 0},
        {gSfAppIdInstagram, 0}
}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

-- appFlag is zero for Instagram & set to a non-zero value for Facebook
function clientSuccess(context, appFlag)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    if (appFlag ~= 0) then
        DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
        gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdFacebook)
    else
        DC.printf('Instagram: Detected Client, packetCount: %d\n', context.packetCount)
        gDetector:client_addApp(appServiceId, appTypeId, appProductId_Insta, "", gSfAppIdInstagram)
    end
    return DC.clientStatus.success
end

function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.einvalid
end


--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    gDetector:addHttpPattern(2, 5, 0, 161, 1, 0, 0, 'Facebook', 629, 1);

    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
	gDetector:client_init()
	appTypeId = 19
	appProductId = 161
	appServiceId = 33

        appProductId_Insta = 124

	DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
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


--[[Validator function registered in DetectorInit()
--]]
function client_validate()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('Facebook client packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

	if (size == 0) then
    	return clientInProcess(context)
	end


    if (dir == 0 and dstPort == 443 and size > 100) then
        matched, len = gDetector:getPcreGroups(".*KEXS[^\\.]*.*(facebook\\.com|fbcdn\\.net)", 50)
        if (matched) then
            DC.printf ('Facebook:DetectorValidator(): matched %s\n', matched)
            return clientSuccess(context, 1)
        end
        matched, len = gDetector:getPcreGroups(".*KEXS[^\\.]*.*(instagram\\.com)", 50)
        if (matched) then
            DC.printf ('Instagram:DetectorValidator(): matched %s\n', matched)
            return clientSuccess(context, 0)
        end
    end


    return clientFail(context)
end

function client_clean()
end

