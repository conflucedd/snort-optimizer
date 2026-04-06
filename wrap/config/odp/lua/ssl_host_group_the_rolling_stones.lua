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
detection_name: SSL Group "The Rolling Stones"
version: 7
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Azure cloud portal' => 'Microsoft Azure cloud service portal.',
          'OneDrive' => 'Microsoft cloud storage offering, successor to SkyDrive.',
          'Microsoft' => 'Official Microsoft website.',
          'Microsoft Stream' => 'Enterprise video streaming and sharing software.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_the_rolling_stones",
    proto = DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
    -- Microsoft Stream
    { 0, 4553, 'api.microsoftstream.com' },
    { 0, 4553, 'az416426.vo.msecnd.net' },
    { 0, 4553, 'web.microsoftstream.com' },
    { 0, 4553, 'amsglob0cdnstream11.azureedge.net' },
    { 0, 4553, 'amsglob0cdnstream12.azureedge.net' },
    { 0, 4553, 'nps.onyx.azure.net' },
    { 0, 4553, 'media.azure.net' },
    { 0, 4553, 'stream.microsoft.com' },
    { 0, 4553, 'streamcdn.azureedge.net' },
    { 0, 4553, 'streaming.mediaservices.windows.net' },

    -- Azure cloud portal
    { 0, 4533, 'portal.azure.com'},
    { 0, 4533, 'portal.azure.net'},
    { 0, 4533, 'management.azure.com'},
    { 0, 4533, 'manage.windowsazure.com'},
    { 0, 4533, 'fpt.windowsazure.com'},
    { 0, 4533, 'ext.azure.com'},
    { 0, 4533, 'proxy.azure.com'},
    { 0, 4533, 'gallery.azure.com'},
    { 0, 4533, 'console.azure.com'},
    { 0, 4533, 'functions.azure.com'},
    { 0, 4533, 'recommendationsvc.azure.com'},
    { 0, 4533, 'graph.windows.net'},
    { 0, 4533, 'wpc.azureedge.net'},
    { 0, 4533, 'azurecomcdn.azureedge.net'},
    { 0, 4533, 'cus-ex-core-prod-cdn-endpoint.azureedge.net'},
    { 0, 4533, 'azureadvisorfonts.azureedge.net'},
    { 0, 4533, 'cloudapp.azure.com'},
    { 0, 4533, 'azureexpert.trafficmanager.net'},
    { 0, 4533, 'security.azure.com'},
    { 0, 4533, 'database.windows.net'},
    { 0, 4533, 'azurewebsites.net'},
    { 0, 4533, 'azurewebsistes.windows.net'},
    { 0, 4533, 'queue.core.windows.net'},

    -- OneDrive 
    { 0, 3735, 'onedrive.com'},
    
    -- Microsoft
    { 0, 1423, 'msedge.net'},
}

function DetectorInit(detectorInstance)
    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    return gDetector
end

function DetectorClean()
end
