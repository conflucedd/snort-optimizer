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
detection_name: Payload Group "The Rolling Stones"
version: 5
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Azure cloud portal' => 'Microsoft Azure cloud service portal.',
          'Microsoft Stream' => 'Enterprise video streaming and sharing software.',
          'Microsoft' => 'Official Microsoft website.',
          'Exchange Online' => 'Traffic associated with Exchange Online, such as visiting outlook.com.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_the_rolling_stones",
    proto = DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
    -- Azure cloud portal
    { 0, 0, 0, 1911, 22, "azure.microsoft.com", "/azure-portal", "http:", "", 4533 },
    { 0, 0, 0, 1911, 22, "portal.azure.com", "/", "http:", "", 4533 },
    { 0, 0, 0, 1911, 22, "security.azure.com", "/", "http:", "", 4533 },
    { 0, 0, 0, 1911, 22, "database.windows.net", "/", "http:", "", 4533 },
    { 0, 0, 0, 1911, 22, "azurewebsites.net", "/", "http:", "", 4533 },
    { 0, 0, 0, 1911, 22, "azurewebsistes.windows.net", "/", "http:", "", 4533 },
    { 0, 0, 0, 1911, 22, "queue.core.windows.net", "/", "http:", "", 4533 },

    -- microsoft Stream
    { 0, 0, 0, 1912, 13, "amsglob0cdnstream11.azureedge.net", "/", "http:", "", 4553 },
    { 0, 0, 0, 1912, 13, "amsglob0cdnstream12.azureedge.net", "/", "http:", "", 4553 },
    { 0, 0, 0, 1912, 13, "streaming.mediaservices.windows.net", "/", "http:", "", 4553},
    -- Exchange Online
    { 0, 0, 0, 1847, 4, "domains.live.com", "/", "http:", "", 2810 },
    -- Microsoft 
    { 0, 0, 0, 579, 4, "go.microsoft.com", "/", "http:", "", 1423 },

}

function DetectorInit(detectorInstance)
    gDetector = detectorInstance

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector
end

function DetectorClean()
end
