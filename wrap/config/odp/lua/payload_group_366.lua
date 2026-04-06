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
detection_name: Payload Group "366"
version: 2
description: Group of Payload Detectors.
bundle_description: $VAR1 = {
          'Potato VPN' => 'PotatoVPN is a cross-platform VPN application created by FASTPOTATO PTE LTD.',
          'iCloud Mail' => 'iCloud Mail is an online email service included in Apple iCloud product.',
          'Microsoft Teams Call' => 'Call traffic of Microsoft Teams.',
          'Slack Voice' => 'Voice traffic of the productivity focused instant messenger Slack.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_366",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- iCloud Mail
    {0, 0, 0, 4630, 1, "p01-mccgateway.icloud.com", "/", "http:", "", 7363},
    -- Potato VPN
    {0, 0, 0, 4631, 1, "potatovpn.io", "/", "http:", "", 7364},
    -- Slack Voice
    {0, 0, 0, 4632, 1, "slack.com", "/", "http:", "", 7365},
    -- Microsoft Teams Call
    {0, 0, 0, 4633, 1, "teams.microsoft.com", "/start", "http:", "", 7366},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end
    gUrlPatternList = nil

    return gDetector;
end

function DetectorClean()
end
