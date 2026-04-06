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
detection_name: Payload Group "357"
version: 4
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'StrongVPN' => 'VPN/anonymizer app.',
          'IPVanish VPN' => 'VPN/anonymizer app.',
          'Mozilla VPN' => 'VPN/anonymizer app.',
          'SurfShark' => 'VPN/anonymizer app.',
          'Cato Networks' => 'Company that provides remote access and VPN.',
          'NordVPN' => 'NordVPN is a VPN service provided by company Nordsec Ltd.',
          'iTop VPN' => 'VPN/anonymizer app.',
          'Urban VPN' => 'VPN/anonymizer app.',
          'Proton VPN' => 'VPN/anonymizer app.',
          'Avira Phantom VPN' => 'VPN/anonymizer app.',
          'FastVPN' => 'VPN/anonymizer app.',
          'Seed4me' => 'VPN/anonymizer app.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_357",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Proton VPN
    { 0, 0, 0, 2555, 1, "protonvpn.com", "/", "http:", "", 4903},
    -- SurfShark
    { 0, 0, 0, 2556, 1, "surfshark.com", "/", "http:", "", 4904},
    -- Urban VPN
    { 0, 0, 0, 2557, 1, "urban-vpn.com", "/", "http:", "", 4905},
    -- StrongVPN
    { 0, 0, 0, 2558, 1, "strongvpn.com", "/", "http:", "", 4906},
    -- NordVPN
    { 0, 0, 0, 2559, 1, "nordvpn.com", "/", "http:", "", 4907},
    -- FastVPN
    { 0, 0, 0, 2560, 1, "fastvpn.com", "/", "http:", "", 4908},
    -- Cato Networks
    { 0, 0, 0, 2561, 1, "catonetworks.com", "/", "http:", "", 4909},
    -- Seed4me
    { 0, 0, 0, 2562, 1, "seed4.me", "/", "http:", "", 4910},
    -- Avira Phantom VPN
    { 0, 0, 0, 2564, 1, "avira-update.com", "/", "http:", "", 4912},
    -- IPVanish VPN
    { 0, 0, 0, 2565, 1, "ipvanish.com", "/", "http:", "", 4913},
    --  Mozilla VPN
    { 0, 0, 0, 2566, 1, "vpn.mozilla.org", "/", "http:", "", 4914},
    -- iTop VPN
    { 0, 0, 0, 2568, 1, "itopvpn.com", "/", "http:", "", 4916},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
