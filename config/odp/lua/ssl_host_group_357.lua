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
detection_name: SSL Group "357"
version: 5
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Seed4me' => 'VPN/anonymizer app.',
          'Proton VPN' => 'VPN/anonymizer app.',
          'FastVPN' => 'VPN/anonymizer app.',
          'iTop VPN' => 'VPN/anonymizer app.',
          'Urban VPN' => 'VPN/anonymizer app.',
          'NordVPN' => 'NordVPN is a VPN service provided by company Nordsec Ltd.',
          'IPVanish VPN' => 'VPN/anonymizer app.',
          'Cato Networks' => 'Company that provides remote access and VPN.',
          'Mozilla VPN' => 'VPN/anonymizer app.',
          'SurfShark' => 'VPN/anonymizer app.',
          'StrongVPN' => 'VPN/anonymizer app.',
          'Avira Phantom VPN' => 'VPN/anonymizer app.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_357",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Proton VPN
    {0, 4903, 'protonvpn.com', },
    -- SurfShark
    {0, 4904, 'surfshark.com', },
    -- Urban VPN
    {0, 4905, 'urban-vpn.com', },
    -- StrongVPN
    {0, 4906, 'strongvpn.com', },
    -- NordVPN
    {0, 4907, 'nordvpn.com', },
    -- FastVPN
    {0, 4908, 'fastvpn.com', },
    -- Cato Networks
    {0, 4909, 'catonetworks.com', },
    -- Seed4me
    {0, 4910, 'seed4.me', },
    -- Avira Phantom VPN
    {0, 4912, 'avira-update.com', },
    -- IPVanish VPN
    {0, 4913, 'ipvanish.com', },
    -- Mozilla VPN
    {0, 4914, 'vpn.mozilla.org', },
    -- iTop VPN
    {0, 4916, 'itopvpn.com', },
}

gSSLCnamePatternList = {
    -- Proton VPN
    {0, 4903, 'protonvpn.com', },
    -- SurfShark
    {0, 4904, 'surfshark.com', },
    -- Urban VPN
    {0, 4905, 'urban-vpn.com', },
    -- StrongVPN
    {0, 4906, 'strongvpn.com', },
    -- NordVPN
    {0, 4907, 'nordvpn.com', },
    -- FastVPN
    {0, 4908, 'fastvpn.com', },
    -- Cato Networks
    {0, 4909, 'catonetworks.com', },
    -- Seed4me
    {0, 4910, 'seed4.me', },
    -- Avira Phantom VPN
    {0, 4912, 'avira-vpn.com', },
    -- IPVanish VPN
    {0, 4913, 'ipvanish.com', },
    -- Mozilla VPN
    {0, 4914, 'vpn.mozilla.org', },
    -- iTop VPN
    {0, 4916, 'itopvpn.com', },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
