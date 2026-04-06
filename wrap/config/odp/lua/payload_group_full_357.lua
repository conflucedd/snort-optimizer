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
detection_name: Payload Group Full "357"
version: 4
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'NordVPN' => 'NordVPN is a VPN service provided by company Nordsec Ltd.',
          'SurfShark' => 'VPN/anonymizer app.',
          'Proton VPN' => 'VPN/anonymizer app.',
          'Avira Phantom VPN' => 'VPN/anonymizer app.',
          'FastVPN' => 'VPN/anonymizer app.',
          'StrongVPN' => 'VPN/anonymizer app.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_full_357",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Proton VPN
      { 0, 0, 0, 2555, 1, "proton.me", "/", "http:", "", 4903},
      { 0, 0, 0, 2555, 1, "pm.me", "/", "http:", "", 4903},
    -- SurfShark
      { 0, 0, 0, 2556, 1, "surfsharkstatus.com", "/", "http:", "", 4904},
      { 0, 0, 0, 2556, 1, "surfshark.ssl.zendesk.com", "/", "http:", "", 4904},
    -- StrongVPN
      { 0, 0, 0, 2558, 1, "strongvpn.zendesk.com", "/", "http:", "", 4906},
    -- NordVPN
      { 0, 0, 0, 2559, 1, "73dkt-vwrqs.xyz", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "icpsuawn1zy5amys.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "judua3rtinpst0s.xyz", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "mzhlhrfr8z.info", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "ndaccount.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "njtzzrvg0lwj3bsn.info", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "nordaccount.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "nord-apps.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "nordcdn.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "nordpass.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "nordvpn.net", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "nordvpnteams.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "ns8469rfvth42.xyz", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "otmwumj6qw5em0zb.me", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "p99nxpivfscyverz.me", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "x9fnzrtl4x8pynsf.com", "/", "http:", "", 4907},
      { 0, 0, 0, 2559, 1, "zwyr157wwiu6eior.com", "/", "http:", "", 4907},
    -- FastVPN
      { 0, 0, 0, 2560, 1, "vpn.ncapi.io", "/", "http:", "", 4908},
    -- Avira Phantom VPN
      { 0, 0, 0, 2564, 1, "avira-vpn.com", "/", "http:", "", 4912},
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

