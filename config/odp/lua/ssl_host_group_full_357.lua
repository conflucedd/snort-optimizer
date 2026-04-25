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
detection_name: SSL Group Full "357"
version: 3
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Avira Phantom VPN' => 'VPN/anonymizer app.',
          'SurfShark' => 'VPN/anonymizer app.',
          'NordVPN' => 'NordVPN is a VPN service provided by company Nordsec Ltd.',
          'StrongVPN' => 'VPN/anonymizer app.',
          'FastVPN' => 'VPN/anonymizer app.',
          'Proton VPN' => 'VPN/anonymizer app.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_full_357",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Proton VPN
      {0, 4903, 'proton.me', },
      {0, 4903, 'pm.me', },
    -- SurfShark
      {0, 4904, 'surfsharkstatus.com', },
      {0, 4904, 'surfshark.ssl.zendesk.com', },
    -- StrongVPN
      {0, 4906, 'strongvpn.zendesk.com', },
    -- NordVPN
      {0, 4907, '73dkt-vwrqs.xyz', },
      {0, 4907, 'icpsuawn1zy5amys.com', },
      {0, 4907, 'judua3rtinpst0s.xyz', },
      {0, 4907, 'mzhlhrfr8z.info', },
      {0, 4907, 'ndaccount.com', },
      {0, 4907, 'njtzzrvg0lwj3bsn.info', },
      {0, 4907, 'nordaccount.com', },
      {0, 4907, 'nord-apps.com', },
      {0, 4907, 'nordcdn.com', },
      {0, 4907, 'nordpass.com', },
      {0, 4907, 'nordvpn.net', },
      {0, 4907, 'nordvpnteams.com', },
      {0, 4907, 'ns8469rfvth42.xyz', },
      {0, 4907, 'otmwumj6qw5em0zb.me', },
      {0, 4907, 'p99nxpivfscyverz.me', },
      {0, 4907, 'x9fnzrtl4x8pynsf.com', },
      {0, 4907, 'zwyr157wwiu6eior.com', },
    -- FastVPN
      {0, 4908, 'vpn.ncapi.io', },
    -- Avira Phantom VPN
      {0, 4912, 'avira-vpn.com', },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
